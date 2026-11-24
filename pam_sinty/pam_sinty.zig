//! pam_sinty (Zig): PIN authentication, replacing pam_unix. The auth phase prompts
//! for the PIN over the PAM conversation and execs `sintykey unseal` (the single
//! key-custody helper -> the TPM; the TPM dictionary-attack lockout throttles
//! guesses), stashing the returned CE key; the session phase installs that key into
//! the kernel so the user's fscrypt CE data decrypts. No stub: the whole path is
//! real (the TPM itself is swtpm in a VM or a discrete/Pluton TPM on hardware).
const std = @import("std");
const bo = @import("build_options");
const c = @cImport({
    @cInclude("security/pam_modules.h");
    @cInclude("security/pam_appl.h");
    @cInclude("linux/fscrypt.h");
    @cInclude("sys/ioctl.h");
    @cInclude("pwd.h");
    @cInclude("shadow.h");
});

// A locked account (usermod -L / passwd -l / the "Prevent login" toggle) prepends
// '!' to the shadow password. The Sinty PIN-user baseline is "*" (no Unix password,
// NOT locked), so a leading '!' means an admin locked the account -> refuse login.
// pam_sinty is the auth path (pam_unix is bypassed), so WE must honor the lock, or
// "Prevent login" is a no-op (critical for enterprise/IT account control).
fn accountLocked(user: [*c]const u8) bool {
    // Fail CLOSED: if the shadow entry can't be read (missing entry, or /etc/shadow
    // unreadable), we cannot prove the account is unlocked -> treat it as locked. A
    // lock check that fails open silently defeats "Prevent login". pam_sinty runs in
    // privileged contexts (greetd/login/polkit as root), so getspnam succeeds normally.
    const sp = c.getspnam(user) orelse return true;
    const p = sp.*.sp_pwdp;
    if (p == null) return true; // no password field at all -> deny
    return p[0] == '!'; // '!' = admin-locked; '*' baseline = not locked
}

// libc, declared directly: <fcntl.h> fortify wrappers break translate-c.
extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern fn close(fd: c_int) c_int;
extern fn unlink(path: [*:0]const u8) c_int;
extern fn read(fd: c_int, buf: [*]u8, n: usize) isize;
extern fn write(fd: c_int, buf: [*]const u8, n: usize) isize;
extern fn pipe(fds: *[2]c_int) c_int;
extern fn fork() c_int;
extern fn dup2(old: c_int, new: c_int) c_int;
extern fn execv(path: [*:0]const u8, argv: [*:null]const ?[*:0]const u8) c_int;
extern fn waitpid(pid: c_int, status: *c_int, options: c_int) c_int;
extern fn _exit(code: c_int) noreturn;
extern fn getpid() c_int;
extern fn getuid() c_uint;
extern fn geteuid() c_uint;
extern fn setresuid(r: c_uint, e: c_uint, s: c_uint) c_int;
extern fn setresgid(r: c_uint, e: c_uint, s: c_uint) c_int;
extern fn setgroups(n: usize, list: ?*const c_uint) c_int;
extern fn execve(path: [*:0]const u8, argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8) c_int;
extern fn socket(domain: c_int, kind: c_int, proto: c_int) c_int;
extern fn connect(fd: c_int, addr: *const anyopaque, len: u32) c_int;
extern fn setsockopt(fd: c_int, level: c_int, name: c_int, val: *const anyopaque, len: u32) c_int;
const O_RDONLY: c_int = 0;
const O_WRONLY: c_int = 1;
const O_CREAT: c_int = 0o100;
const O_APPEND: c_int = 0o2000;
// DEVICE-FIX(arm64): O_DIRECTORY differs per architecture; the x86 value is O_DIRECT on aarch64, so opens on tmpfs fail and provisioning dies
const O_DIRECTORY: c_int = @bitCast(std.posix.O{ .DIRECTORY = true });
const O_CLOEXEC: c_int = 0o2000000;
// DEVICE-FIX(arm64): O_NOFOLLOW differs per architecture; the x86 value is O_LARGEFILE on aarch64 and the symlink guard is lost
const O_NOFOLLOW: c_int = @bitCast(std.posix.O{ .NOFOLLOW = true });
const BADGE_USER = "sinty-badge";
const BADGE_TICKET = "/run/sinty-badge/ticket";

// Compile-time-gated fscrypt key diagnostics (dev builds only).
fn dbgHex(bytes: []const u8, out: []u8) []const u8 {
    const hc = "0123456789abcdef";
    var i: usize = 0;
    while (i < bytes.len and i * 2 + 1 < out.len) : (i += 1) {
        out[i * 2] = hc[bytes[i] >> 4];
        out[i * 2 + 1] = hc[bytes[i] & 0xf];
    }
    return out[0 .. bytes.len * 2];
}
fn dbgCrown(comptime fmt: []const u8, args: anytype) void {
    if (!bo.debug_e2e) return;
    const fd = open("/var/lib/sinty/.dbg-crown", O_WRONLY | O_CREAT | O_APPEND, 0o600);
    if (fd < 0) return;
    defer _ = close(fd);
    var lb: [256]u8 = undefined;
    const ln = std.fmt.bufPrint(&lb, fmt, args) catch return;
    _ = write(fd, ln.ptr, ln.len);
}

const DATA_KEY = "sinty_ce_key";
const SINTYKEY_BIN = "/usr/bin/sintykey"; // fixed path (no PATH lookup in a PAM context)
const KEYLEN = 32;
const RECOVERD_SOCK = "/run/sinty-recoverd.sock";
const Key = extern struct { bytes: [KEYLEN]u8 };

fn askPin(pamh: ?*c.pam_handle_t) ?[*:0]u8 {
    return askSecret(pamh, "PIN: ");
}

fn askSecret(pamh: ?*c.pam_handle_t, prompt: [*:0]const u8) ?[*:0]u8 {
    var item: ?*const anyopaque = null;
    if (c.pam_get_item(pamh, c.PAM_CONV, &item) != c.PAM_SUCCESS or item == null) return null;
    const conv: *const c.pam_conv = @ptrCast(@alignCast(item));
    const cb = conv.conv orelse return null;

    var msg = c.pam_message{ .msg_style = c.PAM_PROMPT_ECHO_OFF, .msg = prompt };
    var msgs = [_][*c]const c.pam_message{&msg};
    var resp: [*c]c.pam_response = null;
    if (cb(1, &msgs, &resp, conv.appdata_ptr) != c.PAM_SUCCESS or resp == null) return null;
    const pin = resp[0].resp;
    std.c.free(resp);
    return @ptrCast(pin);
}

fn hasSecurityKeys(uid: []const u8) bool {
    var pb: [512]u8 = undefined;
    const path = std.fmt.bufPrintZ(&pb, "{s}/{s}.security-keys", .{ bo.status_dir, uid }) catch return false;
    const fd = open(path.ptr, O_CLOEXEC, 0);
    if (fd < 0) return false;
    _ = close(fd);
    return true;
}

fn touchHint(pamh: ?*c.pam_handle_t) void {
    tell(pamh, c.PAM_TEXT_INFO, "Touch your security key.");
}

fn tell(pamh: ?*c.pam_handle_t, style: c_int, text: [*:0]const u8) void {
    var item: ?*const anyopaque = null;
    if (c.pam_get_item(pamh, c.PAM_CONV, &item) != c.PAM_SUCCESS or item == null) return;
    const conv: *const c.pam_conv = @ptrCast(@alignCast(item));
    const cb = conv.conv orelse return;
    var msg = c.pam_message{ .msg_style = style, .msg = text };
    var msgs = [_][*c]const c.pam_message{&msg};
    var resp: [*c]c.pam_response = null;
    if (cb(1, &msgs, &resp, conv.appdata_ptr) == c.PAM_SUCCESS and resp != null) {
        if (resp[0].resp != null) std.c.free(resp[0].resp);
        std.c.free(resp);
    }
}

fn changePinViaCli(uid: [*:0]const u8, old: [*:0]const u8, new: [*:0]const u8) bool {
    var in_p: [2]c_int = undefined;
    if (pipe(&in_p) != 0) return false;
    const pid = fork();
    if (pid < 0) {
        _ = close(in_p[0]);
        _ = close(in_p[1]);
        return false;
    }
    if (pid == 0) {
        _ = dup2(in_p[0], 0);
        _ = close(in_p[0]);
        _ = close(in_p[1]);
        const nul = open("/dev/null", O_WRONLY | O_CLOEXEC, 0);
        if (nul >= 0) _ = dup2(nul, 1);
        const argv = [_:null]?[*:0]const u8{ SINTYKEY_BIN, "change-pin", "--uid", uid };
        _ = execv(SINTYKEY_BIN, &argv);
        _exit(127);
    }
    _ = close(in_p[0]);
    var ok = true;
    for ([_][]const u8{ std.mem.span(old), "\n", std.mem.span(new), "\n" }) |part| {
        if (write(in_p[1], part.ptr, part.len) != @as(isize, @intCast(part.len))) ok = false;
    }
    _ = close(in_p[1]);
    var status: c_int = 0;
    _ = waitpid(pid, &status, 0);
    return ok and (status & 0x7f) == 0 and ((status >> 8) & 0xff) == 0;
}

fn domainName(user: []const u8) bool {
    if (user.len == 0 or user.len > 64) return false;
    for (user, 0..) |ch, i| {
        const alnum = std.ascii.isAlphanumeric(ch);
        if (i == 0 and !alnum) return false;
        if (!alnum and ch != '.' and ch != '_' and ch != '-') return false;
    }
    return true;
}

fn exists(path: [*:0]const u8) bool {
    const fd = open(path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return false;
    _ = close(fd);
    return true;
}

fn domainUser(user: []const u8) bool {
    if (!domainName(user)) return false;
    var jb: [512]u8 = undefined;
    const join = std.fmt.bufPrintZ(&jb, "{s}/join.json", .{bo.domain_dir}) catch return false;
    if (!exists(join.ptr)) return false;
    var nb: [80]u8 = undefined;
    const nameZ = std.fmt.bufPrintZ(&nb, "{s}", .{user}) catch return false;
    if (c.getpwnam(nameZ.ptr) == null) return true;
    var lower: [64]u8 = undefined;
    for (user, 0..) |ch, i| lower[i] = std.ascii.toLower(ch);
    var ab: [600]u8 = undefined;
    const acct = std.fmt.bufPrintZ(&ab, "{s}/accounts/{s}", .{ bo.domain_dir, lower[0..user.len] }) catch return false;
    return exists(acct.ptr);
}

const DomainVerdict = enum { online, offline, wrong, disabled, expired, locked, needs_network, untrusted, conflict, failed };

fn domainLogin(user: []const u8, password: [*:0]const u8) DomainVerdict {
    const fd = socket(1, 1 | O_CLOEXEC, 0);
    if (fd < 0) return .failed;
    defer _ = close(fd);
    const tv = extern struct { sec: i64, usec: i64 }{ .sec = 60, .usec = 0 };
    _ = setsockopt(fd, 1, 20, &tv, @sizeOf(@TypeOf(tv)));
    _ = setsockopt(fd, 1, 21, &tv, @sizeOf(@TypeOf(tv)));
    var addr = extern struct { family: u16, path: [108]u8 }{ .family = 1, .path = [_]u8{0} ** 108 };
    if (bo.domain_sock.len >= addr.path.len) return .failed;
    @memcpy(addr.path[0..bo.domain_sock.len], bo.domain_sock);
    if (connect(fd, &addr, @sizeOf(@TypeOf(addr))) != 0) return .failed;
    var msg: [1024]u8 = undefined;
    defer std.crypto.secureZero(u8, msg[0..]);
    const line = std.fmt.bufPrint(&msg, "login\n{s}\n{s}\n", .{ user, std.mem.span(password) }) catch return .wrong;
    var off: usize = 0;
    while (off < line.len) {
        const w = write(fd, line[off..].ptr, line.len - off);
        if (w <= 0) return .failed;
        off += @intCast(w);
    }
    var reply: [64]u8 = undefined;
    var n: usize = 0;
    while (n < reply.len) {
        const r = read(fd, reply[n..].ptr, reply.len - n);
        if (r <= 0) break;
        n += @intCast(r);
        if (std.mem.indexOfScalar(u8, reply[0..n], '\n') != null) break;
    }
    const got = std.mem.trimEnd(u8, reply[0..n], "\n");
    const answers = [_]struct { []const u8, DomainVerdict }{
        .{ "OK online", .online },               .{ "OK offline", .offline },
        .{ "ERR Wrong", .wrong },                .{ "ERR Disabled", .disabled },
        .{ "ERR Expired", .expired },            .{ "ERR Locked", .locked },
        .{ "ERR NeedsNetwork", .needs_network }, .{ "ERR Untrusted", .untrusted },
        .{ "ERR Conflict", .conflict },
    };
    for (answers) |a| if (std.mem.eql(u8, got, a[0])) return a[1];
    return .failed;
}

fn domainAuthenticate(pamh: ?*c.pam_handle_t, user: [*c]const u8) c_int {
    const name = std.mem.span(user);
    const password = askSecret(pamh, "Password: ") orelse return c.PAM_CONV_ERR;
    defer {
        std.crypto.secureZero(u8, std.mem.span(password));
        std.c.free(password);
    }
    const verdict = domainLogin(name, password);
    switch (verdict) {
        .online, .offline => {},
        .failed => if (c.getpwnam(user) == null) return c.PAM_AUTHINFO_UNAVAIL,
        .wrong => return c.PAM_AUTH_ERR,
        .disabled => {
            tell(pamh, c.PAM_ERROR_MSG, "This account is disabled.");
            return c.PAM_AUTH_ERR;
        },
        .expired => {
            tell(pamh, c.PAM_ERROR_MSG, "The password has expired. Change it on a device connected to your organisation.");
            return c.PAM_AUTH_ERR;
        },
        .locked => {
            tell(pamh, c.PAM_ERROR_MSG, "Too many attempts. Try again later.");
            return c.PAM_AUTH_ERR;
        },
        .needs_network => {
            tell(pamh, c.PAM_ERROR_MSG, "Connect to your organisation's network to sign in.");
            return c.PAM_AUTH_ERR;
        },
        .untrusted => {
            tell(pamh, c.PAM_ERROR_MSG, "The domain controller could not prove who it is.");
            return c.PAM_AUTH_ERR;
        },
        .conflict => {
            tell(pamh, c.PAM_ERROR_MSG, "A local account already uses this name.");
            return c.PAM_AUTH_ERR;
        },
    }
    const pw = c.getpwnam(user) orelse return c.PAM_USER_UNKNOWN;
    if (accountLocked(user)) return c.PAM_AUTH_ERR;
    var uidbuf: [16]u8 = undefined;
    const uidZ = std.fmt.bufPrintZ(&uidbuf, "{d}", .{pw.*.pw_uid}) catch return c.PAM_AUTH_ERR;
    var ce = unsealViaCli(uidZ.ptr, password) orelse blk: {
        if (verdict != .online) return c.PAM_AUTH_ERR;
        tell(pamh, c.PAM_TEXT_INFO, "Your password was changed. Enter the previous one to unlock your files.");
        const old = askSecret(pamh, "Previous password: ") orelse return c.PAM_CONV_ERR;
        defer {
            std.crypto.secureZero(u8, std.mem.span(old));
            std.c.free(old);
        }
        if (!changePinViaCli(uidZ.ptr, old, password)) return c.PAM_AUTH_ERR;
        break :blk unsealViaCli(uidZ.ptr, password) orelse return c.PAM_AUTH_ERR;
    };
    defer std.crypto.secureZero(u8, ce.bytes[0..]);
    const heap: *Key = @ptrCast(@alignCast(std.c.malloc(@sizeOf(Key)) orelse return c.PAM_BUF_ERR));
    heap.* = ce;
    if (c.pam_set_data(pamh, DATA_KEY, heap, keyCleanup) != c.PAM_SUCCESS) {
        keyCleanup(pamh, heap, 0);
        return c.PAM_AUTH_ERR;
    }
    return c.PAM_SUCCESS;
}

// unsealViaCli execs `sintykey unseal --uid <uid>`, pipes the PIN to its stdin, and
// reads the raw 32-byte CE key from its stdout. Returns null on any failure (wrong
// PIN -> non-zero exit, throttled by the TPM lockout).
fn unsealViaCli(uid: [*:0]const u8, pin: [*:0]const u8) ?Key {
    var in_p: [2]c_int = undefined; // parent -> child stdin (the PIN)
    var out_p: [2]c_int = undefined; // child stdout -> parent (the key)
    if (pipe(&in_p) != 0) return null;
    if (pipe(&out_p) != 0) {
        _ = close(in_p[0]);
        _ = close(in_p[1]);
        return null;
    }
    const pid = fork();
    if (pid < 0) {
        for ([_]c_int{ in_p[0], in_p[1], out_p[0], out_p[1] }) |fd| _ = close(fd);
        return null;
    }
    if (pid == 0) {
        _ = dup2(in_p[0], 0);
        _ = dup2(out_p[1], 1);
        for ([_]c_int{ in_p[0], in_p[1], out_p[0], out_p[1] }) |fd| _ = close(fd);
        const argv = [_:null]?[*:0]const u8{ SINTYKEY_BIN, "unseal", "--uid", uid };
        if (getuid() != 0 and geteuid() == 0) {
            if (setgroups(0, null) != 0 or setresgid(0, 0, 0) != 0 or setresuid(0, 0, 0) != 0) _exit(127);
            const envp = [_:null]?[*:0]const u8{"PATH=/usr/sbin:/usr/bin"};
            _ = execve(SINTYKEY_BIN, &argv, &envp);
            _exit(127);
        }
        _ = execv(SINTYKEY_BIN, &argv);
        _exit(127);
    }
    _ = close(in_p[0]);
    _ = close(out_p[1]);
    _ = write(in_p[1], pin, std.mem.len(pin));
    _ = close(in_p[1]); // EOF to the child's stdin
    var k: Key = undefined;
    var n: usize = 0;
    while (n < KEYLEN) {
        const r = read(out_p[0], k.bytes[n..].ptr, KEYLEN - n);
        if (r <= 0) break;
        n += @intCast(r);
    }
    _ = close(out_p[0]);
    var status: c_int = 0;
    _ = waitpid(pid, &status, 0);
    const ok = (status & 0x7f) == 0 and ((status >> 8) & 0xff) == 0;
    if (!ok or n != KEYLEN) {
        std.crypto.secureZero(u8, k.bytes[0..]);
        return null;
    }
    return k;
}

const Verdict = enum { ok, fail, absent };

fn verifyViaDaemon(uid: []const u8, pin: [*:0]const u8) Verdict {
    const fd = socket(1, 1 | O_CLOEXEC, 0);
    if (fd < 0) return .absent;
    defer _ = close(fd);
    const tv = extern struct { sec: i64, usec: i64 }{ .sec = if (hasSecurityKeys(uid)) 40 else 6, .usec = 0 };
    _ = setsockopt(fd, 1, 20, &tv, @sizeOf(@TypeOf(tv)));
    _ = setsockopt(fd, 1, 21, &tv, @sizeOf(@TypeOf(tv)));
    var addr = extern struct { family: u16, path: [108]u8 }{ .family = 1, .path = [_]u8{0} ** 108 };
    @memcpy(addr.path[0..RECOVERD_SOCK.len], RECOVERD_SOCK);
    if (connect(fd, &addr, @sizeOf(@TypeOf(addr))) != 0) return .absent;
    const p = std.mem.span(pin);
    var msg: [320]u8 = undefined;
    const line = std.fmt.bufPrint(&msg, "verify\n{s}\n{s}\n", .{ uid, p }) catch return .fail;
    defer std.crypto.secureZero(u8, msg[0..]);
    var off: usize = 0;
    while (off < line.len) {
        const w = write(fd, line[off..].ptr, line.len - off);
        if (w <= 0) return .fail;
        off += @intCast(w);
    }
    var reply: [16]u8 = undefined;
    const n = read(fd, &reply, reply.len);
    if (n >= 2 and reply[0] == 'O' and reply[1] == 'K') return .ok;
    return .fail;
}

fn armQuickUnlock(uid: c_uint) void {
    const fd = socket(1, 1 | O_CLOEXEC, 0);
    if (fd < 0) return;
    defer _ = close(fd);
    const tv = extern struct { sec: i64, usec: i64 }{ .sec = 2, .usec = 0 };
    _ = setsockopt(fd, 1, 20, &tv, @sizeOf(@TypeOf(tv)));
    _ = setsockopt(fd, 1, 21, &tv, @sizeOf(@TypeOf(tv)));
    var addr = extern struct { family: u16, path: [108]u8 }{ .family = 1, .path = [_]u8{0} ** 108 };
    @memcpy(addr.path[0..RECOVERD_SOCK.len], RECOVERD_SOCK);
    if (connect(fd, &addr, @sizeOf(@TypeOf(addr))) != 0) return;
    var msg: [32]u8 = undefined;
    const line = std.fmt.bufPrint(&msg, "arm\n{d}\n", .{uid}) catch return;
    if (write(fd, line.ptr, line.len) != @as(isize, @intCast(line.len))) return;
    var reply: [8]u8 = undefined;
    _ = read(fd, &reply, reply.len);
}

fn keyCleanup(pamh: ?*c.pam_handle_t, data: ?*anyopaque, ec: c_int) callconv(.c) void {
    _ = pamh;
    _ = ec;
    if (data) |d| {
        const k: *Key = @ptrCast(@alignCast(d));
        std.crypto.secureZero(u8, k.bytes[0..]);
        std.c.free(d);
    }
}

fn hasArg(argc: c_int, argv: [*c][*c]const u8, name: []const u8) bool {
    if (argv == null) return false;
    var i: usize = 0;
    while (i < @as(usize, @intCast(@max(argc, 0)))) : (i += 1) {
        if (argv[i] != null and std.mem.eql(u8, std.mem.span(argv[i]), name)) return true;
    }
    return false;
}

fn takeTicket(out: *[64]u8) bool {
    const fd = open(BADGE_TICKET, O_RDONLY | O_NOFOLLOW | O_CLOEXEC, 0);
    if (fd < 0) return false;
    _ = unlink(BADGE_TICKET);
    defer _ = close(fd);
    var buf: [66]u8 = undefined;
    const n = read(fd, &buf, buf.len);
    defer std.crypto.secureZero(u8, buf[0..]);
    if (n != 64 and !(n == 65 and buf[64] == '\n')) return false;
    @memcpy(out[0..], buf[0..64]);
    return true;
}

fn badgeAuthenticate(pamh: ?*c.pam_handle_t) c_int {
    if (getuid() != 0 and geteuid() != 0) return c.PAM_AUTH_ERR;
    const resp = askPin(pamh) orelse return c.PAM_CONV_ERR;
    defer {
        std.crypto.secureZero(u8, std.mem.span(resp));
        std.c.free(resp);
    }
    var want: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, want[0..]);
    if (!takeTicket(&want)) return c.PAM_AUTH_ERR;
    const got = std.mem.span(resp);
    if (got.len != want.len) return c.PAM_AUTH_ERR;
    if (!std.crypto.timing_safe.eql([64]u8, got[0..64].*, want)) return c.PAM_AUTH_ERR;
    return c.PAM_SUCCESS;
}

export fn pam_sm_authenticate(pamh: ?*c.pam_handle_t, flags: c_int, argc: c_int, argv: [*c][*c]const u8) callconv(.c) c_int {
    _ = flags;

    var user: [*c]const u8 = null;
    if (c.pam_get_user(pamh, &user, null) != c.PAM_SUCCESS or user == null) return c.PAM_USER_UNKNOWN;
    if (getuid() == 0 and !hasArg(argc, argv, "verify") and domainUser(std.mem.span(user))) return domainAuthenticate(pamh, user);
    const pw = c.getpwnam(user) orelse return c.PAM_USER_UNKNOWN;
    // Refuse a locked account BEFORE touching the PIN/TPM (covers auth-only callers
    // like the lockscreen, which never runs the account phase).
    if (accountLocked(user)) {
        if (bo.debug_e2e) dbgCrown("auth user={s} REFUSED: account locked\n", .{std.mem.span(user)});
        return c.PAM_AUTH_ERR;
    }
    if (std.mem.eql(u8, std.mem.span(user), BADGE_USER)) return badgeAuthenticate(pamh);
    var uidbuf: [16]u8 = undefined;
    const uidZ = std.fmt.bufPrintZ(&uidbuf, "{d}", .{pw.*.pw_uid}) catch return c.PAM_AUTH_ERR;

    const pin = askPin(pamh) orelse return c.PAM_CONV_ERR;
    defer {
        const span = std.mem.span(pin);
        std.crypto.secureZero(u8, span);
        std.c.free(pin);
    }

    if (hasSecurityKeys(uidZ)) touchHint(pamh);

    if (getuid() != 0 or hasArg(argc, argv, "verify")) {
        switch (verifyViaDaemon(uidZ, pin)) {
            .ok => return c.PAM_SUCCESS,
            .fail => return c.PAM_AUTH_ERR,
            .absent => {},
        }
    }

    var ce = unsealViaCli(uidZ.ptr, pin) orelse return c.PAM_AUTH_ERR;
    defer std.crypto.secureZero(u8, ce.bytes[0..]);

    // Stash the unsealed key for the session phase (heap copy; wiped on cleanup).
    const heap: *Key = @ptrCast(@alignCast(std.c.malloc(@sizeOf(Key)) orelse return c.PAM_BUF_ERR));
    heap.* = ce;
    if (c.pam_set_data(pamh, DATA_KEY, heap, keyCleanup) != c.PAM_SUCCESS) {
        keyCleanup(pamh, heap, 0);
        return c.PAM_AUTH_ERR;
    }
    if (bo.debug_e2e) dbgCrown("auth user={s} pid={d} stashed-key ok\n", .{ std.mem.span(user), getpid() });
    return c.PAM_SUCCESS;
}

export fn pam_sm_setcred(pamh: ?*c.pam_handle_t, flags: c_int, argc: c_int, argv: [*c][*c]const u8) callconv(.c) c_int {
    _ = pamh;
    _ = flags;
    _ = argc;
    _ = argv;
    return c.PAM_SUCCESS;
}

// Account phase: the semantic place for "account is locked/disabled". Enforced for
// full-stack services (login/greetd/polkit) that call pam_acct_mgmt; the auth-phase
// check above additionally covers auth-only callers (the lockscreen).
export fn pam_sm_acct_mgmt(pamh: ?*c.pam_handle_t, flags: c_int, argc: c_int, argv: [*c][*c]const u8) callconv(.c) c_int {
    _ = flags;
    _ = argc;
    _ = argv;
    var user: [*c]const u8 = null;
    if (c.pam_get_user(pamh, &user, null) != c.PAM_SUCCESS or user == null) return c.PAM_USER_UNKNOWN;
    if (accountLocked(user)) return c.PAM_ACCT_EXPIRED;
    return c.PAM_SUCCESS;
}

// Install the stashed CE key into the kernel so the user's fscrypt data decrypts.
export fn pam_sm_open_session(pamh: ?*c.pam_handle_t, flags: c_int, argc: c_int, argv: [*c][*c]const u8) callconv(.c) c_int {
    _ = flags;
    _ = argc;
    _ = argv;

    var user: [*c]const u8 = null;
    _ = c.pam_get_user(pamh, &user, null);
    const uname = if (user != null) std.mem.span(user) else "?";

    var data: ?*const anyopaque = null;
    const gd = c.pam_get_data(pamh, DATA_KEY, &data);
    if (gd != c.PAM_SUCCESS or data == null) {
        if (bo.debug_e2e) dbgCrown("session user={s} pid={d} get_data FAILED rc={d} -> NO key added (silent success)\n", .{ uname, getpid(), gd });
        return c.PAM_SUCCESS;
    }
    const ce: *const Key = @ptrCast(@alignCast(data));

    // Add the key on the user's real home fs (the f2fs data volume).
    if (user == null) return c.PAM_SESSION_ERR;
    const pw = c.getpwnam(user) orelse return c.PAM_SESSION_ERR;
    const mfd = open(pw.*.pw_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (mfd < 0) return c.PAM_SESSION_ERR;
    defer _ = close(mfd);

    const total = @sizeOf(c.fscrypt_add_key_arg) + ce.bytes.len;
    const argp: [*]u8 = @ptrCast(std.c.malloc(total) orelse return c.PAM_BUF_ERR);
    defer std.c.free(argp);
    @memset(argp[0..total], 0);
    const arg: *c.fscrypt_add_key_arg = @ptrCast(@alignCast(argp));
    arg.key_spec.type = c.FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
    arg.raw_size = @intCast(ce.bytes.len);
    @memcpy(argp[@sizeOf(c.fscrypt_add_key_arg)..][0..ce.bytes.len], ce.bytes[0..]);
    const rc = c.ioctl(mfd, c.FS_IOC_ADD_ENCRYPTION_KEY, argp);
    if (bo.debug_e2e) {
        var idhex: [64]u8 = undefined;
        dbgCrown("session user={s} pid={d} pw_dir={s} add-key rc={d} added-id={s}\n", .{ uname, getpid(), std.mem.span(pw.*.pw_dir), rc, dbgHex(arg.key_spec.u.identifier[0..16], &idhex) });
    }
    if (rc != 0) return c.PAM_SESSION_ERR;
    armQuickUnlock(pw.*.pw_uid);
    // Positive crown proof: IN this session, with the key just added, does the
    // user's encrypted /home actually decrypt? Reading a plaintext-named file
    // succeeds only if the key is active. (The post-pam_end cat in a test harness
    // can't see this -- the real greetd session stays alive holding the key.)
    if (bo.debug_e2e) {
        var pbuf: [512]u8 = undefined;
        const fp = std.fmt.bufPrintZ(&pbuf, "{s}/.bashrc", .{std.mem.span(pw.*.pw_dir)}) catch return c.PAM_SUCCESS;
        const rfd = open(fp.ptr, O_RDONLY, 0);
        if (rfd >= 0) {
            var rb: [32]u8 = undefined;
            const n = read(rfd, &rb, rb.len);
            _ = close(rfd);
            dbgCrown("session IN-SESSION read .bashrc -> OK n={d} == CROWN: /home decrypts with the key just added\n", .{n});
        } else {
            dbgCrown("session IN-SESSION read .bashrc -> FAILED (plaintext name absent -> key not active, or no .bashrc)\n", .{});
        }
    }
    return c.PAM_SUCCESS;
}

export fn pam_sm_close_session(pamh: ?*c.pam_handle_t, flags: c_int, argc: c_int, argv: [*c][*c]const u8) callconv(.c) c_int {
    _ = pamh;
    _ = flags;
    _ = argc;
    _ = argv;
    return c.PAM_SUCCESS;
}
