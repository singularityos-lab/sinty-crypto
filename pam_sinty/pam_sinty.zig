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
extern fn read(fd: c_int, buf: [*]u8, n: usize) isize;
extern fn write(fd: c_int, buf: [*]const u8, n: usize) isize;
extern fn pipe(fds: *[2]c_int) c_int;
extern fn fork() c_int;
extern fn dup2(old: c_int, new: c_int) c_int;
extern fn execv(path: [*:0]const u8, argv: [*:null]const ?[*:0]const u8) c_int;
extern fn waitpid(pid: c_int, status: *c_int, options: c_int) c_int;
extern fn _exit(code: c_int) noreturn;
extern fn getpid() c_int;
const O_RDONLY: c_int = 0;
const O_WRONLY: c_int = 1;
const O_CREAT: c_int = 0o100;
const O_APPEND: c_int = 0o2000;
const O_DIRECTORY: c_int = 0o200000;
const O_CLOEXEC: c_int = 0o2000000;

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
const Key = extern struct { bytes: [KEYLEN]u8 };

fn askPin(pamh: ?*c.pam_handle_t) ?[*:0]u8 {
    var item: ?*const anyopaque = null;
    if (c.pam_get_item(pamh, c.PAM_CONV, &item) != c.PAM_SUCCESS or item == null) return null;
    const conv: *const c.pam_conv = @ptrCast(@alignCast(item));
    const cb = conv.conv orelse return null;

    var msg = c.pam_message{ .msg_style = c.PAM_PROMPT_ECHO_OFF, .msg = "PIN: " };
    var msgs = [_][*c]const c.pam_message{&msg};
    var resp: [*c]c.pam_response = null;
    if (cb(1, &msgs, &resp, conv.appdata_ptr) != c.PAM_SUCCESS or resp == null) return null;
    const pin = resp[0].resp;
    std.c.free(resp);
    return @ptrCast(pin);
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

fn keyCleanup(pamh: ?*c.pam_handle_t, data: ?*anyopaque, ec: c_int) callconv(.c) void {
    _ = pamh;
    _ = ec;
    if (data) |d| {
        const k: *Key = @ptrCast(@alignCast(d));
        std.crypto.secureZero(u8, k.bytes[0..]);
        std.c.free(d);
    }
}

export fn pam_sm_authenticate(pamh: ?*c.pam_handle_t, flags: c_int, argc: c_int, argv: [*c][*c]const u8) callconv(.c) c_int {
    _ = flags;
    _ = argc;
    _ = argv;

    var user: [*c]const u8 = null;
    if (c.pam_get_user(pamh, &user, null) != c.PAM_SUCCESS or user == null) return c.PAM_USER_UNKNOWN;
    const pw = c.getpwnam(user) orelse return c.PAM_USER_UNKNOWN;
    // Refuse a locked account BEFORE touching the PIN/TPM (covers auth-only callers
    // like the lockscreen, which never runs the account phase).
    if (accountLocked(user)) {
        if (bo.debug_e2e) dbgCrown("auth user={s} REFUSED: account locked\n", .{std.mem.span(user)});
        return c.PAM_AUTH_ERR;
    }
    var uidbuf: [16]u8 = undefined;
    const uidZ = std.fmt.bufPrintZ(&uidbuf, "{d}", .{pw.*.pw_uid}) catch return c.PAM_AUTH_ERR;

    const pin = askPin(pamh) orelse return c.PAM_CONV_ERR;
    defer {
        const span = std.mem.span(pin);
        std.crypto.secureZero(u8, span);
        std.c.free(pin);
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
