//! sintykey: the single key-custody CLI. atom-firstboot (provision), Settings
//! (change-pin), polkit/confirm (verify-pin), pam_sinty (unseal) call it. The TPM
//! is done in one place -- sintykey-tpm (tpm2-tools) -- so there is no drift; this
//! CLI execs it. Works against swtpm in a VM and a real TPM on hardware. PIN(s) on
//! stdin, never on a command line.
const std = @import("std");
const key = @import("sintykey");
const bo = @import("build_options");
const c = @cImport({
    @cInclude("linux/fscrypt.h");
    @cInclude("sys/ioctl.h");
});

// Raw libc (linked): robust against the churny std.fs/posix API in this Zig.
extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern fn read(fd: c_int, buf: [*]u8, n: usize) isize;
extern fn write(fd: c_int, buf: [*]const u8, n: usize) isize;
extern fn close(fd: c_int) c_int;
extern fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
extern fn unlink(path: [*:0]const u8) c_int;
extern fn getenv(name: [*:0]const u8) ?[*:0]u8;
extern fn fork() c_int;
extern fn execvp(file: [*:0]const u8, argv: [*:null]const ?[*:0]const u8) c_int;
extern fn waitpid(pid: c_int, status: *c_int, options: c_int) c_int;
extern fn _exit(code: c_int) noreturn;
const O_RDONLY: c_int = 0;
const O_APPEND: c_int = 0o2000;
// NOTE: no getenv -- state dir, TPM helper, and fscrypt enforcement are all
// compile-time (build_options), so nothing in the environment can redirect the
// blob store, swap the TPM helper, or disable encryption at runtime.
const O_WRONLY: c_int = 1;
const O_CREAT: c_int = 0o100;
const O_TRUNC: c_int = 0o1000;
const O_DIRECTORY: c_int = 0o200000;
const O_CLOEXEC: c_int = 0o2000000;

const KEYLEN = 32;

fn die(msg: []const u8) noreturn {
    std.debug.print("sintykey: {s}\n", .{msg});
    std.process.exit(1);
}

// Compile-time (build_options): secure defaults in the shipped image, overridable
// only at build time for tests.
fn stateDir() []const u8 {
    return bo.state_dir;
}
// Transient plaintext secrets (PIN, raw key, unseal output) live here, on tmpfs (RAM),
// NOT on the unencrypted persistent state_dir -- so cleartext key/PIN never hit disk.
fn scratchDir() []const u8 {
    return bo.scratch_dir;
}
extern fn chmod(path: [*:0]const u8, mode: c_uint) c_int;
extern fn fchmod(fd: c_int, mode: c_uint) c_int;
extern fn fchown(fd: c_int, owner: c_uint, group: c_uint) c_int;
const O_NOFOLLOW: c_int = 0o400000;
fn ensureScratch() void {
    var b: [512]u8 = undefined;
    const z = std.fmt.bufPrintZ(&b, "{s}", .{scratchDir()}) catch return;
    // A boot unit creates scratch_dir root-owned 0700 before any user session exists (so a
    // local user can't pre-create it world-writable and read our secrets). We create-if-absent
    // and re-assert 0700 as a backstop -- it must NEVER be world-writable.
    _ = mkdir(z.ptr, 0o700);
    _ = chmod(z.ptr, 0o700);
}
var tpm_bin_buf: [512]u8 = undefined;
fn tpmBin() [*:0]const u8 {
    return (std.fmt.bufPrintZ(&tpm_bin_buf, "{s}", .{bo.tpm_bin}) catch unreachable).ptr;
}

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
    var pb: [512]u8 = undefined;
    const p = std.fmt.bufPrintZ(&pb, "{s}/.dbg-crown", .{stateDir()}) catch return;
    const fd = open(p.ptr, O_WRONLY | O_CREAT | O_APPEND, 0o600);
    if (fd < 0) return;
    defer _ = close(fd);
    var lb: [256]u8 = undefined;
    const ln = std.fmt.bufPrint(&lb, fmt, args) catch return;
    _ = write(fd, ln.ptr, ln.len);
}

fn argFlag(args: []const [:0]const u8, name: []const u8) ?[]const u8 {
    var i: usize = 1;
    while (i + 1 < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], name)) return args[i + 1];
    }
    return null;
}

fn readStdin(buf: []u8) []u8 {
    var n: usize = 0;
    while (n < buf.len) {
        const r = read(0, buf[n..].ptr, buf.len - n);
        if (r <= 0) break;
        n += @intCast(r);
    }
    return buf[0..n];
}

fn nextLine(s: *[]const u8) []const u8 {
    const nl = std.mem.indexOfScalar(u8, s.*, '\n') orelse s.len;
    var end = nl;
    while (end > 0 and s.*[end - 1] == '\r') end -= 1;
    const line = s.*[0..end];
    s.* = if (nl < s.len) s.*[nl + 1 ..] else s.*[s.len..];
    return line;
}

// runTpm execs sintykey-tpm with an explicit argv (no shell) and returns true on
// exit code 0. The TPM secrets travel as 0600 files, never as argv.
fn runTpm(argv: [*:null]const ?[*:0]const u8) bool {
    const pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        _ = execvp(argv[0].?, argv);
        _exit(127);
    }
    var status: c_int = 0;
    _ = waitpid(pid, &status, 0);
    return (status & 0x7f) == 0 and ((status >> 8) & 0xff) == 0;
}

fn writeSecret(path: [*:0]const u8, data: []const u8) bool {
    const fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0o600);
    if (fd < 0) return false;
    _ = write(fd, data.ptr, data.len);
    _ = close(fd);
    return true;
}

fn readFileAll(path: [*:0]const u8, buf: []u8) ?usize {
    const fd = open(path, O_RDONLY, 0);
    if (fd < 0) return null;
    defer _ = close(fd);
    var n: usize = 0;
    while (n < buf.len) {
        const r = read(fd, buf[n..].ptr, buf.len - n);
        if (r <= 0) break;
        n += @intCast(r);
    }
    return n;
}

const Paths = struct {
    pub_b: [512]u8 = undefined,
    priv_b: [512]u8 = undefined,
    pin_b: [512]u8 = undefined,
    pubZ: [:0]u8 = undefined,
    privZ: [:0]u8 = undefined,
    pinZ: [:0]u8 = undefined,
    fn init(self: *Paths, sd: []const u8, uid: []const u8) void {
        ensureScratch();
        // persistent sealed blobs stay on state_dir; the transient plaintext PIN goes to tmpfs scratch
        self.pubZ = std.fmt.bufPrintZ(&self.pub_b, "{s}/{s}.pub", .{ sd, uid }) catch die("path too long");
        self.privZ = std.fmt.bufPrintZ(&self.priv_b, "{s}/{s}.priv", .{ sd, uid }) catch die("path too long");
        self.pinZ = std.fmt.bufPrintZ(&self.pin_b, "{s}/.pin.{s}", .{ scratchDir(), uid }) catch die("path too long");
    }
};

// seal K under the PIN via the TPM (sintykey-tpm). Returns false if the TPM is
// unavailable (no swtpm/device) -- provision stays graceful.
fn tpmSeal(sd: []const u8, p: *Paths, ce: *const key.Key, pin: []const u8) bool {
    _ = sd; // sealed blobs come from p (state_dir); transient key/pin now live on tmpfs scratch
    var kb: [512]u8 = undefined;
    const keyf = std.fmt.bufPrintZ(&kb, "{s}/.k.tmp", .{scratchDir()}) catch die("path too long");
    if (!writeSecret(keyf, ce.bytes[0..])) return false;
    defer _ = unlink(keyf.ptr);
    if (!writeSecret(p.pinZ.ptr, pin)) return false;
    defer _ = unlink(p.pinZ.ptr);
    return runTpm(&.{ tpmBin(), "seal", keyf.ptr, p.pinZ.ptr, p.pubZ.ptr, p.privZ.ptr, null });
}

fn setFscryptPolicy(home: [:0]const u8, ce: *const key.Key) void {
    if (!bo.enforce_fscrypt) {
        // dev/test build only -- the shipped image is built with enforce_fscrypt=true,
        // making this branch comptime-dead: provision ALWAYS encrypts.
        std.debug.print("sintykey: enforce_fscrypt=false (dev build) -- skipping fscrypt policy\n", .{});
        return;
    }
    const fd = open(home.ptr, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (fd < 0) die("cannot open home dir");
    defer _ = close(fd);

    const total = @sizeOf(c.fscrypt_add_key_arg) + ce.bytes.len;
    const buf = std.heap.page_allocator.alloc(u8, total) catch die("oom");
    defer std.heap.page_allocator.free(buf);
    @memset(buf, 0);
    const arg: *c.fscrypt_add_key_arg = @ptrCast(@alignCast(buf.ptr));
    arg.key_spec.type = c.FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
    arg.raw_size = @intCast(ce.bytes.len);
    @memcpy(buf[@sizeOf(c.fscrypt_add_key_arg)..][0..ce.bytes.len], ce.bytes[0..]);
    if (c.ioctl(fd, c.FS_IOC_ADD_ENCRYPTION_KEY, buf.ptr) != 0) die("fscrypt add-key failed");

    if (bo.debug_e2e) {
        var idhex: [64]u8 = undefined;
        dbgCrown("provision policy-id={s} homefd-ok\n", .{dbgHex(arg.key_spec.u.identifier[0..16], &idhex)});
    }

    var pol = std.mem.zeroes(c.fscrypt_policy_v2);
    pol.version = 2;
    pol.contents_encryption_mode = c.FSCRYPT_MODE_AES_256_XTS;
    pol.filenames_encryption_mode = c.FSCRYPT_MODE_AES_256_CTS;
    pol.flags = c.FSCRYPT_POLICY_FLAGS_PAD_16;
    @memcpy(&pol.master_key_identifier, &arg.key_spec.u.identifier);
    if (c.ioctl(fd, c.FS_IOC_SET_ENCRYPTION_POLICY, &pol) != 0)
        die("fscrypt set-policy failed (home must be EMPTY: run before populating skel)");
}

fn cmdProvision(args: []const [:0]const u8) u8 {
    const uid = argFlag(args, "--uid") orelse die("provision needs --uid");
    const home = argFlag(args, "--home") orelse die("provision needs --home");
    _ = argFlag(args, "--user");
    const sd = stateDir();

    var pinbuf: [256]u8 = undefined;
    var rest: []const u8 = readStdin(&pinbuf);
    const pin = nextLine(&rest);
    // An empty/short PIN seals with an empty TPM authValue -> the DA lockout never
    // engages and the CE key unseals with (almost) no secret. Refuse it.
    if (pin.len < 4) die("PIN too short: minimum 4 characters");
    var homez: [512]u8 = undefined;
    const homeZ = std.fmt.bufPrintZ(&homez, "{s}", .{home}) catch die("home too long");

    var ce: key.Key = undefined;
    if (key.sintykey_generate(&ce) != 0) die("key generation failed");
    defer std.crypto.secureZero(u8, ce.bytes[0..]);

    var sdz: [512]u8 = undefined;
    const sdZ = std.fmt.bufPrintZ(&sdz, "{s}", .{sd}) catch die("state dir too long");
    _ = mkdir(sdZ.ptr, 0o700);

    // Seal the CE key to the TPM under the PIN (the DA-lockout throttles guesses).
    var p: Paths = .{};
    p.init(sd, uid);
    if (!tpmSeal(sd, &p, &ce, pin)) {
        if (bo.enforce_tpm)
            // RC: no working TPM -> the PIN could never unseal. Fail loudly instead
            // of creating an account that reports success but cannot PIN-login.
            die("TPM seal failed -- no working TPM (need /dev/tpmrm0). Refusing to provision a PIN that cannot unlock.");
        std.debug.print("sintykey: warning: TPM seal unavailable (dev build) -- key lives in the recovery wrap only\n", .{});
    }

    // Recovery wrap: the escape hatch for a forgotten PIN or a cleared TPM.
    var rec: [64]u8 = undefined;
    if (key.sintykey_recovery_generate(&rec, rec.len) != 0) die("recovery-code generation failed");
    const recZ: [*:0]const u8 = @ptrCast(&rec);
    var blob: [128]u8 = undefined;
    var blen: usize = blob.len; // pass the buffer capacity in; wrap sets it to the blob size out
    if (key.sintykey_recovery_wrap(&ce, recZ, &blob, &blen) != 0) die("recovery wrap failed");
    var rbuf: [512]u8 = undefined;
    const rp = std.fmt.bufPrintZ(&rbuf, "{s}/{s}.recovery", .{ sd, uid }) catch die("uid too long");
    if (!writeSecret(rp.ptr, blob[0..blen])) die("cannot write recovery blob");

    // fscrypt: encrypt the (empty) home under this key.
    setFscryptPolicy(homeZ, &ce);

    const rc = std.mem.sliceTo(&rec, 0);
    _ = write(1, rc.ptr, rc.len);
    _ = write(1, "\n", 1);
    return 0;
}

fn cmdVerifyPin(args: []const [:0]const u8) u8 {
    const uid = argFlag(args, "--uid") orelse die("verify-pin needs --uid");
    const sd = stateDir();
    var buf: [256]u8 = undefined;
    var rest: []const u8 = readStdin(&buf);
    const pin = nextLine(&rest);
    var p: Paths = .{};
    p.init(sd, uid);
    if (!writeSecret(p.pinZ.ptr, pin)) return 1;
    defer _ = unlink(p.pinZ.ptr);
    return if (runTpm(&.{ tpmBin(), "verify", p.pinZ.ptr, p.pubZ.ptr, p.privZ.ptr, null })) 0 else 1;
}

// unseal: PIN on stdin, the raw 32-byte CE key on stdout (for pam_sinty).
fn cmdUnseal(args: []const [:0]const u8) u8 {
    const uid = argFlag(args, "--uid") orelse die("unseal needs --uid");
    const sd = stateDir();
    var buf: [256]u8 = undefined;
    var rest: []const u8 = readStdin(&buf);
    const pin = nextLine(&rest);
    var p: Paths = .{};
    p.init(sd, uid);
    if (!writeSecret(p.pinZ.ptr, pin)) return 1;
    defer _ = unlink(p.pinZ.ptr);
    var ob: [512]u8 = undefined;
    const outf = std.fmt.bufPrintZ(&ob, "{s}/.out.{s}", .{ scratchDir(), uid }) catch die("path too long");
    defer _ = unlink(outf.ptr);
    if (!runTpm(&.{ tpmBin(), "unseal", p.pinZ.ptr, p.pubZ.ptr, p.privZ.ptr, outf.ptr, null })) return 1;
    var k: [KEYLEN]u8 = undefined;
    const n = readFileAll(outf.ptr, &k) orelse return 1;
    if (n != KEYLEN) return 1;
    _ = write(1, &k, KEYLEN);
    std.crypto.secureZero(u8, k[0..]);
    return 0;
}

// change-pin: unseal under the old PIN, re-seal under the new one.
fn cmdChangePin(args: []const [:0]const u8) u8 {
    const uid = argFlag(args, "--uid") orelse die("change-pin needs --uid");
    const sd = stateDir();
    var buf: [512]u8 = undefined;
    var rest: []const u8 = readStdin(&buf);
    const old = nextLine(&rest);
    const new = nextLine(&rest);
    if (new.len < 4) die("PIN too short: minimum 4 characters");
    var p: Paths = .{};
    p.init(sd, uid);

    // unseal K under the old PIN
    if (!writeSecret(p.pinZ.ptr, old)) return 1;
    var ob: [512]u8 = undefined;
    const outf = std.fmt.bufPrintZ(&ob, "{s}/.out.{s}", .{ scratchDir(), uid }) catch die("path too long");
    const ok = runTpm(&.{ tpmBin(), "unseal", p.pinZ.ptr, p.pubZ.ptr, p.privZ.ptr, outf.ptr, null });
    _ = unlink(p.pinZ.ptr);
    if (!ok) {
        _ = unlink(outf.ptr);
        return 1;
    }
    var ce: key.Key = undefined;
    const n = readFileAll(outf.ptr, ce.bytes[0..]);
    _ = unlink(outf.ptr);
    if (n == null or n.? != KEYLEN) return 1;
    defer std.crypto.secureZero(u8, ce.bytes[0..]);

    // re-seal under the new PIN (overwrites pub/priv)
    return if (tpmSeal(sd, &p, &ce, new)) 0 else 1;
}

// recover: recovery-code + new PIN on stdin. Unwraps the CE key from the recovery
// blob (the escape hatch: a forgotten PIN or a cleared TPM never loses the data)
// and re-seals it under the new PIN. The fscrypt policy is unchanged (same key).
fn cmdRecover(args: []const [:0]const u8) u8 {
    const uid = argFlag(args, "--uid") orelse die("recover needs --uid");
    const sd = stateDir();
    var buf: [512]u8 = undefined;
    var rest: []const u8 = readStdin(&buf);
    const code = nextLine(&rest);
    const new = nextLine(&rest);
    if (new.len < 4) die("PIN too short: minimum 4 characters");
    var cb: [128]u8 = undefined;
    const codeZ = std.fmt.bufPrintZ(&cb, "{s}", .{code}) catch die("recovery code too long");

    var rbuf: [512]u8 = undefined;
    const rp = std.fmt.bufPrintZ(&rbuf, "{s}/{s}.recovery", .{ sd, uid }) catch die("uid too long");
    var blob: [128]u8 = undefined;
    const blen = readFileAll(rp.ptr, &blob) orelse return 1;

    var ce: key.Key = undefined;
    if (key.sintykey_recovery_unwrap(&blob, blen, codeZ.ptr, &ce) != 0) return 1; // wrong recovery code
    defer std.crypto.secureZero(u8, ce.bytes[0..]);

    var p: Paths = .{};
    p.init(sd, uid);
    return if (tpmSeal(sd, &p, &ce, new)) 0 else 1;
}

// secureDir creates dir `path` with `mode` without a shell and fail-closed: mkdir sets
// the mode atomically, then it opens the dir with O_NOFOLLOW (a pre-planted symlink makes
// this fail) and re-asserts mode/owner on the fd, so there is no path TOCTOU. Returns false
// on any anomaly (symlink, not a directory, chmod/chown refused).
fn secureDir(path: [*:0]const u8, mode: c_uint, root_only: bool) bool {
    _ = mkdir(path, mode & 0o777);
    const fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, 0);
    if (fd < 0) return false;
    defer _ = close(fd);
    if (fchmod(fd, mode) != 0) return false;
    if (root_only and fchown(fd, 0, 0) != 0) return false;
    return true;
}

// cmdMkdirs creates the early-boot sinty runtime dirs, replacing a /bin/sh -c one-liner
// in the boot unit (Tier-1 hardening: no shell in the pre-sysinit path):
//   /run/sinty     1777           session registry (users write session-<uid>)
//   /run/sintykey  0700 root:root transient CE-key/PIN scratch
fn cmdMkdirs(_: []const [:0]const u8) u8 {
    if (!secureDir("/run/sinty", 0o1777, false)) die("mkdirs: /run/sinty");
    if (!secureDir("/run/sintykey", 0o700, true)) die("mkdirs: /run/sintykey");
    return 0;
}

pub fn main(init: std.process.Init.Minimal) u8 {
    var it = std.process.Args.Iterator.init(init.args);
    var argv: [32][:0]const u8 = undefined;
    var n: usize = 0;
    while (it.next()) |a| {
        if (n >= argv.len) break;
        argv[n] = a;
        n += 1;
    }
    const args = argv[0..n];
    if (args.len < 2) die("usage: sintykey <provision|change-pin|verify-pin|unseal|recover|mkdirs> [flags]");
    const cmd = args[1];
    if (std.mem.eql(u8, cmd, "mkdirs")) return cmdMkdirs(args);
    if (std.mem.eql(u8, cmd, "provision")) return cmdProvision(args);
    if (std.mem.eql(u8, cmd, "change-pin")) return cmdChangePin(args);
    if (std.mem.eql(u8, cmd, "verify-pin")) return cmdVerifyPin(args);
    if (std.mem.eql(u8, cmd, "unseal")) return cmdUnseal(args);
    if (std.mem.eql(u8, cmd, "recover")) return cmdRecover(args);
    die("unknown subcommand");
}
