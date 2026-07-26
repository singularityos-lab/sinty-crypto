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
    @cInclude("dirent.h");
});

// Raw libc (linked): robust against the churny std.fs/posix API in this Zig.
extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern fn read(fd: c_int, buf: [*]u8, n: usize) isize;
extern fn write(fd: c_int, buf: [*]const u8, n: usize) isize;
extern fn close(fd: c_int) c_int;
extern fn fsync(fd: c_int) c_int;
extern fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
extern fn unlink(path: [*:0]const u8) c_int;
extern fn getenv(name: [*:0]const u8) ?[*:0]u8;
extern fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
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
// Without a TPM there is no hardware dictionary-attack lockout, so the software L1 tier
// must carry the strength in the secret itself: a short PIN is refused there and a real
// passphrase is required. On the hardware tiers a short PIN stays safe (the TPM throttles).
const l1_min_secret = 12;

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

fn hasFlag(args: []const [:0]const u8, name: []const u8) bool {
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], name)) return true;
    }
    return false;
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
    // A single write() may be short, leaving a truncated secret while the caller is told it
    // succeeded; and without fsync the bytes may never reach disk before a power loss. Loop
    // the write, fsync, and check close so "true" means the whole secret is durably on disk.
    var off: usize = 0;
    while (off < data.len) {
        const w = write(fd, data[off..].ptr, data.len - off);
        if (w <= 0) {
            _ = close(fd);
            return false;
        }
        off += @intCast(w);
    }
    if (fsync(fd) != 0) {
        _ = close(fd);
        return false;
    }
    return close(fd) == 0;
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

// When there is no working TPM (a VM without swtpm, a board with no TPM), the seal
// falls back to software: the key is wrapped with Argon2id(secret)+XChaCha, the same
// audited primitive as the recovery blob. This is L1: with no hardware DA-lockout the
// throttle is only the KDF cost, so a short secret is correspondingly weaker -- an
// accepted L1 limitation. The system stays FUNCTIONAL and strengthens to the TPM tier
// automatically where hardware is present. The tier is chosen by which blob exists on
// disk: {name}.priv (+ .pub) = TPM-sealed; {name}.soft = software L1.

// softSeal wraps `k` under `secret` and writes state_dir/{name}.soft (0600 root). It is
// the L1 fallback used when the TPM seal is unavailable.
fn softSeal(sd: []const u8, name: []const u8, k: *const key.Key, secret: []const u8) bool {
    var sb: [512]u8 = undefined;
    const secz = std.fmt.bufPrintZ(&sb, "{s}", .{secret}) catch return false;
    var blob: [128]u8 = undefined;
    var blen: usize = blob.len;
    if (key.sintykey_recovery_wrap(k, secz.ptr, &blob, &blen) != 0) return false;
    var pb: [512]u8 = undefined;
    const path = std.fmt.bufPrintZ(&pb, "{s}/{s}.soft", .{ sd, name }) catch return false;
    return writeSecret(path.ptr, blob[0..blen]);
}

// resealAny seals `k` under `secret` at the best available tier: TPM if it works, else the
// software L1 fallback (unless enforce_tpm forbids it). Used by provision/change-pin/recover
// so every write path degrades identically.
fn resealAny(sd: []const u8, uid: []const u8, p: *Paths, k: *const key.Key, secret: []const u8) bool {
    if (tpmSeal(sd, p, k, secret)) return true;
    if (bo.enforce_tpm) return false;
    if (secret.len < l1_min_secret) return false; // L1 needs a real passphrase, not a short PIN
    return softSeal(sd, uid, k, secret);
}

// unsealAny recovers `k` under `secret` from whichever tier holds it: TPM blobs if present
// and valid, else the software L1 blob.
fn unsealAny(sd: []const u8, uid: []const u8, p: *Paths, secret: []const u8, k: *key.Key) bool {
    if (!writeSecret(p.pinZ.ptr, secret)) return false;
    defer _ = unlink(p.pinZ.ptr);
    var ob: [512]u8 = undefined;
    const outf = std.fmt.bufPrintZ(&ob, "{s}/.out.{s}", .{ scratchDir(), uid }) catch return false;
    if (runTpm(&.{ tpmBin(), "unseal", p.pinZ.ptr, p.pubZ.ptr, p.privZ.ptr, outf.ptr, null })) {
        const n = readFileAll(outf.ptr, k.bytes[0..]);
        _ = unlink(outf.ptr);
        return n != null and n.? == KEYLEN;
    }
    return softUnseal(sd, uid, secret, k);
}

// softUnseal reads state_dir/{name}.soft and unwraps `k` under `secret`. Returns false
// if the blob is absent (not this tier) or the secret is wrong.
fn softUnseal(sd: []const u8, name: []const u8, secret: []const u8, k: *key.Key) bool {
    var pb: [512]u8 = undefined;
    const path = std.fmt.bufPrintZ(&pb, "{s}/{s}.soft", .{ sd, name }) catch return false;
    var blob: [128]u8 = undefined;
    const blen = readFileAll(path.ptr, &blob) orelse return false;
    var sb: [512]u8 = undefined;
    const secz = std.fmt.bufPrintZ(&sb, "{s}", .{secret}) catch return false;
    return key.sintykey_recovery_unwrap(&blob, blen, secz.ptr, k) == 0;
}

// addFscryptKey adds `k` to the filesystem holding `dir` (FS_IOC_ADD_ENCRYPTION_KEY),
// so directories already carrying our policy become readable. Unlike setFscryptPolicy it
// does not set a policy -- unlock only needs the key present. Returns false on any error
// (unlock stays graceful: a missing key just leaves the data locked, it never dies).
fn addFscryptKey(dir: [:0]const u8, k: *const key.Key) bool {
    const fd = open(dir.ptr, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (fd < 0) return false;
    defer _ = close(fd);
    const total = @sizeOf(c.fscrypt_add_key_arg) + k.bytes.len;
    const buf = std.heap.page_allocator.alloc(u8, total) catch return false;
    defer std.heap.page_allocator.free(buf);
    @memset(buf, 0);
    const arg: *c.fscrypt_add_key_arg = @ptrCast(@alignCast(buf.ptr));
    arg.key_spec.type = c.FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
    arg.raw_size = @intCast(k.bytes.len);
    @memcpy(buf[@sizeOf(c.fscrypt_add_key_arg)..][0..k.bytes.len], k.bytes[0..]);
    return c.ioctl(fd, c.FS_IOC_ADD_ENCRYPTION_KEY, buf.ptr) == 0;
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

    // Seal the CE key to the TPM under the PIN (the DA-lockout throttles guesses). With
    // no working TPM, degrade gracefully to the software L1 tier (Argon2id under the PIN)
    // so the account can still PIN-login on a VM or a TPM-less board, unless the operator
    // built with enforce_tpm to forbid the fallback.
    var p: Paths = .{};
    p.init(sd, uid);
    if (!tpmSeal(sd, &p, &ce, pin)) {
        if (bo.enforce_tpm)
            die("TPM seal failed and enforce_tpm set -- refusing to provision a PIN that cannot unlock");
        if (pin.len < l1_min_secret)
            die("no TPM present: without the hardware lockout a short PIN is unsafe -- provide a passphrase of at least 12 characters");
        if (!softSeal(sd, uid, &ce, pin))
            die("both TPM and software seal failed -- cannot secure the PIN");
        std.debug.print("sintykey: no TPM -- provisioned at software tier (L1, passphrase-protected)\n", .{});
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
    if (runTpm(&.{ tpmBin(), "verify", p.pinZ.ptr, p.pubZ.ptr, p.privZ.ptr, null })) return 0;
    // Software L1 tier: a correct PIN unwraps the blob (AEAD tag holds); a wrong one fails.
    var k: key.Key = undefined;
    defer std.crypto.secureZero(u8, k.bytes[0..]);
    return if (softUnseal(sd, uid, pin, &k)) 0 else 1;
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
    if (runTpm(&.{ tpmBin(), "unseal", p.pinZ.ptr, p.pubZ.ptr, p.privZ.ptr, outf.ptr, null })) {
        var k: [KEYLEN]u8 = undefined;
        const n = readFileAll(outf.ptr, &k) orelse return 1;
        if (n != KEYLEN) return 1;
        _ = write(1, &k, KEYLEN);
        std.crypto.secureZero(u8, k[0..]);
        return 0;
    }
    // No TPM tier (or it refused): try the software L1 tier under the same PIN. A wrong
    // PIN fails the AEAD tag here, exactly as it fails the TPM authValue above.
    var sk: key.Key = undefined;
    if (!softUnseal(sd, uid, pin, &sk)) return 1;
    _ = write(1, &sk.bytes, KEYLEN);
    std.crypto.secureZero(u8, sk.bytes[0..]);
    return 0;
}

// The DE key protects system data that must be readable BEFORE any login (so the greeter
// can run): /var/{log,cache,spool}. It is unlocked with no PIN at boot. On hardware it is
// sealed to the TPM (empty authValue); with no TPM it degrades to a root-only key file
// (L1: at-rest encryption whose key is recoverable by root, no hardware confidentiality).
// device.pub is the presence marker the boot unit's Condition checks; the tier is chosen
// at unlock by which artifact exists: device.priv (+ .pub) = TPM, device.key = L1.
//
// LIMITATION (flagged for review): the TPM seal binds to the empty authValue only, not to
// a PCR / stable-root policy, so the TPM tier gives no stronger confidentiality than L1
// yet. Real DE hardware binding (stable-root PCR policy) is a follow-up in sintykey-tpm.
const deSubdirs = [_][]const u8{ "log", "cache", "spool" };

// setPolicyBestEffort sets our fscrypt policy on `dir` using key id `k`, returning false
// (never dying) when the directory is missing or not empty. provision-device applies the
// policy only to the subdirs it can, so a partially-populated /var never aborts the boot.
fn setPolicyBestEffort(dir: [:0]const u8, k: *const key.Key) bool {
    const fd = open(dir.ptr, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (fd < 0) return false;
    defer _ = close(fd);
    if (!addFscryptKeyFd(fd, k)) return false;

    var pol = std.mem.zeroes(c.fscrypt_policy_v2);
    pol.version = 2;
    pol.contents_encryption_mode = c.FSCRYPT_MODE_AES_256_XTS;
    pol.filenames_encryption_mode = c.FSCRYPT_MODE_AES_256_CTS;
    pol.flags = c.FSCRYPT_POLICY_FLAGS_PAD_16;
    keyIdentifier(k, &pol.master_key_identifier);
    return c.ioctl(fd, c.FS_IOC_SET_ENCRYPTION_POLICY, &pol) == 0;
}

// addFscryptKeyFd adds `k` to the filesystem backing an already-open dir fd and writes the
// resulting key identifier back into arg for the policy call. Split from addFscryptKey so
// provision (needs the id) and unlock (does not) share the add path.
fn addFscryptKeyFd(fd: c_int, k: *const key.Key) bool {
    const total = @sizeOf(c.fscrypt_add_key_arg) + k.bytes.len;
    const buf = std.heap.page_allocator.alloc(u8, total) catch return false;
    defer std.heap.page_allocator.free(buf);
    @memset(buf, 0);
    const arg: *c.fscrypt_add_key_arg = @ptrCast(@alignCast(buf.ptr));
    arg.key_spec.type = c.FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
    arg.raw_size = @intCast(k.bytes.len);
    @memcpy(buf[@sizeOf(c.fscrypt_add_key_arg)..][0..k.bytes.len], k.bytes[0..]);
    return c.ioctl(fd, c.FS_IOC_ADD_ENCRYPTION_KEY, buf.ptr) == 0;
}

// keyIdentifier recomputes the fscrypt key identifier for `k` by adding it to a throwaway
// (the identifier is a function of the key, deterministic), so set-policy and add-key agree.
fn keyIdentifier(k: *const key.Key, out: *[c.FSCRYPT_KEY_IDENTIFIER_SIZE]u8) void {
    // HKDF-derived identifier per the kernel: we obtain it from the add-key result on the
    // first subdir. Callers add the key on the same fd immediately before, so we read it
    // back from a fresh add on the state dir which shares the filesystem.
    const total = @sizeOf(c.fscrypt_add_key_arg) + k.bytes.len;
    const buf = std.heap.page_allocator.alloc(u8, total) catch return;
    defer std.heap.page_allocator.free(buf);
    @memset(buf, 0);
    const arg: *c.fscrypt_add_key_arg = @ptrCast(@alignCast(buf.ptr));
    arg.key_spec.type = c.FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
    arg.raw_size = @intCast(k.bytes.len);
    @memcpy(buf[@sizeOf(c.fscrypt_add_key_arg)..][0..k.bytes.len], k.bytes[0..]);
    var sdz: [512]u8 = undefined;
    const sdZ = std.fmt.bufPrintZ(&sdz, "{s}", .{stateDir()}) catch return;
    const fd = open(sdZ.ptr, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (fd < 0) return;
    defer _ = close(fd);
    if (c.ioctl(fd, c.FS_IOC_ADD_ENCRYPTION_KEY, buf.ptr) != 0) return;
    @memcpy(out, arg.key_spec.u.identifier[0..c.FSCRYPT_KEY_IDENTIFIER_SIZE]);
}

fn cmdProvisionDevice(_: []const [:0]const u8) u8 {
    const sd = stateDir();
    var sdz: [512]u8 = undefined;
    const sdZ = std.fmt.bufPrintZ(&sdz, "{s}", .{sd}) catch die("state dir too long");
    _ = mkdir(sdZ.ptr, 0o700);

    var de: key.Key = undefined;
    if (key.sintykey_generate(&de) != 0) die("device key generation failed");
    defer std.crypto.secureZero(u8, de.bytes[0..]);

    // Seal the device key with an empty authValue (no PIN, unlocked at boot). With no TPM,
    // degrade to a root-only 0600 key file. device.pub is the presence marker either way.
    var p: Paths = .{};
    p.init(sd, "device");
    var pubmark: [512]u8 = undefined;
    const pubZ = std.fmt.bufPrintZ(&pubmark, "{s}/device.pub", .{sd}) catch die("path too long");
    if (tpmSeal(sd, &p, &de, "")) {
        std.debug.print("sintykey: device key sealed to TPM\n", .{});
    } else {
        if (bo.enforce_tpm) die("TPM seal failed and enforce_tpm set -- cannot provision the device key");
        var kb: [512]u8 = undefined;
        const keyZ = std.fmt.bufPrintZ(&kb, "{s}/device.key", .{sd}) catch die("path too long");
        if (!writeSecret(keyZ.ptr, de.bytes[0..])) die("cannot write device key");
        _ = writeSecret(pubZ.ptr, "L1\n");
        std.debug.print("sintykey: no TPM -- device key at software tier (L1)\n", .{});
    }

    // Apply the fscrypt policy to each DE subdir under /var that is present and empty.
    // Best-effort: a populated subdir is skipped, never aborting the provision.
    for (deSubdirs) |sub| {
        var db: [512]u8 = undefined;
        const dz = std.fmt.bufPrintZ(&db, "/var/{s}", .{sub}) catch continue;
        _ = setPolicyBestEffort(dz, &de);
    }
    return 0;
}

fn cmdUnlockDevice(args: []const [:0]const u8) u8 {
    const mount = argFlag(args, "--mount") orelse "/var";
    const sd = stateDir();

    // Recover the device key from whichever tier provisioned it. If neither exists the DE
    // feature was never provisioned: nothing to unlock, exit 0 so the boot unit is inert.
    var de: key.Key = undefined;
    defer std.crypto.secureZero(u8, de.bytes[0..]);
    var priv_b: [512]u8 = undefined;
    const privZ = std.fmt.bufPrintZ(&priv_b, "{s}/device.priv", .{sd}) catch die("path too long");
    if (open(privZ.ptr, O_RDONLY, 0) >= 0) {
        var p: Paths = .{};
        p.init(sd, "device");
        var ob: [512]u8 = undefined;
        const outf = std.fmt.bufPrintZ(&ob, "{s}/.out.device", .{scratchDir()}) catch die("path too long");
        defer _ = unlink(outf.ptr);
        _ = writeSecret(p.pinZ.ptr, "");
        defer _ = unlink(p.pinZ.ptr);
        if (!runTpm(&.{ tpmBin(), "unseal", p.pinZ.ptr, p.pubZ.ptr, p.privZ.ptr, outf.ptr, null })) return 1;
        const n = readFileAll(outf.ptr, de.bytes[0..]) orelse return 1;
        if (n != KEYLEN) return 1;
    } else {
        var kb: [512]u8 = undefined;
        const keyZ = std.fmt.bufPrintZ(&kb, "{s}/device.key", .{sd}) catch die("path too long");
        const n = readFileAll(keyZ.ptr, de.bytes[0..]) orelse return 0; // not provisioned -> inert
        if (n != KEYLEN) return 1;
    }

    // Add the key to the mount's filesystem so its policy'd subdirs decrypt.
    var mz: [512]u8 = undefined;
    const mountZ = std.fmt.bufPrintZ(&mz, "{s}", .{mount}) catch die("mount path too long");
    return if (addFscryptKey(mountZ, &de)) 0 else 1;
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

    var ce: key.Key = undefined;
    defer std.crypto.secureZero(u8, ce.bytes[0..]);
    if (!unsealAny(sd, uid, &p, old, &ce)) return 1; // wrong old PIN or no blob
    // re-seal under the new PIN at the same tier the box supports (overwrites the blob)
    return if (resealAny(sd, uid, &p, &ce, new)) 0 else 1;
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
    return if (resealAny(sd, uid, &p, &ce, new)) 0 else 1;
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

extern fn pipe(fds: *[2]c_int) c_int;
extern fn dup2(oldfd: c_int, newfd: c_int) c_int;

// runTpmCapture execs sintykey-tpm and captures its stdout into `out`, returning the
// captured slice (empty on failure). Used for lock-read, whose one-line state output the
// wrapper parses. Secrets never travel this path (lock state is not a secret).
fn runTpmCapture(argv: [*:null]const ?[*:0]const u8, out: []u8, ok: *bool) []u8 {
    ok.* = false;
    var fds: [2]c_int = undefined;
    if (pipe(&fds) != 0) return out[0..0];
    const pid = fork();
    if (pid < 0) {
        _ = close(fds[0]);
        _ = close(fds[1]);
        return out[0..0];
    }
    if (pid == 0) {
        _ = close(fds[0]);
        _ = dup2(fds[1], 1);
        _ = close(fds[1]);
        _ = execvp(argv[0].?, argv);
        _exit(127);
    }
    _ = close(fds[1]);
    var n: usize = 0;
    while (n < out.len) {
        const r = read(fds[0], out[n..].ptr, out.len - n);
        if (r <= 0) break;
        n += @intCast(r);
    }
    _ = close(fds[0]);
    var status: c_int = 0;
    _ = waitpid(pid, &status, 0);
    ok.* = (status & 0x7f) == 0 and ((status >> 8) & 0xff) == 0;
    return out[0..n];
}

// wipeKeys is the evil-maid wipe: it discards ALL fscrypt key custody so /var (DE) and
// every home (CE) become permanently unreadable. It deletes the TPM-sealed blobs, the
// software L1 blobs, the device key, and the recovery blobs from state_dir; with the key
// material gone no tier can ever re-derive a CE/DE key, so the ciphertext is cryptographically
// destroyed. Kernel-resident keys drop at the mandatory reboot the (un)lock triggers.
// Returns the number of artifacts removed.
fn wipeKeys() usize {
    const sd = stateDir();
    var sdz: [512]u8 = undefined;
    const sdZ = std.fmt.bufPrintZ(&sdz, "{s}", .{sd}) catch return 0;
    const dir = c.opendir(sdZ.ptr) orelse return 0;
    defer _ = c.closedir(dir);
    const suffixes = [_][]const u8{ ".priv", ".pub", ".soft", ".recovery", ".key" };
    var removed: usize = 0;
    while (c.readdir(dir)) |ent| {
        const name = std.mem.sliceTo(@as([*:0]const u8, @ptrCast(&ent.*.d_name)), 0);
        var match = false;
        for (suffixes) |sfx| {
            if (std.mem.endsWith(u8, name, sfx)) match = true;
        }
        if (!match) continue;
        var pb: [1024]u8 = undefined;
        const path = std.fmt.bufPrintZ(&pb, "{s}/{s}", .{ sd, name }) catch continue;
        if (unlink(path.ptr) == 0) removed += 1;
    }
    return removed;
}

// lock-state: read the hardware lock bit and print it in the recovery seam's format:
//   locked=<true|false>
//   unlock_count=<int>
// FAIL CLOSED: if the TPM helper cannot reach the TPM (nonzero exit) we print locked=true
// and EXIT NONZERO (2), so a missing/failed TPM is never mistaken for unlocked. A reachable
// TPM with the index undefined is a legitimate LOCKED (exit 0). The recovery agent
// (cryptoReadLockBit) parses these two lines.
fn cmdLockState(_: []const [:0]const u8) u8 {
    var buf: [256]u8 = undefined;
    var ok: bool = false;
    const outp = runTpmCapture(&.{ tpmBin(), "lock-read", null }, &buf, &ok);
    if (!ok) {
        _ = write(1, "locked=true\nunlock_count=0\n", 27);
        return 2;
    }
    const unlocked = std.mem.indexOf(u8, outp, "state=unlocked") != null;
    var count: []const u8 = "0";
    if (std.mem.indexOf(u8, outp, "unlocks=")) |i| {
        const rest = outp[i + "unlocks=".len ..];
        const end = std.mem.indexOfScalar(u8, rest, ' ') orelse rest.len;
        if (end > 0) count = rest[0..end];
    }
    var lb: [128]u8 = undefined;
    const line = std.fmt.bufPrint(&lb, "locked={s}\nunlock_count={s}\n", .{ if (unlocked) "false" else "true", count }) catch {
        _ = write(1, "locked=true\nunlock_count=0\n", 27);
        return 2;
    };
    _ = write(1, line.ptr, line.len);
    return 0;
}

// verity-state: print the dm-verity policy the loader must apply, straight from the TPM NV
// verity toggle (verity=on|off). Fail closed to verity=on. This is the loader's read seam.
fn cmdVerityState(_: []const [:0]const u8) u8 {
    var buf: [64]u8 = undefined;
    var ok: bool = false;
    const outp = runTpmCapture(&.{ tpmBin(), "verity-read", null }, &buf, &ok);
    const off = ok and std.mem.indexOf(u8, outp, "verity=off") != null;
    const line: []const u8 = if (off) "verity=off\n" else "verity=on\n";
    _ = write(1, line.ptr, line.len);
    return 0;
}

// wipe-var (cryptoWipeVar): the evil-maid wipe. Discards ALL CE/DE fscrypt key custody so
// /var and every home become permanently unreadable. Exit 0 on success.
fn cmdWipeVar(_: []const [:0]const u8) u8 {
    const n = wipeKeys();
    std.debug.print("sintykey: wiped {d} key artifact(s)\n", .{n});
    return 0;
}

// set-unlock (cryptoSetUnlockBit): flip the TPM NV lock bit to UNLOCKED and advance the
// monotonic unlock count. Exit 0 on success, nonzero if the TPM write failed.
fn cmdSetUnlock(_: []const [:0]const u8) u8 {
    if (!runTpm(&.{ tpmBin(), "lock-unlock", null })) return 1;
    return 0;
}

// set-lock: clear the TPM NV lock bit back to LOCKED (unlock count is monotonic, kept).
// The mirror of set-unlock, for the re-lock flow.
fn cmdSetLock(_: []const [:0]const u8) u8 {
    if (!runTpm(&.{ tpmBin(), "lock-relock", null })) return 1;
    return 0;
}

// disable-verity (cryptoDisableVerity): set the TPM NV verity toggle to OFF so the loader
// boots on its no-ATOM_ROOT_HASH path. The loader consumes the toggle by reading TPM NV
// index 0x01800003 (value 0xA5 == off), or via `sintykey verity-state`. Exit 0 on success.
fn cmdDisableVerity(_: []const [:0]const u8) u8 {
    if (!runTpm(&.{ tpmBin(), "verity-set-off", null })) return 1;
    return 0;
}

// enable-verity: set the verity toggle back ON (verified boot). Mirror of disable-verity.
fn cmdEnableVerity(_: []const [:0]const u8) u8 {
    if (!runTpm(&.{ tpmBin(), "verity-set-on", null })) return 1;
    return 0;
}

// unlock-bootloader --confirm: convenience wrapper that runs the whole unlock the recovery
// agent otherwise orchestrates step by step: wipe -> set-unlock -> disable-verity. Requires
// --confirm so the destructive wipe is never a single accidental invocation.
fn cmdUnlockBootloader(args: []const [:0]const u8) u8 {
    if (!hasFlag(args, "--confirm")) die("unlock-bootloader wipes ALL data -- re-run with --confirm");
    const n = wipeKeys();
    std.debug.print("sintykey: wiped {d} key artifact(s)\n", .{n});
    if (!runTpm(&.{ tpmBin(), "lock-unlock", null })) die("TPM lock bit set-unlocked failed");
    if (!runTpm(&.{ tpmBin(), "verity-set-off", null })) die("TPM verity toggle set-off failed");
    std.debug.print("sintykey: bootloader UNLOCKED (verity off at next boot)\n", .{});
    return 0;
}

// lock-bootloader --confirm: convenience wrapper for the re-lock: wipe -> set-lock ->
// enable-verity. Same --confirm gate.
fn cmdLockBootloader(args: []const [:0]const u8) u8 {
    if (!hasFlag(args, "--confirm")) die("lock-bootloader wipes ALL data -- re-run with --confirm");
    const n = wipeKeys();
    std.debug.print("sintykey: wiped {d} key artifact(s)\n", .{n});
    if (!runTpm(&.{ tpmBin(), "lock-relock", null })) die("TPM lock bit set-locked failed");
    if (!runTpm(&.{ tpmBin(), "verity-set-on", null })) die("TPM verity toggle set-on failed");
    std.debug.print("sintykey: bootloader LOCKED (verity on at next boot)\n", .{});
    return 0;
}

pub fn main(init: std.process.Init.Minimal) u8 {
    // Pass the measured-boot PCR selection down to sintykey-tpm (inherited across the
    // fork/exec in runTpm). Empty by default -> PIN-only sealing.
    if (bo.seal_pcrs.len > 0) {
        var pbuf: [64]u8 = undefined;
        if (std.fmt.bufPrintZ(&pbuf, "{s}", .{bo.seal_pcrs})) |z| {
            _ = setenv("SINTYKEY_SEAL_PCRS", z.ptr, 1);
        } else |_| {}
    }
    var it = std.process.Args.Iterator.init(init.args);
    var argv: [32][:0]const u8 = undefined;
    var n: usize = 0;
    while (it.next()) |a| {
        if (n >= argv.len) break;
        argv[n] = a;
        n += 1;
    }
    const args = argv[0..n];
    if (args.len < 2) die("usage: sintykey <provision|provision-device|unlock-device|change-pin|verify-pin|unseal|recover|mkdirs|lock-state|verity-state|wipe-var|set-unlock|set-lock|disable-verity|enable-verity|unlock-bootloader|lock-bootloader> [flags]");
    const cmd = args[1];
    if (std.mem.eql(u8, cmd, "mkdirs")) return cmdMkdirs(args);
    if (std.mem.eql(u8, cmd, "lock-state")) return cmdLockState(args);
    if (std.mem.eql(u8, cmd, "verity-state")) return cmdVerityState(args);
    if (std.mem.eql(u8, cmd, "wipe-var")) return cmdWipeVar(args);
    if (std.mem.eql(u8, cmd, "set-unlock")) return cmdSetUnlock(args);
    if (std.mem.eql(u8, cmd, "set-lock")) return cmdSetLock(args);
    if (std.mem.eql(u8, cmd, "disable-verity")) return cmdDisableVerity(args);
    if (std.mem.eql(u8, cmd, "enable-verity")) return cmdEnableVerity(args);
    if (std.mem.eql(u8, cmd, "unlock-bootloader")) return cmdUnlockBootloader(args);
    if (std.mem.eql(u8, cmd, "lock-bootloader")) return cmdLockBootloader(args);
    if (std.mem.eql(u8, cmd, "provision")) return cmdProvision(args);
    if (std.mem.eql(u8, cmd, "provision-device")) return cmdProvisionDevice(args);
    if (std.mem.eql(u8, cmd, "unlock-device")) return cmdUnlockDevice(args);
    if (std.mem.eql(u8, cmd, "change-pin")) return cmdChangePin(args);
    if (std.mem.eql(u8, cmd, "verify-pin")) return cmdVerifyPin(args);
    if (std.mem.eql(u8, cmd, "unseal")) return cmdUnseal(args);
    if (std.mem.eql(u8, cmd, "recover")) return cmdRecover(args);
    die("unknown subcommand");
}
