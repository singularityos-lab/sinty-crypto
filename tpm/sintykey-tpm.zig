//! sintykey-tpm: the real TPM 2.0 backend, native Zig over libtss2 ESYS (no shell,
//! no tpm2-tools subprocess, no PATH lookup). Seals the CE key under the PIN, protected
//! by the TPM's dictionary-attack lockout. Same CLI contract the sintykey Zig CLI execs:
//!   ensure-primary
//!   seal   <keyfile> <pinfile> <pub_out> <priv_out>
//!   unseal <pinfile> <pub> <priv> <out>
//!   verify <pinfile> <pub> <priv>                 (exit 0 ok / 1 wrong-PIN)
//!
//! The TCTI is chosen by the SINTYKEY_TCTI env (e.g. "swtpm:host=127.0.0.1,port=2321"
//! in a VM); default is the kernel resource manager on hardware. The PIN is read from a
//! 0600 file, never argv. The sealed object lives under a persistent ECC primary at
//! 0x81000001, created once in the owner hierarchy.
const std = @import("std");
const c = @cImport({
    @cInclude("tss2/tss2_esys.h");
    @cInclude("tss2/tss2_mu.h");
    @cInclude("tss2/tss2_rc.h");
    @cInclude("tss2/tss2_tctildr.h");
});

const PERSISTENT: u32 = 0x81000001;

// Raw POSIX for file I/O and env (Zig 0.16's std.fs/Io is not used here, matching the CLI).
extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern fn read(fd: c_int, buf: [*]u8, n: usize) isize;
extern fn write(fd: c_int, buf: [*]const u8, n: usize) isize;
extern fn close(fd: c_int) c_int;
extern fn fsync(fd: c_int) c_int;
extern fn getenv(name: [*:0]const u8) ?[*:0]const u8;
extern fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
const O_RDONLY: c_int = 0;
const O_WRONLY: c_int = 1;
const O_CREAT: c_int = 0o100;
const O_TRUNC: c_int = 0o1000;

fn fatal(comptime msg: []const u8, args: anytype) noreturn {
    std.debug.print("sintykey-tpm: " ++ msg ++ "\n", args);
    std.process.exit(1);
}
fn ck(rc: c.TSS2_RC, comptime what: []const u8) void {
    if (rc != c.TSS2_RC_SUCCESS) fatal(what ++ " failed: 0x{x} ({s})", .{ rc, c.Tss2_RC_Decode(rc) });
}

fn readFile(path: [:0]const u8, buf: []u8) []u8 {
    const fd = open(path.ptr, O_RDONLY, 0);
    if (fd < 0) fatal("open {s}", .{path});
    defer _ = close(fd);
    var n: usize = 0;
    while (n < buf.len) {
        const r = read(fd, buf[n..].ptr, buf.len - n);
        if (r <= 0) break;
        n += @intCast(r);
    }
    return buf[0..n];
}
fn writeFileSecret(path: [:0]const u8, bytes: []const u8) void {
    const fd = open(path.ptr, O_WRONLY | O_CREAT | O_TRUNC, 0o600);
    if (fd < 0) fatal("create {s}", .{path});
    // Loop the write (a single write() may be short and silently truncate the sealed blob),
    // fsync so it survives power loss, and check close: a truncated .priv/.pub would make the
    // key unrecoverable while the seal reported success.
    var off: usize = 0;
    while (off < bytes.len) {
        const w = write(fd, bytes[off..].ptr, bytes.len - off);
        if (w <= 0) {
            _ = close(fd);
            fatal("write {s}", .{path});
        }
        off += @intCast(w);
    }
    if (fsync(fd) != 0) {
        _ = close(fd);
        fatal("fsync {s}", .{path});
    }
    if (close(fd) != 0) fatal("close {s}", .{path});
}

fn esysInit() *c.ESYS_CONTEXT {
    // Silence tss2's own stderr logging: the handle-not-found (first ensure-primary) and
    // wrong-PIN (verify) paths are normal control flow. We surface REAL errors via ck().
    // overwrite=0 leaves an operator's TSS2_LOG in place for debugging.
    _ = setenv("TSS2_LOG", "all+none", 0);
    var tcti: ?*c.TSS2_TCTI_CONTEXT = null;
    // SINTYKEY_TCTI selects the transport (swtpm in a VM, device on hw). NULL -> tctildr default.
    const conf = getenv("SINTYKEY_TCTI");
    ck(c.Tss2_TctiLdr_Initialize(if (conf) |cc| cc else null, &tcti), "tcti init");
    var ctx: ?*c.ESYS_CONTEXT = null;
    ck(c.Esys_Initialize(&ctx, tcti, null), "esys init");
    // TPM2_SU_CLEAR; a re-startup on an already-started TPM returns INITIALIZE -- ignore it.
    _ = c.Esys_Startup(ctx, c.TPM2_SU_CLEAR);
    return ctx.?;
}

// SRK-like ECC storage parent (restricted decrypt), the standard TCG template.
fn primaryTemplate() c.TPM2B_PUBLIC {
    var t = std.mem.zeroes(c.TPM2B_PUBLIC);
    const p = &t.publicArea;
    p.type = c.TPM2_ALG_ECC;
    p.nameAlg = c.TPM2_ALG_SHA256;
    p.objectAttributes = c.TPMA_OBJECT_FIXEDTPM | c.TPMA_OBJECT_FIXEDPARENT |
        c.TPMA_OBJECT_SENSITIVEDATAORIGIN | c.TPMA_OBJECT_USERWITHAUTH |
        c.TPMA_OBJECT_RESTRICTED | c.TPMA_OBJECT_DECRYPT;
    p.parameters.eccDetail.symmetric.algorithm = c.TPM2_ALG_AES;
    p.parameters.eccDetail.symmetric.keyBits.aes = 128;
    p.parameters.eccDetail.symmetric.mode.aes = c.TPM2_ALG_CFB;
    p.parameters.eccDetail.scheme.scheme = c.TPM2_ALG_NULL;
    p.parameters.eccDetail.curveID = c.TPM2_ECC_NIST_P256;
    p.parameters.eccDetail.kdf.scheme = c.TPM2_ALG_NULL;
    return t;
}

// Sealed-data object: keyedhash carrying the CE key, unlocked by the PIN (userAuth), bound
// to this TPM+parent. No origin flag (we supply the data); no sign/decrypt/restricted.
fn sealTemplate() c.TPM2B_PUBLIC {
    var t = std.mem.zeroes(c.TPM2B_PUBLIC);
    const p = &t.publicArea;
    p.type = c.TPM2_ALG_KEYEDHASH;
    p.nameAlg = c.TPM2_ALG_SHA256;
    p.objectAttributes = c.TPMA_OBJECT_FIXEDTPM | c.TPMA_OBJECT_FIXEDPARENT | c.TPMA_OBJECT_USERWITHAUTH;
    p.parameters.keyedHashDetail.scheme.scheme = c.TPM2_ALG_NULL;
    return t;
}

fn ensurePrimary(ctx: *c.ESYS_CONTEXT) c.ESYS_TR {
    var handle: c.ESYS_TR = c.ESYS_TR_NONE;
    // Reuse the persistent primary if it already exists.
    if (c.Esys_TR_FromTPMPublic(ctx, PERSISTENT, c.ESYS_TR_NONE, c.ESYS_TR_NONE, c.ESYS_TR_NONE, &handle) == c.TSS2_RC_SUCCESS)
        return handle;

    const inSensitive = std.mem.zeroes(c.TPM2B_SENSITIVE_CREATE);
    const inPublic = primaryTemplate();
    const outsideInfo = std.mem.zeroes(c.TPM2B_DATA);
    const creationPCR = std.mem.zeroes(c.TPML_PCR_SELECTION);
    var transient: c.ESYS_TR = c.ESYS_TR_NONE;
    var outPublic: ?*c.TPM2B_PUBLIC = null;
    ck(c.Esys_CreatePrimary(ctx, c.ESYS_TR_RH_OWNER, c.ESYS_TR_PASSWORD, c.ESYS_TR_NONE, c.ESYS_TR_NONE, &inSensitive, &inPublic, &outsideInfo, &creationPCR, &transient, &outPublic, null, null, null), "createprimary");
    c.Esys_Free(outPublic);
    // Persist it at 0x81000001, then drop the transient copy.
    var persistent: c.ESYS_TR = c.ESYS_TR_NONE;
    ck(c.Esys_EvictControl(ctx, c.ESYS_TR_RH_OWNER, transient, c.ESYS_TR_PASSWORD, c.ESYS_TR_NONE, c.ESYS_TR_NONE, PERSISTENT, &persistent), "evictcontrol");
    _ = c.Esys_FlushContext(ctx, transient);
    return persistent;
}

fn authFromPin(pin: []const u8) c.TPM2B_AUTH {
    var a = std.mem.zeroes(c.TPM2B_AUTH);
    if (pin.len > a.buffer.len) fatal("pin too long", .{});
    a.size = @intCast(pin.len);
    @memcpy(a.buffer[0..pin.len], pin);
    return a;
}

// sealPcrs parses SINTYKEY_SEAL_PCRS (comma-separated decimal PCR indices, SHA-256 bank)
// into a selection. Returns null when unset/empty, which keeps sealing PIN-only (the object
// is unlocked by the authValue alone). When set, the sealed key additionally requires the
// listed PCRs to hold their seal-time values, binding it to a measured boot state.
fn sealPcrs() ?c.TPML_PCR_SELECTION {
    const env = getenv("SINTYKEY_SEAL_PCRS") orelse return null;
    const s = std.mem.span(env);
    if (s.len == 0) return null;
    var sel = std.mem.zeroes(c.TPML_PCR_SELECTION);
    sel.count = 1;
    sel.pcrSelections[0].hash = c.TPM2_ALG_SHA256;
    sel.pcrSelections[0].sizeofSelect = 3; // 24 PCRs / 8 bits
    var any = false;
    var it = std.mem.tokenizeScalar(u8, s, ',');
    while (it.next()) |tok| {
        const idx = std.fmt.parseInt(u8, std.mem.trim(u8, tok, " "), 10) catch continue;
        if (idx >= 24) continue;
        sel.pcrSelections[0].pcrSelect[idx / 8] |= (@as(u8, 1) << @intCast(idx % 8));
        any = true;
    }
    return if (any) sel else null;
}

// symNull is the "no parameter encryption" symmetric definition for a bare policy session.
fn symNull() c.TPMT_SYM_DEF {
    var s = std.mem.zeroes(c.TPMT_SYM_DEF);
    s.algorithm = c.TPM2_ALG_NULL;
    return s;
}

// runPolicy applies PolicyAuthValue (the PIN must be satisfied) then PolicyPCR (the sealed
// PCR state must match the current one) to a session. Used both trial (to derive the
// seal-time authPolicy digest) and real (to authorize an unseal).
fn runPolicy(ctx: *c.ESYS_CONTEXT, session: c.ESYS_TR, sel: *const c.TPML_PCR_SELECTION) void {
    ck(c.Esys_PolicyAuthValue(ctx, session, c.ESYS_TR_NONE, c.ESYS_TR_NONE, c.ESYS_TR_NONE), "policy authvalue");
    ck(c.Esys_PolicyPCR(ctx, session, c.ESYS_TR_NONE, c.ESYS_TR_NONE, c.ESYS_TR_NONE, null, sel), "policy pcr");
}

// policyDigest runs the policy in a trial session and returns its digest: the authPolicy
// the sealed object is created under, so only that same PIN+PCR combination can unseal it.
fn policyDigest(ctx: *c.ESYS_CONTEXT, sel: *const c.TPML_PCR_SELECTION) c.TPM2B_DIGEST {
    var sym = symNull();
    var session: c.ESYS_TR = c.ESYS_TR_NONE;
    ck(c.Esys_StartAuthSession(ctx, c.ESYS_TR_NONE, c.ESYS_TR_NONE, c.ESYS_TR_NONE, c.ESYS_TR_NONE, c.ESYS_TR_NONE, null, c.TPM2_SE_TRIAL, &sym, c.TPM2_ALG_SHA256, &session), "start trial session");
    defer _ = c.Esys_FlushContext(ctx, session);
    runPolicy(ctx, session, sel);
    var digest: ?*c.TPM2B_DIGEST = null;
    ck(c.Esys_PolicyGetDigest(ctx, session, c.ESYS_TR_NONE, c.ESYS_TR_NONE, c.ESYS_TR_NONE, &digest), "policy getdigest");
    const d = digest.?.*;
    c.Esys_Free(digest);
    return d;
}

fn doSeal(ctx: *c.ESYS_CONTEXT, keyfile: [:0]const u8, pinfile: [:0]const u8, pubOut: [:0]const u8, privOut: [:0]const u8) void {
    const primary = ensurePrimary(ctx);
    var keybuf: [256]u8 = undefined;
    var pinbuf: [256]u8 = undefined;
    const keyb = readFile(keyfile, &keybuf);
    const pinb = readFile(pinfile, &pinbuf);

    var inSensitive = std.mem.zeroes(c.TPM2B_SENSITIVE_CREATE);
    // userAuth = the PIN (throttled by the TPM DA lockout); data = the CE key to seal.
    const auth = authFromPin(pinb);
    inSensitive.sensitive.userAuth = auth;
    if (keyb.len > inSensitive.sensitive.data.buffer.len) fatal("key too long to seal", .{});
    inSensitive.sensitive.data.size = @intCast(keyb.len);
    @memcpy(inSensitive.sensitive.data.buffer[0..keyb.len], keyb);

    var inPublic = sealTemplate();
    // When PCRs are configured, seal under a policy (PIN authValue AND the measured PCR
    // state) instead of the plain authValue: clear USERWITHAUTH so a user-role unseal must
    // satisfy the authPolicy, and set that policy to the trial digest.
    if (sealPcrs()) |sel| {
        inPublic.publicArea.authPolicy = policyDigest(ctx, &sel);
        inPublic.publicArea.objectAttributes &= ~@as(c.TPMA_OBJECT, c.TPMA_OBJECT_USERWITHAUTH);
    }
    const outsideInfo = std.mem.zeroes(c.TPM2B_DATA);
    const creationPCR = std.mem.zeroes(c.TPML_PCR_SELECTION);
    var outPrivate: ?*c.TPM2B_PRIVATE = null;
    var outPublic: ?*c.TPM2B_PUBLIC = null;
    ck(c.Esys_Create(ctx, primary, c.ESYS_TR_PASSWORD, c.ESYS_TR_NONE, c.ESYS_TR_NONE, &inSensitive, &inPublic, &outsideInfo, &creationPCR, &outPrivate, &outPublic, null, null, null), "create(seal)");
    defer c.Esys_Free(outPrivate);
    defer c.Esys_Free(outPublic);
    std.crypto.secureZero(u8, &keybuf);
    std.crypto.secureZero(u8, &pinbuf);

    // Marshal the pub/priv blobs to files (the sealed CE key never leaves the TPM in the clear).
    var mbuf: [4096]u8 = undefined;
    var off: usize = 0;
    ck(c.Tss2_MU_TPM2B_PUBLIC_Marshal(outPublic, &mbuf, mbuf.len, &off), "marshal pub");
    writeFileSecret(pubOut, mbuf[0..off]);
    off = 0;
    ck(c.Tss2_MU_TPM2B_PRIVATE_Marshal(outPrivate, &mbuf, mbuf.len, &off), "marshal priv");
    writeFileSecret(privOut, mbuf[0..off]);
}

// Load the sealed object and unseal it with the PIN. Returns the unsealed bytes into `out`
// on success; returns null when the PIN is wrong (or the object won't load) so the caller
// can map that to a clean verify/unseal failure without a fatal.
fn tryUnseal(ctx: *c.ESYS_CONTEXT, pinfile: [:0]const u8, pubIn: [:0]const u8, privIn: [:0]const u8, out: []u8) ?[]u8 {
    const primary = ensurePrimary(ctx);
    var pbuf: [4096]u8 = undefined;
    var rbuf: [4096]u8 = undefined;
    const pb = readFile(pubIn, &pbuf);
    const rb = readFile(privIn, &rbuf);

    var pubBlob = std.mem.zeroes(c.TPM2B_PUBLIC);
    var privBlob = std.mem.zeroes(c.TPM2B_PRIVATE);
    var off: usize = 0;
    ck(c.Tss2_MU_TPM2B_PUBLIC_Unmarshal(&pbuf, pb.len, &off, &pubBlob), "unmarshal pub");
    off = 0;
    ck(c.Tss2_MU_TPM2B_PRIVATE_Unmarshal(&rbuf, rb.len, &off, &privBlob), "unmarshal priv");

    var item: c.ESYS_TR = c.ESYS_TR_NONE;
    if (c.Esys_Load(ctx, primary, c.ESYS_TR_PASSWORD, c.ESYS_TR_NONE, c.ESYS_TR_NONE, &privBlob, &pubBlob, &item) != c.TSS2_RC_SUCCESS)
        return null;
    defer _ = c.Esys_FlushContext(ctx, item);

    var pinbuf: [256]u8 = undefined;
    const pinb = readFile(pinfile, &pinbuf);
    const auth = authFromPin(pinb);
    ck(c.Esys_TR_SetAuth(ctx, item, &auth), "set pin auth");
    std.crypto.secureZero(u8, &pinbuf);

    // A PCR-bound object carries an authPolicy: authorize it with a real policy session
    // (PolicyAuthValue binds the PIN we just set, PolicyPCR requires the sealed PCR state),
    // so a wrong PIN OR a changed measured-boot state both fail the unseal. An object with
    // no authPolicy keeps the plain password-auth path (backward compatible).
    var authSession: c.ESYS_TR = c.ESYS_TR_PASSWORD;
    var pcrSession: c.ESYS_TR = c.ESYS_TR_NONE;
    if (pubBlob.publicArea.authPolicy.size > 0) {
        if (sealPcrs()) |sel| {
            var sym = symNull();
            if (c.Esys_StartAuthSession(ctx, c.ESYS_TR_NONE, c.ESYS_TR_NONE, c.ESYS_TR_NONE, c.ESYS_TR_NONE, c.ESYS_TR_NONE, null, c.TPM2_SE_POLICY, &sym, c.TPM2_ALG_SHA256, &pcrSession) != c.TSS2_RC_SUCCESS)
                return null;
            runPolicy(ctx, pcrSession, &sel);
            authSession = pcrSession;
        } else return null; // sealed under a policy but no selection configured now
    }
    defer if (pcrSession != c.ESYS_TR_NONE) {
        _ = c.Esys_FlushContext(ctx, pcrSession);
    };

    var outData: ?*c.TPM2B_SENSITIVE_DATA = null;
    // A wrong PIN (or, for a PCR-bound object, a changed PCR state) fails here and advances
    // the DA lockout -> not fatal, just "no".
    if (c.Esys_Unseal(ctx, item, authSession, c.ESYS_TR_NONE, c.ESYS_TR_NONE, &outData) != c.TSS2_RC_SUCCESS)
        return null;
    defer {
        c.Esys_Free(outData);
    }
    const n = outData.?.size;
    if (n > out.len) fatal("unseal output too large", .{});
    @memcpy(out[0..n], outData.?.buffer[0..n]);
    return out[0..n];
}

pub fn main(init: std.process.Init.Minimal) u8 {
    var it = std.process.Args.Iterator.init(init.args);
    var argv: [8][:0]const u8 = undefined;
    var argc: usize = 0;
    while (it.next()) |a| {
        if (argc >= argv.len) break;
        argv[argc] = a;
        argc += 1;
    }
    if (argc < 2) fatal("usage: sintykey-tpm ensure-primary|seal|unseal|verify ...", .{});
    const cmd = argv[1];
    const ctx = esysInit(); // one-shot CLI: the process exits right after, so the OS reclaims the ESYS ctx

    if (std.mem.eql(u8, cmd, "ensure-primary")) {
        _ = ensurePrimary(ctx);
    } else if (std.mem.eql(u8, cmd, "seal")) {
        if (argc < 6) fatal("seal needs <keyfile> <pinfile> <pub_out> <priv_out>", .{});
        doSeal(ctx, argv[2], argv[3], argv[4], argv[5]);
    } else if (std.mem.eql(u8, cmd, "unseal")) {
        if (argc < 6) fatal("unseal needs <pinfile> <pub> <priv> <out>", .{});
        var out: [256]u8 = undefined;
        const r = tryUnseal(ctx, argv[2], argv[3], argv[4], &out) orelse fatal("unseal failed (wrong PIN or bad object)", .{});
        writeFileSecret(argv[5], r);
        std.crypto.secureZero(u8, &out);
    } else if (std.mem.eql(u8, cmd, "verify")) {
        if (argc < 5) fatal("verify needs <pinfile> <pub> <priv>", .{});
        var out: [256]u8 = undefined;
        const ok = tryUnseal(ctx, argv[2], argv[3], argv[4], &out) != null;
        std.crypto.secureZero(u8, &out);
        return if (ok) 0 else 1;
    } else {
        fatal("unknown command: {s}", .{cmd});
    }
    return 0;
}
