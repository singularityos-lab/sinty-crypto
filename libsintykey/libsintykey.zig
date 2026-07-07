//! libsintykey: key-custody behind pam_sinty and the installer, in Zig.
//! Recovery wrap uses std.crypto (Argon2id + XChaCha20-Poly1305) -- no libsodium.
//! The seal/unseal talk to the TPM (filled on hardware). C ABI is preserved
//! (libsintykey.h) so C consumers link it unchanged; Zig consumers can @import.
const std = @import("std");
const argon2 = std.crypto.pwhash.argon2;
const XChaCha = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

const KEYLEN = 32;
const SALTLEN = 16;
const NONCELEN = XChaCha.nonce_length; // 24
const TAGLEN = XChaCha.tag_length; // 16

pub const Key = extern struct { bytes: [KEYLEN]u8 };

const ENOSYS: c_int = -38;
const EIO: c_int = -5;
const EINVAL: c_int = -22;
const EACCES: c_int = -13;
const ENOSPC: c_int = -28;

fn newIo(t: *std.Io.Threaded) std.Io {
    t.* = .init(std.heap.page_allocator, .{});
    return t.io();
}

pub export fn sintykey_generate(out: *Key) c_int {
    var t: std.Io.Threaded = undefined;
    const io = newIo(&t);
    defer t.deinit();
    // randomSecure (getrandom, no fallback) for the CE MASTER key: fail closed if the
    // CSPRNG is unseedable rather than silently deriving it from pid+time+ASLR.
    io.randomSecure(&out.bytes) catch return EIO;
    return 0;
}

const B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // Crockford, no ambiguous glyphs

pub export fn sintykey_recovery_generate(out: [*]u8, out_len: usize) c_int {
    if (out_len < 40) return EINVAL;
    var t: std.Io.Threaded = undefined;
    const io = newIo(&t);
    defer t.deinit();
    var raw: [16]u8 = undefined;
    // randomSecure for the recovery-code seed (the brute-forceable secret): fail closed
    // rather than emit a low-entropy code from a weak fallback seed.
    io.randomSecure(&raw) catch return EIO;
    defer std.crypto.secureZero(u8, &raw); // wipe the code's binary preimage on return
    var o: usize = 0;
    var acc: u32 = 0;
    var bits: u5 = 0;
    var emitted: usize = 0;
    for (raw) |b| {
        acc = (acc << 8) | b;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            if (o + 2 >= out_len) return ENOSPC;
            if (emitted != 0 and emitted % 5 == 0) {
                out[o] = '-';
                o += 1;
            }
            out[o] = B32[(acc >> bits) & 0x1F];
            o += 1;
            emitted += 1;
        }
    }
    out[o] = 0;
    return 0;
}

fn derive(io: std.Io, secret: []const u8, salt: []const u8, key: *[32]u8) bool {
    argon2.kdf(std.heap.page_allocator, key, secret, salt, .{ .t = 3, .m = 65536, .p = 1 }, .argon2id, io) catch return false;
    return true;
}

pub export fn sintykey_recovery_wrap(k: *const Key, secret: [*:0]const u8, blob: [*]u8, blob_len: *usize) c_int {
    // blob_len is IN/OUT: the caller passes the buffer capacity; we refuse if it can't
    // hold the 88-byte blob, so an oversized write cannot run past the buffer.
    const need = SALTLEN + NONCELEN + KEYLEN + TAGLEN;
    if (blob_len.* < need) return ENOSPC;
    const sec = std.mem.span(secret);
    const salt = blob[0..SALTLEN];
    const nonce: *[NONCELEN]u8 = blob[SALTLEN..][0..NONCELEN];
    const ct = blob[SALTLEN + NONCELEN ..][0..KEYLEN];
    const tag: *[TAGLEN]u8 = blob[SALTLEN + NONCELEN + KEYLEN ..][0..TAGLEN];
    var t: std.Io.Threaded = undefined;
    const io = newIo(&t);
    defer t.deinit();
    io.random(salt);
    io.random(nonce);
    var dk: [32]u8 = undefined;
    if (!derive(io, sec, salt, &dk)) return EIO;
    XChaCha.encrypt(ct, tag, &k.bytes, "", nonce.*, dk);
    std.crypto.secureZero(u8, dk[0..]);
    blob_len.* = SALTLEN + NONCELEN + KEYLEN + TAGLEN;
    return 0;
}

pub export fn sintykey_recovery_unwrap(blob: [*]const u8, blob_len: usize, secret: [*:0]const u8, out: *Key) c_int {
    if (blob_len != SALTLEN + NONCELEN + KEYLEN + TAGLEN) return EINVAL;
    const sec = std.mem.span(secret);
    const salt = blob[0..SALTLEN];
    const nonce: *const [NONCELEN]u8 = blob[SALTLEN..][0..NONCELEN];
    const ct = blob[SALTLEN + NONCELEN ..][0..KEYLEN];
    const tag: *const [TAGLEN]u8 = blob[SALTLEN + NONCELEN + KEYLEN ..][0..TAGLEN];
    var t: std.Io.Threaded = undefined;
    const io = newIo(&t);
    defer t.deinit();
    var dk: [32]u8 = undefined;
    if (!derive(io, sec, salt, &dk)) return EIO;
    XChaCha.decrypt(&out.bytes, ct, tag.*, "", nonce.*, dk) catch {
        std.crypto.secureZero(u8, dk[0..]);
        return EACCES; // wrong recovery secret -> tag fails
    };
    std.crypto.secureZero(u8, dk[0..]);
    return 0;
}

pub export fn sintykey_tpm_seal(k: *const Key, pin: [*:0]const u8, blob_path: [*:0]const u8) c_int {
    _ = k; _ = pin; _ = blob_path; return ENOSYS;
}
pub export fn sintykey_tpm_unseal(blob_path: [*:0]const u8, pin: [*:0]const u8, out: *Key) c_int {
    _ = blob_path; _ = pin; _ = out; return ENOSYS;
}
pub export fn sintykey_tpm_reseal(blob_path: [*:0]const u8, k: *const Key, pin: [*:0]const u8) c_int {
    _ = blob_path; _ = k; _ = pin; return ENOSYS;
}
pub export fn sintykey_verify_pin(blob_path: [*:0]const u8, pin: [*:0]const u8) c_int {
    var k: Key = undefined;
    const r = sintykey_tpm_unseal(blob_path, pin, &k);
    std.crypto.secureZero(u8, k.bytes[0..]);
    return r;
}
pub export fn sintykey_change_pin(blob_path: [*:0]const u8, old_pin: [*:0]const u8, new_pin: [*:0]const u8) c_int {
    var k: Key = undefined;
    var r = sintykey_tpm_unseal(blob_path, old_pin, &k);
    if (r == 0) r = sintykey_tpm_reseal(blob_path, &k, new_pin);
    std.crypto.secureZero(u8, k.bytes[0..]);
    return r;
}

test "recovery wrap roundtrip + wrong secret rejected" {
    var k: Key = undefined;
    _ = sintykey_generate(&k);
    var rec: [64]u8 = undefined;
    try std.testing.expectEqual(@as(c_int, 0), sintykey_recovery_generate(&rec, rec.len));
    const secret: [*:0]const u8 = @ptrCast(&rec);

    var blob: [128]u8 = undefined;
    var blen: usize = 0;
    try std.testing.expectEqual(@as(c_int, 0), sintykey_recovery_wrap(&k, secret, &blob, &blen));

    var out: Key = undefined;
    try std.testing.expectEqual(@as(c_int, 0), sintykey_recovery_unwrap(&blob, blen, secret, &out));
    try std.testing.expect(std.mem.eql(u8, &k.bytes, &out.bytes));

    const wrong: [*:0]const u8 = "WRONG-SECRET";
    try std.testing.expect(sintykey_recovery_unwrap(&blob, blen, wrong, &out) != 0);
}
