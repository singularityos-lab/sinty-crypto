const std = @import("std");
pub const fido2 = @import("fido2");

const XChaCha = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;

pub const max_keys = 8;
pub const rp = "sinty";
const magic = "SKF1";

extern fn open(path: [*:0]const u8, flags: c_int, mode: c_uint) c_int;
extern fn read(fd: c_int, buf: [*]u8, n: usize) isize;
extern fn close(fd: c_int) c_int;
extern fn fcntl(fd: c_int, cmd: c_int, ...) c_int;

pub const Entry = struct {
    id: [255]u8 = undefined,
    id_len: u8 = 0,
    name: [64]u8 = undefined,
    name_len: u8 = 0,
    nonce: [XChaCha.nonce_length]u8 = undefined,
    wrapped: [32]u8 = undefined,
    tag: [XChaCha.tag_length]u8 = undefined,

    pub fn credential(e: *const Entry) []const u8 {
        return e.id[0..e.id_len];
    }

    pub fn label(e: *const Entry) []const u8 {
        return e.name[0..e.name_len];
    }
};

pub const Store = struct {
    salt: [32]u8 = undefined,
    count: usize = 0,
    entries: [max_keys]Entry = undefined,

    pub fn parse(data: []const u8) ?Store {
        var s: Store = .{};
        if (data.len < magic.len + 33 or !std.mem.eql(u8, data[0..magic.len], magic)) return null;
        var i: usize = magic.len;
        s.salt = data[i..][0..32].*;
        i += 32;
        s.count = data[i];
        i += 1;
        if (s.count == 0 or s.count > max_keys) return null;
        for (s.entries[0..s.count]) |*e| {
            if (data.len - i < 1) return null;
            e.id_len = data[i];
            i += 1;
            if (e.id_len == 0 or data.len - i < e.id_len + 1) return null;
            @memcpy(e.id[0..e.id_len], data[i..][0..e.id_len]);
            i += e.id_len;
            const nl = data[i];
            i += 1;
            if (nl > e.name.len or data.len - i < nl + e.nonce.len + e.wrapped.len + e.tag.len) return null;
            e.name_len = nl;
            @memcpy(e.name[0..nl], data[i..][0..nl]);
            i += nl;
            e.nonce = data[i..][0..e.nonce.len].*;
            i += e.nonce.len;
            e.wrapped = data[i..][0..32].*;
            i += 32;
            e.tag = data[i..][0..e.tag.len].*;
            i += e.tag.len;
        }
        if (i != data.len) return null;
        return s;
    }

    pub fn serialize(s: *const Store, out: []u8) ?[]u8 {
        var i: usize = 0;
        const put = struct {
            fn f(o: []u8, at: *usize, b: []const u8) bool {
                if (o.len - at.* < b.len) return false;
                @memcpy(o[at.*..][0..b.len], b);
                at.* += b.len;
                return true;
            }
        }.f;
        if (!put(out, &i, magic) or !put(out, &i, &s.salt) or !put(out, &i, &.{@intCast(s.count)})) return null;
        for (s.entries[0..s.count]) |*e| {
            if (!put(out, &i, &.{e.id_len}) or !put(out, &i, e.credential()) or
                !put(out, &i, &.{e.name_len}) or !put(out, &i, e.label()) or
                !put(out, &i, &e.nonce) or !put(out, &i, &e.wrapped) or !put(out, &i, &e.tag)) return null;
        }
        return out[0..i];
    }

    pub fn ids(s: *const Store, buf: *[max_keys][]const u8) []const []const u8 {
        for (s.entries[0..s.count], 0..) |*e, i| buf[i] = e.credential();
        return buf[0..s.count];
    }

    pub fn remove(s: *Store, index: usize) void {
        var i = index;
        while (i + 1 < s.count) : (i += 1) s.entries[i] = s.entries[i + 1];
        s.count -= 1;
        std.crypto.secureZero(u8, std.mem.asBytes(&s.entries[s.count]));
    }
};

fn wrapKey(uid: []const u8, out: *const [32]u8) [32]u8 {
    const prk = Hkdf.extract("sinty security key", out);
    var k: [32]u8 = undefined;
    Hkdf.expand(&k, uid, prk);
    return k;
}

pub fn wrap(uid: []const u8, out: *const [32]u8, factor: *const [32]u8, e: *Entry) fido2.Error!void {
    var k = wrapKey(uid, out);
    defer std.crypto.secureZero(u8, &k);
    try fido2.fill(&e.nonce);
    XChaCha.encrypt(&e.wrapped, &e.tag, factor, e.credential(), e.nonce, k);
}

pub fn unwrap(uid: []const u8, out: *const [32]u8, e: *const Entry, factor: *[32]u8) bool {
    var k = wrapKey(uid, out);
    defer std.crypto.secureZero(u8, &k);
    XChaCha.decrypt(factor, &e.wrapped, e.tag, e.credential(), e.nonce, k) catch return false;
    return true;
}

pub fn mix(factor: *const [32]u8, pin: []const u8, out: *[32]u8) []const u8 {
    var mac: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &mac);
    HmacSha256.create(&mac, pin, factor);
    const hex = "0123456789abcdef";
    for (mac[0..16], 0..) |b, i| {
        out[2 * i] = hex[b >> 4];
        out[2 * i + 1] = hex[b & 15];
    }
    return out[0..32];
}

pub const Failure = enum {
    absent,
    untouched,
    unknown,
    pin_required,
    pin_invalid,
    pin_blocked,
    unsupported,
    excluded,
    full,
    failed,

    pub fn message(f: Failure) []const u8 {
        return switch (f) {
            .absent => "security-key-absent",
            .untouched => "security-key-untouched",
            .unknown => "security-key-unknown",
            .pin_required => "security-key-pin-required",
            .pin_invalid => "security-key-pin-invalid",
            .pin_blocked => "security-key-pin-blocked",
            .unsupported => "security-key-unsupported",
            .excluded => "security-key-exists",
            .full => "security-key-full",
            .failed => "security-key-failed",
        };
    }
};

fn failureOf(e: fido2.Error) Failure {
    return switch (e) {
        error.Timeout, error.Denied => .untouched,
        error.NoCredential => .unknown,
        error.PinRequired => .pin_required,
        error.PinInvalid => .pin_invalid,
        error.PinBlocked => .pin_blocked,
        error.NoHmacSecret => .unsupported,
        error.Excluded => .excluded,
        else => .failed,
    };
}

pub const Devices = struct {
    fds: [8]c_int = undefined,
    n: usize = 0,
    owned: bool = true,

    pub fn find(test_fd: i32) Devices {
        var d: Devices = .{};
        if (test_fd >= 0) {
            d.owned = false;
            var fd = test_fd;
            while (d.n < d.fds.len and fcntl(fd, 1) >= 0) : (fd += 1) {
                d.fds[d.n] = fd;
                d.n += 1;
            }
            return d;
        }
        var idx: usize = 0;
        while (idx < 64 and d.n < d.fds.len) : (idx += 1) {
            var pb: [96]u8 = undefined;
            const desc = std.fmt.bufPrintZ(&pb, "/sys/class/hidraw/hidraw{d}/device/report_descriptor", .{idx}) catch continue;
            const fd = open(desc.ptr, 0o2000000, 0);
            if (fd < 0) continue;
            var buf: [4096]u8 = undefined;
            const n = read(fd, &buf, buf.len);
            _ = close(fd);
            if (n <= 0 or !fido2.isAuthenticator(buf[0..@intCast(n)])) continue;
            var db: [32]u8 = undefined;
            const dev = std.fmt.bufPrintZ(&db, "/dev/hidraw{d}", .{idx}) catch continue;
            const dfd = open(dev.ptr, 0o2 | 0o2000000, 0);
            if (dfd >= 0) {
                d.fds[d.n] = dfd;
                d.n += 1;
            }
        }
        return d;
    }

    pub fn deinit(d: *Devices) void {
        if (!d.owned) return;
        for (d.fds[0..d.n]) |fd| _ = close(fd);
        d.n = 0;
    }
};

pub fn unlock(store: *const Store, uid: []const u8, test_fd: i32, factor: *[32]u8) ?Failure {
    var devs = Devices.find(test_fd);
    defer devs.deinit();
    if (devs.n == 0) return .absent;
    var ids_buf: [max_keys][]const u8 = undefined;
    const ids = store.ids(&ids_buf);
    var last: Failure = .unknown;
    for (devs.fds[0..devs.n]) |fd| {
        var h = fido2.Hid.open(fd) catch |e| {
            last = failureOf(e);
            continue;
        };
        var c = fido2.Client{ .t = h.transport() };
        var out: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &out);
        const which = c.secret(rp, ids, &store.salt, &out) catch |e| {
            last = failureOf(e);
            continue;
        };
        if (unwrap(uid, &out, &store.entries[which], factor)) return null;
        last = .failed;
    }
    return last;
}

pub fn enroll(store: *Store, uid: []const u8, test_fd: i32, factor: *const [32]u8, name: []const u8, device_pin: ?[]const u8) ?Failure {
    if (store.count >= max_keys) return .full;
    var devs = Devices.find(test_fd);
    defer devs.deinit();
    if (devs.n == 0) return .absent;
    var ids_buf: [max_keys][]const u8 = undefined;
    const ids = store.ids(&ids_buf);
    var last: Failure = .absent;
    for (devs.fds[0..devs.n]) |fd| {
        var h = fido2.Hid.open(fd) catch |e| {
            last = failureOf(e);
            continue;
        };
        var c = fido2.Client{ .t = h.transport() };
        var id_buf: [1024]u8 = undefined;
        const id = c.register(rp, device_pin, ids, &id_buf) catch |e| {
            last = failureOf(e);
            continue;
        };
        if (id.len > 255) {
            last = .unsupported;
            continue;
        }
        var e = &store.entries[store.count];
        e.* = .{};
        e.id_len = @intCast(id.len);
        @memcpy(e.id[0..id.len], id);
        const nl = @min(name.len, e.name.len);
        e.name_len = @intCast(nl);
        @memcpy(e.name[0..nl], name[0..nl]);
        var out: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &out);
        const one = [_][]const u8{e.credential()};
        _ = c.secret(rp, &one, &store.salt, &out) catch |err| {
            last = failureOf(err);
            continue;
        };
        wrap(uid, &out, factor, e) catch {
            last = .failed;
            continue;
        };
        store.count += 1;
        return null;
    }
    return last;
}

test "store round trip and removal" {
    var s: Store = .{};
    @memset(&s.salt, 3);
    const factor = [_]u8{5} ** 32;
    for (0..3) |i| {
        var e = &s.entries[i];
        e.* = .{};
        e.id_len = @intCast(10 + i);
        @memset(e.id[0..e.id_len], @intCast(i));
        e.name_len = 3;
        @memcpy(e.name[0..3], "abc");
        const out = [_]u8{@intCast(i)} ** 32;
        try wrap("1000", &out, &factor, e);
    }
    s.count = 3;
    var buf: [4096]u8 = undefined;
    const data = s.serialize(&buf).?;
    var back = Store.parse(data).?;
    try std.testing.expectEqual(@as(usize, 3), back.count);
    var f: [32]u8 = undefined;
    try std.testing.expect(unwrap("1000", &([_]u8{1} ** 32), &back.entries[1], &f));
    try std.testing.expectEqualSlices(u8, &factor, &f);
    try std.testing.expect(!unwrap("1001", &([_]u8{1} ** 32), &back.entries[1], &f));
    try std.testing.expect(!unwrap("1000", &([_]u8{2} ** 32), &back.entries[1], &f));
    back.remove(0);
    try std.testing.expectEqual(@as(usize, 2), back.count);
    try std.testing.expectEqual(@as(u8, 11), back.entries[0].id_len);
    try std.testing.expect(Store.parse(data[0 .. data.len - 1]) == null);
    var bad = buf;
    bad[0] = 'X';
    try std.testing.expect(Store.parse(bad[0..data.len]) == null);
}

test "the secret depends on factor and pin" {
    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    const f1 = [_]u8{1} ** 32;
    const f2 = [_]u8{2} ** 32;
    const s1 = mix(&f1, "1234", &a);
    try std.testing.expectEqual(@as(usize, 32), s1.len);
    try std.testing.expect(!std.mem.eql(u8, s1, mix(&f2, "1234", &b)));
    try std.testing.expect(!std.mem.eql(u8, mix(&f1, "1234", &a), mix(&f1, "1235", &b)));
    try std.testing.expectEqualSlices(u8, mix(&f1, "1234", &a), mix(&f1, "1234", &b));
}
