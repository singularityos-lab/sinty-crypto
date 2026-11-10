const std = @import("std");

const P256 = std.crypto.ecc.P256;
const Aes256 = std.crypto.core.aes.Aes256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;

pub const Error = error{
    Io,
    Timeout,
    Cbor,
    TooLong,
    Device,
    NoCredential,
    Denied,
    PinRequired,
    PinInvalid,
    PinBlocked,
    NoHmacSecret,
    Excluded,
    Status,
};

extern fn getrandom(buf: [*]u8, n: usize, flags: c_uint) isize;
extern fn read(fd: c_int, buf: [*]u8, n: usize) isize;
extern fn write(fd: c_int, buf: [*]const u8, n: usize) isize;
extern fn poll(fds: [*]PollFd, n: c_ulong, timeout: c_int) c_int;
extern fn clock_gettime(clock: c_int, ts: *Timespec) c_int;

const PollFd = extern struct { fd: c_int, events: i16, revents: i16 };
const Timespec = extern struct { sec: i64, nsec: i64 };

pub fn fill(buf: []u8) Error!void {
    var off: usize = 0;
    while (off < buf.len) {
        const r = getrandom(buf[off..].ptr, buf.len - off, 0);
        if (r <= 0) return error.Io;
        off += @intCast(r);
    }
}

fn nowMs() i64 {
    var ts: Timespec = undefined;
    _ = clock_gettime(1, &ts);
    return ts.sec * 1000 + @divTrunc(ts.nsec, 1000000);
}

pub const Writer = struct {
    buf: []u8,
    n: usize = 0,
    over: bool = false,

    fn put(w: *Writer, b: []const u8) void {
        if (w.over or b.len > w.buf.len - w.n) {
            w.over = true;
            return;
        }
        @memcpy(w.buf[w.n..][0..b.len], b);
        w.n += b.len;
    }

    fn head(w: *Writer, major: u8, v: u64) void {
        const m: u8 = major << 5;
        if (v < 24) {
            w.put(&.{m | @as(u8, @intCast(v))});
        } else if (v <= 0xff) {
            w.put(&.{ m | 24, @intCast(v) });
        } else if (v <= 0xffff) {
            var b: [3]u8 = .{ m | 25, 0, 0 };
            std.mem.writeInt(u16, b[1..3], @intCast(v), .big);
            w.put(&b);
        } else if (v <= 0xffffffff) {
            var b: [5]u8 = .{ m | 26, 0, 0, 0, 0 };
            std.mem.writeInt(u32, b[1..5], @intCast(v), .big);
            w.put(&b);
        } else {
            var b: [9]u8 = undefined;
            b[0] = m | 27;
            std.mem.writeInt(u64, b[1..9], v, .big);
            w.put(&b);
        }
    }

    pub fn int(w: *Writer, v: i64) void {
        if (v >= 0) w.head(0, @intCast(v)) else w.head(1, @intCast(-1 - v));
    }
    pub fn bytes(w: *Writer, b: []const u8) void {
        w.head(2, b.len);
        w.put(b);
    }
    pub fn text(w: *Writer, s: []const u8) void {
        w.head(3, s.len);
        w.put(s);
    }
    pub fn array(w: *Writer, n: usize) void {
        w.head(4, n);
    }
    pub fn map(w: *Writer, n: usize) void {
        w.head(5, n);
    }
    pub fn boolean(w: *Writer, b: bool) void {
        w.put(&.{if (b) 0xf5 else 0xf4});
    }
    pub fn written(w: *const Writer) Error![]const u8 {
        if (w.over) return error.TooLong;
        return w.buf[0..w.n];
    }
};

pub const Key = union(enum) { int: i64, text: []const u8 };

pub const Reader = struct {
    d: []const u8,
    i: usize = 0,

    const Head = struct { major: u8, v: u64 };

    fn byte(r: *Reader) Error!u8 {
        if (r.i >= r.d.len) return error.Cbor;
        r.i += 1;
        return r.d[r.i - 1];
    }

    fn uint(r: *Reader, n: usize) Error!u64 {
        if (n > r.d.len - r.i) return error.Cbor;
        var v: u64 = 0;
        for (r.d[r.i..][0..n]) |x| v = (v << 8) | x;
        r.i += n;
        return v;
    }

    fn head(r: *Reader) Error!Head {
        const b = try r.byte();
        const info = b & 31;
        const v: u64 = switch (info) {
            0...23 => info,
            24 => try r.byte(),
            25 => try r.uint(2),
            26 => try r.uint(4),
            27 => try r.uint(8),
            else => return error.Cbor,
        };
        return .{ .major = b >> 5, .v = v };
    }

    fn span(r: *Reader, n: u64) Error![]const u8 {
        if (n > r.d.len - r.i) return error.Cbor;
        const s = r.d[r.i..][0..@intCast(n)];
        r.i += @intCast(n);
        return s;
    }

    pub fn skip(r: *Reader) Error!void {
        return r.skipDepth(0);
    }

    fn skipDepth(r: *Reader, depth: u8) Error!void {
        if (depth > 16) return error.Cbor;
        const h = try r.head();
        switch (h.major) {
            0, 1, 7 => {},
            2, 3 => _ = try r.span(h.v),
            4, 5 => {
                const items = if (h.major == 5) std.math.mul(u64, h.v, 2) catch return error.Cbor else h.v;
                if (items > r.d.len) return error.Cbor;
                var k: u64 = 0;
                while (k < items) : (k += 1) try r.skipDepth(depth + 1);
            },
            6 => try r.skipDepth(depth + 1),
            else => return error.Cbor,
        }
    }

    pub fn int(r: *Reader) Error!i64 {
        const h = try r.head();
        const v = std.math.cast(i64, h.v) orelse return error.Cbor;
        return switch (h.major) {
            0 => v,
            1 => -1 - v,
            else => error.Cbor,
        };
    }

    pub fn bytes(r: *Reader) Error![]const u8 {
        const h = try r.head();
        if (h.major != 2) return error.Cbor;
        return r.span(h.v);
    }

    pub fn text(r: *Reader) Error![]const u8 {
        const h = try r.head();
        if (h.major != 3) return error.Cbor;
        return r.span(h.v);
    }

    pub fn map(r: *Reader) Error!usize {
        const h = try r.head();
        if (h.major != 5 or h.v > r.d.len) return error.Cbor;
        return @intCast(h.v);
    }

    pub fn array(r: *Reader) Error!usize {
        const h = try r.head();
        if (h.major != 4 or h.v > r.d.len) return error.Cbor;
        return @intCast(h.v);
    }

    pub fn boolean(r: *Reader) Error!bool {
        return switch (try r.byte()) {
            0xf5 => true,
            0xf4 => false,
            else => error.Cbor,
        };
    }

    pub fn key(r: *Reader) Error!Key {
        if (r.i >= r.d.len) return error.Cbor;
        return switch (r.d[r.i] >> 5) {
            0, 1 => .{ .int = try r.int() },
            3 => .{ .text = try r.text() },
            else => error.Cbor,
        };
    }
};

fn isInt(k: Key, v: i64) bool {
    return k == .int and k.int == v;
}

fn isText(k: Key, s: []const u8) bool {
    return k == .text and std.mem.eql(u8, k.text, s);
}

pub const Transport = struct {
    ctx: *anyopaque,
    call: *const fn (ctx: *anyopaque, req: []const u8, out: []u8) Error![]u8,
};

const report = 64;
const hid_init = 0x86;
const hid_cbor = 0x90;
const hid_cancel = 0x91;
const hid_keepalive = 0xbb;
const hid_error = 0xbf;

pub const Hid = struct {
    fd: c_int,
    cid: u32 = 0xffffffff,
    timeout_ms: i64 = 30000,

    pub fn open(fd: c_int) Error!Hid {
        var h = Hid{ .fd = fd };
        var nonce: [8]u8 = undefined;
        try fill(&nonce);
        try h.send(hid_init, &nonce);
        const deadline = nowMs() + 2000;
        var buf: [256]u8 = undefined;
        while (true) {
            const left = deadline - nowMs();
            if (left <= 0) return error.Timeout;
            const m = try h.recv(left, &buf);
            if (m.cmd == hid_init and m.data.len >= 17 and std.mem.eql(u8, m.data[0..8], &nonce)) {
                h.cid = std.mem.readInt(u32, m.data[8..12], .big);
                return h;
            }
        }
    }

    pub fn transport(h: *Hid) Transport {
        return .{ .ctx = h, .call = callHid };
    }

    fn callHid(ctx: *anyopaque, req: []const u8, out: []u8) Error![]u8 {
        const h: *Hid = @ptrCast(@alignCast(ctx));
        return h.cbor(req, out);
    }

    fn writePacket(h: *Hid, pkt: *const [report + 1]u8) Error!void {
        const w = write(h.fd, pkt, pkt.len);
        if (w != pkt.len) return error.Io;
    }

    fn send(h: *Hid, cmd: u8, data: []const u8) Error!void {
        if (data.len > 7609) return error.TooLong;
        var pkt = std.mem.zeroes([report + 1]u8);
        std.mem.writeInt(u32, pkt[1..5], h.cid, .big);
        pkt[5] = cmd;
        std.mem.writeInt(u16, pkt[6..8], @intCast(data.len), .big);
        var n: usize = @min(data.len, report - 7);
        @memcpy(pkt[8..][0..n], data[0..n]);
        try h.writePacket(&pkt);
        var seq: u8 = 0;
        while (n < data.len) : (seq += 1) {
            pkt = std.mem.zeroes([report + 1]u8);
            std.mem.writeInt(u32, pkt[1..5], h.cid, .big);
            pkt[5] = seq;
            const m: usize = @min(data.len - n, report - 5);
            @memcpy(pkt[6..][0..m], data[n..][0..m]);
            n += m;
            try h.writePacket(&pkt);
        }
    }

    fn readPacket(h: *Hid, buf: *[report]u8, wait_ms: i64) Error!usize {
        const deadline = nowMs() + wait_ms;
        while (true) {
            const left = deadline - nowMs();
            if (left <= 0) return error.Timeout;
            var pfd = [_]PollFd{.{ .fd = h.fd, .events = 1, .revents = 0 }};
            const r = poll(&pfd, 1, @intCast(@min(left, std.math.maxInt(c_int))));
            if (r < 0) return error.Io;
            if (r == 0) return error.Timeout;
            const n = read(h.fd, buf, report);
            if (n <= 0) return error.Io;
            if (n >= 7 and std.mem.readInt(u32, buf[0..4], .big) == h.cid) return @intCast(n);
        }
    }

    const Message = struct { cmd: u8, data: []u8 };

    fn recv(h: *Hid, wait_ms: i64, out: []u8) Error!Message {
        var pkt: [report]u8 = undefined;
        var n = try h.readPacket(&pkt, wait_ms);
        const cmd = pkt[4];
        if (cmd & 0x80 == 0) return error.Device;
        const size: usize = std.mem.readInt(u16, pkt[5..7], .big);
        if (size > out.len) return error.TooLong;
        var got: usize = @min(size, n - 7);
        @memcpy(out[0..got], pkt[7..][0..got]);
        var seq: u8 = 0;
        while (got < size) : (seq += 1) {
            n = try h.readPacket(&pkt, wait_ms);
            if (pkt[4] != seq) return error.Device;
            const m: usize = @min(size - got, n - 5);
            @memcpy(out[got..][0..m], pkt[5..][0..m]);
            got += m;
        }
        return .{ .cmd = cmd, .data = out[0..size] };
    }

    pub fn cbor(h: *Hid, req: []const u8, out: []u8) Error![]u8 {
        try h.send(hid_cbor, req);
        const deadline = nowMs() + h.timeout_ms;
        while (true) {
            const left = deadline - nowMs();
            if (left <= 0) break;
            const m = h.recv(left, out) catch |e| {
                if (e == error.Timeout) h.send(hid_cancel, &.{}) catch {};
                return e;
            };
            switch (m.cmd) {
                hid_keepalive => continue,
                hid_error => return error.Device,
                hid_cbor => return m.data,
                else => continue,
            }
        }
        h.send(hid_cancel, &.{}) catch {};
        return error.Timeout;
    }
};

pub const Protocol = enum(u8) { one = 1, two = 2 };

pub const Shared = struct {
    hmac: [32]u8,
    aes: [32]u8,

    pub fn wipe(s: *Shared) void {
        std.crypto.secureZero(u8, &s.hmac);
        std.crypto.secureZero(u8, &s.aes);
    }
};

fn kdf(p: Protocol, z: [32]u8) Shared {
    var s: Shared = undefined;
    switch (p) {
        .one => {
            Sha256.hash(&z, &s.hmac, .{});
            s.aes = s.hmac;
        },
        .two => {
            const prk = Hkdf.extract(&([_]u8{0} ** 32), &z);
            Hkdf.expand(&s.hmac, "CTAP2 HMAC key", prk);
            Hkdf.expand(&s.aes, "CTAP2 AES key", prk);
        },
    }
    return s;
}

fn cbc(key: [32]u8, iv: [16]u8, in: []const u8, out: []u8, enc: bool) Error!void {
    if (in.len % 16 != 0 or out.len < in.len) return error.Cbor;
    var prev = iv;
    var i: usize = 0;
    if (enc) {
        const ctx = Aes256.initEnc(key);
        while (i < in.len) : (i += 16) {
            var blk: [16]u8 = undefined;
            for (0..16) |j| blk[j] = in[i + j] ^ prev[j];
            ctx.encrypt(out[i..][0..16], &blk);
            prev = out[i..][0..16].*;
        }
    } else {
        const ctx = Aes256.initDec(key);
        while (i < in.len) : (i += 16) {
            const ct = in[i..][0..16].*;
            var blk: [16]u8 = undefined;
            ctx.decrypt(&blk, &ct);
            for (0..16) |j| out[i + j] = blk[j] ^ prev[j];
            prev = ct;
        }
    }
}

pub fn encrypt(p: Protocol, s: *const Shared, plain: []const u8, out: []u8) Error![]u8 {
    switch (p) {
        .one => {
            try cbc(s.aes, [_]u8{0} ** 16, plain, out, true);
            return out[0..plain.len];
        },
        .two => {
            if (out.len < 16 + plain.len) return error.TooLong;
            var iv: [16]u8 = undefined;
            try fill(&iv);
            out[0..16].* = iv;
            try cbc(s.aes, iv, plain, out[16..], true);
            return out[0 .. 16 + plain.len];
        },
    }
}

pub fn decrypt(p: Protocol, s: *const Shared, data: []const u8, out: []u8) Error![]u8 {
    switch (p) {
        .one => {
            try cbc(s.aes, [_]u8{0} ** 16, data, out, false);
            return out[0..data.len];
        },
        .two => {
            if (data.len < 16) return error.Cbor;
            try cbc(s.aes, data[0..16].*, data[16..], out, false);
            return out[0 .. data.len - 16];
        },
    }
}

pub fn authenticate(p: Protocol, key: []const u8, msg: []const u8, out: *[32]u8) []const u8 {
    HmacSha256.create(out, msg, key);
    return if (p == .one) out[0..16] else out[0..32];
}

pub const Cose = struct { x: [32]u8, y: [32]u8 };

fn writeCose(w: *Writer, k: *const Cose) void {
    w.map(5);
    w.int(1);
    w.int(2);
    w.int(3);
    w.int(-25);
    w.int(-1);
    w.int(1);
    w.int(-2);
    w.bytes(&k.x);
    w.int(-3);
    w.bytes(&k.y);
}

fn readCose(r: *Reader) Error!Cose {
    var k: Cose = undefined;
    var have: u2 = 0;
    const n = try r.map();
    for (0..n) |_| {
        const key = try r.key();
        if (isInt(key, -2) or isInt(key, -3)) {
            const b = try r.bytes();
            if (b.len != 32) return error.Cbor;
            if (isInt(key, -2)) {
                k.x = b[0..32].*;
                have |= 1;
            } else {
                k.y = b[0..32].*;
                have |= 2;
            }
        } else try r.skip();
    }
    if (have != 3) return error.Cbor;
    return k;
}

pub fn agree(p: Protocol, peer: *const Cose, mine: *Cose) Error!Shared {
    const pt = P256.fromSerializedAffineCoordinates(peer.x, peer.y, .big) catch return error.Cbor;
    var seed: [48]u8 = undefined;
    try fill(&seed);
    defer std.crypto.secureZero(u8, &seed);
    var sk = P256.scalar.reduce48(seed, .big);
    defer std.crypto.secureZero(u8, &sk);
    const pub_pt = P256.basePoint.mul(sk, .big) catch return error.Cbor;
    const a = pub_pt.affineCoordinates();
    mine.x = a.x.toBytes(.big);
    mine.y = a.y.toBytes(.big);
    var z = (pt.mul(sk, .big) catch return error.Cbor).affineCoordinates().x.toBytes(.big);
    defer std.crypto.secureZero(u8, &z);
    return kdf(p, z);
}

fn statusError(s: u8) Error {
    return switch (s) {
        0x2e => error.NoCredential,
        0x27, 0x2f => error.Denied,
        0x19 => error.Excluded,
        0x36 => error.PinRequired,
        0x31 => error.PinInvalid,
        0x32, 0x34 => error.PinBlocked,
        else => error.Status,
    };
}

pub const Info = struct {
    hmac_secret: bool = false,
    client_pin: bool = false,
    token_permissions: bool = false,
    make_cred_uv_not_required: bool = false,
    protocol: Protocol = .one,
};

pub const AuthData = struct {
    cred_id: []const u8 = &.{},
    hmac_flag: ?bool = null,
    hmac_output: ?[]const u8 = null,
};

pub fn parseAuthData(ad: []const u8) Error!AuthData {
    if (ad.len < 37) return error.Cbor;
    const flags = ad[32];
    var out: AuthData = .{};
    var r = Reader{ .d = ad, .i = 37 };
    if (flags & 0x40 != 0) {
        if (ad.len - r.i < 18) return error.Cbor;
        const n: usize = std.mem.readInt(u16, ad[r.i + 16 ..][0..2], .big);
        r.i += 18;
        if (ad.len - r.i < n) return error.Cbor;
        out.cred_id = ad[r.i..][0..n];
        r.i += n;
        try r.skip();
    }
    if (flags & 0x80 != 0) {
        const n = try r.map();
        for (0..n) |_| {
            const key = try r.key();
            if (isText(key, "hmac-secret") and r.i < ad.len) {
                switch (ad[r.i]) {
                    0xf4, 0xf5 => out.hmac_flag = try r.boolean(),
                    else => out.hmac_output = try r.bytes(),
                }
            } else try r.skip();
        }
    }
    return out;
}

pub const Client = struct {
    t: Transport,
    info: ?Info = null,
    resp: [4096]u8 = undefined,

    fn call(c: *Client, cmd: u8, params: []const u8) Error![]const u8 {
        var req: [4096]u8 = undefined;
        if (params.len + 1 > req.len) return error.TooLong;
        req[0] = cmd;
        @memcpy(req[1..][0..params.len], params);
        const resp = try c.t.call(c.t.ctx, req[0 .. 1 + params.len], &c.resp);
        if (resp.len == 0) return error.Cbor;
        if (resp[0] != 0) return statusError(resp[0]);
        return resp[1..];
    }

    pub fn getInfo(c: *Client) Error!Info {
        if (c.info) |i| return i;
        var info: Info = .{};
        var r = Reader{ .d = try c.call(0x04, &.{}) };
        const n = try r.map();
        for (0..n) |_| {
            const key = try r.key();
            if (isInt(key, 2)) {
                const m = try r.array();
                for (0..m) |_| {
                    if (std.mem.eql(u8, try r.text(), "hmac-secret")) info.hmac_secret = true;
                }
            } else if (isInt(key, 4)) {
                const m = try r.map();
                for (0..m) |_| {
                    const name = try r.key();
                    if (name != .text or r.i >= r.d.len or (r.d[r.i] != 0xf4 and r.d[r.i] != 0xf5)) {
                        try r.skip();
                        continue;
                    }
                    const v = try r.boolean();
                    if (std.mem.eql(u8, name.text, "clientPin")) info.client_pin = v;
                    if (std.mem.eql(u8, name.text, "pinUvAuthToken")) info.token_permissions = v;
                    if (std.mem.eql(u8, name.text, "makeCredUvNotRqd")) info.make_cred_uv_not_required = v;
                }
            } else if (isInt(key, 6)) {
                const m = try r.array();
                for (0..m) |_| {
                    if (try r.int() == 2) info.protocol = .two;
                }
            } else try r.skip();
        }
        c.info = info;
        return info;
    }

    fn keyAgreement(c: *Client, p: Protocol, mine: *Cose) Error!Shared {
        var buf: [16]u8 = undefined;
        var w = Writer{ .buf = &buf };
        w.map(2);
        w.int(1);
        w.int(@intFromEnum(p));
        w.int(2);
        w.int(2);
        var r = Reader{ .d = try c.call(0x06, try w.written()) };
        const n = try r.map();
        var peer: ?Cose = null;
        for (0..n) |_| {
            const key = try r.key();
            if (isInt(key, 1)) peer = try readCose(&r) else try r.skip();
        }
        return agree(p, &(peer orelse return error.Cbor), mine);
    }

    fn token(c: *Client, p: Protocol, pin: []const u8, rp: []const u8, perms: i64, out: *[32]u8) Error![]u8 {
        const info = try c.getInfo();
        var mine: Cose = undefined;
        var s = try c.keyAgreement(p, &mine);
        defer s.wipe();
        var h: [32]u8 = undefined;
        Sha256.hash(pin, &h, .{});
        defer std.crypto.secureZero(u8, &h);
        var enc_buf: [48]u8 = undefined;
        const enc = try encrypt(p, &s, h[0..16], &enc_buf);
        var buf: [512]u8 = undefined;
        var w = Writer{ .buf = &buf };
        w.map(if (info.token_permissions) 6 else 4);
        w.int(1);
        w.int(@intFromEnum(p));
        w.int(2);
        w.int(if (info.token_permissions) 9 else 5);
        w.int(3);
        writeCose(&w, &mine);
        w.int(6);
        w.bytes(enc);
        if (info.token_permissions) {
            w.int(9);
            w.int(perms);
            w.int(10);
            w.text(rp);
        }
        var r = Reader{ .d = try c.call(0x06, try w.written()) };
        const n = try r.map();
        var tok_enc: ?[]const u8 = null;
        for (0..n) |_| {
            const key = try r.key();
            if (isInt(key, 2)) tok_enc = try r.bytes() else try r.skip();
        }
        const te = tok_enc orelse return error.Cbor;
        var plain: [64]u8 = undefined;
        if (te.len > plain.len + 16) return error.Cbor;
        const t = try decrypt(p, &s, te, &plain);
        defer std.crypto.secureZero(u8, &plain);
        if (t.len != 16 and t.len != 32) return error.Cbor;
        @memcpy(out[0..t.len], t);
        return out[0..t.len];
    }

    pub fn register(c: *Client, rp: []const u8, device_pin: ?[]const u8, exclude: []const []const u8, id_out: []u8) Error![]u8 {
        const info = try c.getInfo();
        if (!info.hmac_secret) return error.NoHmacSecret;
        var cdh: [32]u8 = undefined;
        try fill(&cdh);
        var user_id: [16]u8 = undefined;
        try fill(&user_id);
        var auth: ?[]const u8 = null;
        var auth_buf: [32]u8 = undefined;
        var tok_buf: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &tok_buf);
        const pin = device_pin orelse "";
        if (info.client_pin) {
            if (pin.len == 0 and !info.make_cred_uv_not_required) return error.PinRequired;
            if (pin.len > 0) {
                const tok = try c.token(info.protocol, pin, rp, 0x01, &tok_buf);
                auth = authenticate(info.protocol, tok, &cdh, &auth_buf);
            }
        }
        var buf: [4096]u8 = undefined;
        var w = Writer{ .buf = &buf };
        var entries: usize = 6;
        if (exclude.len > 0) entries += 1;
        if (auth != null) entries += 2;
        w.map(entries);
        w.int(1);
        w.bytes(&cdh);
        w.int(2);
        w.map(2);
        w.text("id");
        w.text(rp);
        w.text("name");
        w.text("Sinty");
        w.int(3);
        w.map(3);
        w.text("id");
        w.bytes(&user_id);
        w.text("name");
        w.text("Sinty");
        w.text("displayName");
        w.text("Sinty");
        w.int(4);
        w.array(1);
        w.map(2);
        w.text("alg");
        w.int(-7);
        w.text("type");
        w.text("public-key");
        if (exclude.len > 0) {
            w.int(5);
            w.array(exclude.len);
            for (exclude) |id| {
                w.map(2);
                w.text("id");
                w.bytes(id);
                w.text("type");
                w.text("public-key");
            }
        }
        w.int(6);
        w.map(1);
        w.text("hmac-secret");
        w.boolean(true);
        w.int(7);
        w.map(1);
        w.text("rk");
        w.boolean(false);
        if (auth) |a| {
            w.int(8);
            w.bytes(a);
            w.int(9);
            w.int(@intFromEnum(info.protocol));
        }
        var r = Reader{ .d = try c.call(0x01, try w.written()) };
        const n = try r.map();
        var ad: ?[]const u8 = null;
        for (0..n) |_| {
            const key = try r.key();
            if (isInt(key, 2)) ad = try r.bytes() else try r.skip();
        }
        const parsed = try parseAuthData(ad orelse return error.Cbor);
        if (parsed.cred_id.len == 0 or parsed.cred_id.len > id_out.len) return error.Cbor;
        if (parsed.hmac_flag != true) return error.NoHmacSecret;
        @memcpy(id_out[0..parsed.cred_id.len], parsed.cred_id);
        return id_out[0..parsed.cred_id.len];
    }

    pub fn secret(c: *Client, rp: []const u8, ids: []const []const u8, salt: *const [32]u8, out: *[32]u8) Error!usize {
        if (ids.len == 0) return error.NoCredential;
        const info = try c.getInfo();
        if (!info.hmac_secret) return error.NoHmacSecret;
        const p = info.protocol;
        var mine: Cose = undefined;
        var s = try c.keyAgreement(p, &mine);
        defer s.wipe();
        var salt_buf: [48]u8 = undefined;
        const salt_enc = try encrypt(p, &s, salt, &salt_buf);
        var auth_buf: [32]u8 = undefined;
        const salt_auth = authenticate(p, &s.hmac, salt_enc, &auth_buf);
        var cdh: [32]u8 = undefined;
        try fill(&cdh);
        var buf: [4096]u8 = undefined;
        var w = Writer{ .buf = &buf };
        w.map(5);
        w.int(1);
        w.text(rp);
        w.int(2);
        w.bytes(&cdh);
        w.int(3);
        w.array(ids.len);
        for (ids) |id| {
            w.map(2);
            w.text("id");
            w.bytes(id);
            w.text("type");
            w.text("public-key");
        }
        w.int(4);
        w.map(1);
        w.text("hmac-secret");
        w.map(if (p == .one) 3 else 4);
        w.int(1);
        writeCose(&w, &mine);
        w.int(2);
        w.bytes(salt_enc);
        w.int(3);
        w.bytes(salt_auth);
        if (p != .one) {
            w.int(4);
            w.int(@intFromEnum(p));
        }
        w.int(5);
        w.map(1);
        w.text("up");
        w.boolean(true);
        var r = Reader{ .d = try c.call(0x02, try w.written()) };
        const n = try r.map();
        var ad: ?[]const u8 = null;
        var used: ?[]const u8 = null;
        for (0..n) |_| {
            const key = try r.key();
            if (isInt(key, 1)) {
                const m = try r.map();
                for (0..m) |_| {
                    const k = try r.key();
                    if (isText(k, "id")) used = try r.bytes() else try r.skip();
                }
            } else if (isInt(key, 2)) ad = try r.bytes() else try r.skip();
        }
        const parsed = try parseAuthData(ad orelse return error.Cbor);
        const enc = parsed.hmac_output orelse return error.NoHmacSecret;
        var plain: [96]u8 = undefined;
        defer std.crypto.secureZero(u8, &plain);
        if (enc.len > plain.len + 16) return error.Cbor;
        const dec = try decrypt(p, &s, enc, &plain);
        if (dec.len < 32) return error.Cbor;
        out.* = dec[0..32].*;
        const which = used orelse (if (ids.len == 1) ids[0] else return error.Cbor);
        for (ids, 0..) |id, i| {
            if (std.mem.eql(u8, id, which)) return i;
        }
        return error.NoCredential;
    }
};

pub fn isAuthenticator(descriptor: []const u8) bool {
    return std.mem.indexOf(u8, descriptor, &.{ 0x06, 0xd0, 0xf1 }) != null;
}

test "cbor round trip of canonical heads" {
    var buf: [64]u8 = undefined;
    var w = Writer{ .buf = &buf };
    w.map(3);
    w.int(1);
    w.int(-25);
    w.int(500);
    w.bytes("abc");
    w.text("up");
    w.boolean(true);
    const out = try w.written();
    try std.testing.expectEqualSlices(u8, &.{ 0xa3, 0x01, 0x38, 0x18, 0x19, 0x01, 0xf4, 0x43, 'a', 'b', 'c', 0x62, 'u', 'p', 0xf5 }, out);
    var r = Reader{ .d = out };
    try std.testing.expectEqual(@as(usize, 3), try r.map());
    try std.testing.expectEqual(@as(i64, 1), try r.int());
    try std.testing.expectEqual(@as(i64, -25), try r.int());
    try std.testing.expectEqual(@as(i64, 500), try r.int());
    try std.testing.expectEqualStrings("abc", try r.bytes());
    try std.testing.expect(isText(try r.key(), "up"));
    try std.testing.expect(try r.boolean());
}

test "cbor refuses truncated and oversized input" {
    var r = Reader{ .d = &.{ 0x5a, 0xff, 0xff, 0xff, 0xff, 0x00 } };
    try std.testing.expectError(error.Cbor, r.bytes());
    var deep: [40]u8 = undefined;
    @memset(&deep, 0x81);
    var r2 = Reader{ .d = &deep };
    try std.testing.expectError(error.Cbor, r2.skip());
    var w = Writer{ .buf = deep[0..2] };
    w.bytes("abc");
    try std.testing.expectError(error.TooLong, w.written());
}

test "cbc matches the AES-256 test vector" {
    const key = [_]u8{ 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
    const iv = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const plain = [_]u8{ 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 };
    const want = [_]u8{ 0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6, 0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d };
    var out: [32]u8 = undefined;
    try cbc(key, iv, &plain, &out, true);
    try std.testing.expectEqualSlices(u8, &want, &out);
    var back: [32]u8 = undefined;
    try cbc(key, iv, &out, &back, false);
    try std.testing.expectEqualSlices(u8, &plain, &back);
}

test "both sides of the key agreement share a secret" {
    var a_seed: [48]u8 = undefined;
    try fill(&a_seed);
    const a_sk = P256.scalar.reduce48(a_seed, .big);
    const a_pub = (try P256.basePoint.mul(a_sk, .big)).affineCoordinates();
    const peer = Cose{ .x = a_pub.x.toBytes(.big), .y = a_pub.y.toBytes(.big) };
    for ([_]Protocol{ .one, .two }) |p| {
        var mine: Cose = undefined;
        const s = try agree(p, &peer, &mine);
        const b = try P256.fromSerializedAffineCoordinates(mine.x, mine.y, .big);
        const z = (try b.mul(a_sk, .big)).affineCoordinates().x.toBytes(.big);
        const other = kdf(p, z);
        try std.testing.expectEqualSlices(u8, &s.hmac, &other.hmac);
        try std.testing.expectEqualSlices(u8, &s.aes, &other.aes);
        var enc_buf: [64]u8 = undefined;
        const enc = try encrypt(p, &s, &([_]u8{9} ** 32), &enc_buf);
        var dec_buf: [64]u8 = undefined;
        try std.testing.expectEqualSlices(u8, &([_]u8{9} ** 32), try decrypt(p, &other, enc, &dec_buf));
    }
}

test "authenticator data with a credential and extensions" {
    var ad: [128]u8 = undefined;
    @memset(ad[0..37], 0);
    ad[32] = 0xc1;
    var i: usize = 37;
    @memset(ad[i..][0..16], 0xaa);
    i += 16;
    std.mem.writeInt(u16, ad[i..][0..2], 4, .big);
    i += 2;
    @memcpy(ad[i..][0..4], "cred");
    i += 4;
    var w = Writer{ .buf = ad[i..] };
    w.map(1);
    w.int(1);
    w.int(2);
    w.map(1);
    w.text("hmac-secret");
    w.boolean(true);
    const parsed = try parseAuthData(ad[0 .. i + w.n]);
    try std.testing.expectEqualStrings("cred", parsed.cred_id);
    try std.testing.expectEqual(@as(?bool, true), parsed.hmac_flag);
    try std.testing.expect(isAuthenticator(&.{ 0x05, 0x01, 0x06, 0xd0, 0xf1, 0x09 }));
    try std.testing.expect(!isAuthenticator(&.{ 0x05, 0x01, 0x09, 0x06 }));
}
