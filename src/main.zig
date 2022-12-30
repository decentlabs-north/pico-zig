const std = @import("std");
const crypto = std.crypto; // @import("crypto.zig");
const Sign = crypto.sign.Ed25519;
const testing = std.testing;
const log = std.log.scoped(.pico);
const hex = std.fmt.fmtSliceHexLower;
// pub const log_level: std.log.Level = .info;

pub const Feed = struct {
    pub const SecretKey = Sign.SecretKey;
    pub const PublicKey = Sign.PublicKey;
    pub const KEY_GLYPH = "K0.";
    pub const PK_LEN = PublicKey.encoded_length;
    pub const SK_LEN = SecretKey.encoded_length;

    buf: []u8,
    keychain: std.ArrayList(usize),
    cache: std.ArrayList([]Block),
    tail: usize = 0,

    pub fn append(self: *Feed, data: []const u8, sk: SecretKey) void {
        log.debug("Kek {*} {*} {*}", .{ self, data, sk });
    }

    pub fn wrap(alc: std.mem.Allocator, data: []u8) anyerror!Feed {
        var f = Feed{ .buf = data, .keychain = std.ArrayList(usize).init(alc), .cache = std.ArrayList([]Block).init(alc) };
        f.tail = data.len;
        try f.index();
        return f;
    }

    pub fn deinit(self: *Feed) void {
        self.keychain.deinit();
        self.cache.deinit();
    }
    fn _keyAt(self: *Feed, idx: usize) []u8 {
        const o = self.keychain.items[idx];
        return self.buf[o..(o + PK_LEN)];
    }

    // TODO: rename to fromBinary?
    fn index(self: *Feed) anyerror!void {
        log.debug("Indexing", .{});
        var offset: usize = 0;
        // var blockIdx = 0;
        while (true) {
            if (offset >= self.tail) break;
            if (offset + KEY_GLYPH.len > self.buf.len) break;
            const isKey = std.mem.eql(u8, KEY_GLYPH, self.buf[offset..(offset + KEY_GLYPH.len)]);
            log.debug("isKey: {}", .{isKey});
            if (isKey) {
                const start = offset + KEY_GLYPH.len;
                const end = start + PK_LEN;
                if (end > self.buf.len) @panic("InvalidKey");
                const key_bytes = self.buf[start..end];
                var found = false;
                for (self.keychain.items) |o| {
                    if (found) break;
                    found = std.mem.eql(u8, key_bytes, self.buf[o .. o + PK_LEN]);
                }
                log.debug("Key: {} {s}", .{ found, hex(key_bytes) });
                if (!found) {
                    try self.keychain.append(start);
                }
                // yield { type: 0, id: keyIdx, key: key, offset };
                offset += end;
            } else {
                const block = Block{ .buffer = self.buf[offset..] };
                log.debug("Block s:{} {s}", .{ block.size(), block.body() });
                const err = block.verify(self._keyAt(0));
                log.debug("isValid {!}", .{err});
                const b = @ptrCast(*Block, self.buf.ptr + offset);
                offset += block.total_size();
            }
        }
    }
};

pub fn signPair() Sign.KeyPair {
    return try Sign.KeyPair.create(undefined);
}

fn parse16(chr: u8) u8 {
    return switch (chr) {
        48...59 => chr - 48,
        'a' => 10,
        'b' => 11,
        'c' => 12,
        'd' => 13,
        'e' => 14,
        'f' => 15,
        else => 0,
    };
}
const BlockDecodeError = error {
    InvalidLength
};
const Block = struct {
    //// -----
    pub const SIG_LEN = Sign.Signature.encoded_length;
    pub const COUNT_TYPE = u32;
    pub const COUNT_LEN = @divExact(@typeInfo(COUNT_TYPE).Int.bits, 8);

    buffer: []u8,

    pub fn sig(self: *const Block) []u8 {
        return self.buffer[0..SIG_LEN];
    }
    pub fn parentSig(self: *const Block) [SIG_LEN]u8 {
        return self.buffer[SIG_LEN..(SIG_LEN * 2)];
    }

    /// Size of block Body
    pub fn size(self: *const Block) usize {
        const o = SIG_LEN * 2;
        const s = COUNT_LEN;
        return std.mem.readIntBig(u32, self.buffer[o .. o + s]);
    }

    /// The data that is covered by the signature
    pub fn data(self: *const Block) []u8 {
        const o = SIG_LEN;
        const end = (SIG_LEN * 2) + COUNT_LEN + self.size();
        return self.buffer[o..end];
    }

    /// Userspace block-body
    pub fn body(self: *const Block) []u8 {
        const o = SIG_LEN * 2 + COUNT_LEN;
        return self.buffer[o .. o + self.size()];
    }

    pub fn total_size(self: *const Block) usize {
        return SIG_LEN * 2 + COUNT_LEN + self.size();
    }

    pub fn verify(self: *const Block, public_key: []u8) !void {
        const message = self.data();
        const pk = try Sign.PublicKey.fromBytes(public_key[0..32].*);
        const sig_bytes = self.buffer[0..SIG_LEN]; //self.sig();
        const signature = Sign.Signature.fromBytes(sig_bytes.*);
        try signature.verify(message, pk);
    }
};

test "basic add functionality" {
    testing.log_level = .debug;
    try testing.expect(true);
    // try testing.expect(add(3, 7) == 10);
    // const f = Feed.create(allocator, size? = 65535);
    // f.append(txt, kp);
    const txt = "4b302e7f90d21dec34410f4c026541a324a989332aab65161cd8b341d72fb5adb552e1c7bd26c2bcd45ce2d307e4af42b5a310c867f58e424824533963c07d2eb15ee87f0b922a8487f1b5a24b652cf7918de8b7d8a265d3b7ff20d34233398a3ef801000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001d416c6c20796f7572206261736520697320616c6c206f75722062617365";
    // log.debug("K: {s}", .{txt});

    // parseHex can be done at comptime
    var binFeed: [txt.len >> 1]u8 = undefined;
    var prev: u8 = ' ';
    for (txt) |chr, i| {
        if (i % 2 != 0) {
            binFeed[i >> 1] = (parse16(prev) << 4) + parse16(chr);
        } else {
            prev = chr;
        }
    }
    log.debug("K: {s}", .{hex(&binFeed)});

    // test index
    const test_allocator = testing.allocator;
    var f = try Feed.wrap(test_allocator, &binFeed);
    defer f.deinit();
    log.debug("f {}", .{@TypeOf(f)});
}

// SK '653e9ae8f5ede09442895291afac3f587310a6ba6209d5b350d9c85b7b074f1d7f90d21dec34410f4c026541a324a989332aab65161cd8b341d72fb5adb552e1'
// Pickle: 'PIC0.K0.f5DSHew0QQ9MAmVBoySpiTMqq2UWHNizQdcvta21UuEB0.x70mwrzUXOLTB-SvQrWjEMhn9Y5CSCRTOWPAfS6xXuh_C5IqhIfxtaJLZSz3kY3ot9iiZdO3_yDTQjM5ij74AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdQWxsIHlvdXIgYmFzZSBpcyBhbGwgb3VyIGJhc2U'
// BinHex: 4b302e7f90d21dec34410f4c026541a324a989332aab65161cd8b341d72fb5adb552e1c7bd26c2bcd45ce2d307e4af42b5a310c867f58e424824533963c07d2eb15ee87f0b922a8487f1b5a24b652cf7918de8b7d8a265d3b7ff20d34233398a3ef801000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001d416c6c20796f7572206261736520697320616c6c206f75722062617365
