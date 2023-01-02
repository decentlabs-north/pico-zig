const testing = std.testing;
const std = @import("std");
const ArrayList = std.ArrayList;
const U = @import("util.zig");
const Pickle = @import("pickle.zig");
const Sign = U.Sign;
const log = U.log;
const hex = U.hex;
pub const Block = @import("block.zig").Block;
// pub const log_level: std.log.Level = .info;

/// Mimic JS-API, returns std.crypto.sign.Ed25519 keypair
/// for convenience.
pub fn signPair() Sign.KeyPair {
    return try Sign.KeyPair.create(undefined);
}

pub const Variant = enum { readable, static, writable };

pub const Feed = struct {
    const Self = @This();
    pub const KEY_GLYPH = U.key_glyph;
    pub const SecretKey = Sign.SecretKey;
    pub const PublicKey = Sign.PublicKey;
    pub const PK_LEN = PublicKey.encoded_length;
    pub const SK_LEN = SecretKey.encoded_length;

    buf: []u8,
    keychain: ArrayList([PK_LEN]u8),
    cache: ArrayList(Block),
    tail: usize = 0,

    buffer: union(Variant) {
        /// Read-only feed
        readable: []u8,
        /// Fixed capacity buffer with known tail
        static: []u8,
        /// Backed by private array list with growing capacity.
        writable: ArrayList(u8),
    },

    fn keyAt(self: *Self, idx: usize) [PK_LEN]u8 {
        var iter = self.iterator();
        var n = 0;
        while (iter.next()) |segment| {
            switch (segment) {
                .key => |k| {
                    if (n == idx) return k;
                    n += 1;
                },
            }
        }
    }

    pub fn get(self: *Self, idx: usize) Block {
        var iter = self.iterator();
        var n = 0;
        while (iter.next()) |segment| {
            switch (segment) {
                .block => |b| {
                    if (n == idx) return b;
                    n += 1;
                },
            }
        }
    }

    pub fn append(self: *Self, data: []const u8, sk: [SK_LEN]u8) !void {
        const block_size = data.len + Block.HEADER_LENGTH;
        log.debug("BS S:{} s{}", .{ self.buf.len, self.tail + block_size });
        if (self.buf.len < self.tail + block_size) {
            return error.OutOfMemory;
        }
        const l = @truncate(u32, data.len);
        log.debug("BATMUT: {} => {}", .{ data.len, l });
        std.mem.writeIntBig(
            u32,
            self.buf[self.tail + 2 * U.size.sig ..][0..4],
            l,
        );
        var block = try Block.from(self.buf[self.tail..]);
        log.debug("Block s:{} {s}", .{ block.size, block.body });
        // std.mem.copy(u8, d
        log.debug("Kek {s}", .{hex(&sk)});
    }

    /// Attach and read an existing binary feed buffer
    pub fn wrap(alc: std.mem.Allocator, data: []u8) !Feed {
        var f = Feed{
            .buf = data,
            .keychain = ArrayList([32]u8).init(alc),
            .cache = ArrayList(Block).init(alc),
            .tail = data.len, // Don't like this
        };
        try f.index();
        return f;
    }

    pub fn create(alc: std.mem.Allocator, cap: ?usize) !Feed {
        return Feed{
            .buffer = .{ .writable = try ArrayList(u8).initCapacity(alc, cap orelse 1024) },
            .keychain = ArrayList([32]u8).init(alc),
            .cache = ArrayList(Block).init(alc),
            .tail = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        self.keychain.deinit();
        self.cache.deinit();
    }

    pub fn iterator(self: *Self) FeedIterator {
        return .{ .data = self.buf[0..self.tail], .offset = 0 };
    }

    // TODO: rename to fromBinary?
    fn index(self: *Self) !void {
        log.debug("Indexing, tail: {}", .{self.tail});
        // var blockIdx = 0;
        var iter = self.iterator();
        while (try iter.next()) |segment| {
            switch (segment) {
                .key => |public_key| {
                    var found = false;
                    for (self.keychain.items) |other| {
                        if (found) break;
                        found = std.mem.eql(u8, public_key, &other);
                    }
                    // log.debug("Key: {} {s}", .{ found, hex(public_key) });
                    if (!found) {
                        try self.keychain.append(public_key[0..PK_LEN].*);
                    }
                },
                .block => |block| {
                    try block.verify(self.keyAt(0));
                    try self.cache.append(block);
                },
            }
        }
    }
};

const SegmentType = enum { key, block };
const FeedSegment = union(SegmentType) { key: []u8, block: Block };
const FeedIterator = struct {
    data: []u8,
    offset: usize,
    pub fn next(self: *FeedIterator) !?FeedSegment {
        const key_glyph = U.key_glyph;
        if (self.offset >= self.data.len) return null;
        if (self.offset + key_glyph.len > self.data.len) return null;
        const isKey = std.mem.eql(u8, key_glyph, self.data[self.offset..][0..key_glyph.len]);
        // TODO: prevent key-less feeds? if (!isKey and 0 == self.keychain.items.len) ;
        if (isKey) {
            const start = self.offset + key_glyph.len;
            const end = start + U.size.pk;
            if (end > self.data.len) return error.InvalidLength;
            self.offset += end;
            return .{ .key = self.data[start..end] };
        } else {
            const start = self.offset;
            // Block.from handles size validations.
            const block = try Block.from(self.data[start..]);
            self.offset += block.block_size;
            return .{ .block = block };
        }
    }
};

test "Writable feed" {
    testing.log_level = .debug;
    const test_allocator = testing.allocator;

    const pair = try Sign.KeyPair.create(undefined);
    const sk = pair.secret_key.bytes;

    var f = try Feed.create(test_allocator, undefined);
    defer f.deinit();
    try f.append(@as([]const u8, "Hello Gentlemen"), sk);
    try testing.expect(true);
}

test "readonly Feed from Pickle" {
    testing.log_level = .debug;
    const pickle = "PIC0.K0.f5DSHew0QQ9MAmVBoySpiTMqq2UWHNizQdcvta21UuEB0.x70mwrzUXOLTB-SvQrWjEMhn9Y5CSCRTOWPAfS6xXuh_C5IqhIfxtaJLZSz3kY3ot9iiZdO3_yDTQjM5ij74AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdQWxsIHlvdXIgYmFzZSBpcyBhbGwgb3VyIGJhc2U";
    const arr = try Pickle.decode_pickle(testing.allocator, pickle);
    defer arr.deinit();
    var f = try Feed.wrap(testing.allocator, arr.items);
    defer f.deinit();
    try f.index();
    const b: Block = f.get(0);
    try testing.expectEqualStrings(b.body, "All your base is all our base");
}

// SK '653e9ae8f5ede09442895291afac3f587310a6ba6209d5b350d9c85b7b074f1d7f90d21dec34410f4c026541a324a989332aab65161cd8b341d72fb5adb552e1'
// Pickle: 'PIC0.K0.f5DSHew0QQ9MAmVBoySpiTMqq2UWHNizQdcvta21UuEB0.x70mwrzUXOLTB-SvQrWjEMhn9Y5CSCRTOWPAfS6xXuh_C5IqhIfxtaJLZSz3kY3ot9iiZdO3_yDTQjM5ij74AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdQWxsIHlvdXIgYmFzZSBpcyBhbGwgb3VyIGJhc2U'
// BinHex: 4b302e7f90d21dec34410f4c026541a324a989332aab65161cd8b341d72fb5adb552e1c7bd26c2bcd45ce2d307e4af42b5a310c867f58e424824533963c07d2eb15ee87f0b922a8487f1b5a24b652cf7918de8b7d8a265d3b7ff20d34233398a3ef801000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001d416c6c20796f7572206261736520697320616c6c206f75722062617365
