const testing = std.testing;
const std = @import("std");
const ArrayList = std.ArrayList;
const U = @import("util.zig");
const Pickle = @import("pickle.zig");
const Sign = U.Sign;
const log = U.log;
const hex = U.hex;
pub const Block = @import("block.zig").Block;
const Header = @import("block.zig").Header;
// pub const log_level: std.log.Level = .info;

// Export keypair generation to WASM
pub inline fn signPair() Sign.KeyPair {
    return try Sign.KeyPair.create(undefined);
}

pub const Feed = struct {
    const Self = @This();
    pub const KEY_GLYPH = U.key_glyph;
    pub const SecretKey = Sign.SecretKey;
    pub const PublicKey = Sign.PublicKey;
    pub const PK_LEN = PublicKey.encoded_length;
    pub const SK_LEN = SecretKey.encoded_length;

    keychain: ArrayList([PK_LEN]u8),
    cache: ArrayList(Block),
    buffer: union(enum) { ro: []const u8, rw: ArrayList(u8) },

    inline fn items(self: *Self) []const u8 {
        switch (self.buffer) {
            .rw => |v| return v.items,
            .ro => |v| return v,
        }
    }
    inline fn writable(self: *Self) ArrayList(u8) {
        switch (self.buffer) {
            .rw => |v| return v,
            .ro => unreachable,
        }
    }

    fn keyAt(self: *Self, idx: usize) ![PK_LEN]u8 {
        var iter = self.iterator();
        var n: usize = 0;
        while (iter.next()) |segment| {
            switch (segment) {
                .key => |k| {
                    if (n == idx) return k[0..PK_LEN];
                    n += 1;
                },
                else => {},
            }
        }
        return error.InvalidIndex;
    }

    pub fn block_at(self: *Self, idx: usize) !Block {
        var iter = self.iterator();
        var n: usize = 0;
        while (iter.next()) |segment| {
            switch (segment) {
                .block => |b| {
                    if (n == idx) return b;
                    n += 1;
                },
                else => {},
            }
        }
        return error.InvalidIndex;
    }

    pub fn append(self: *Self, data: []const u8, secret_key: [SK_LEN]u8) !void {
        // TODO: self.ensureKey(sk[32..])
        const block_size = data.len + U.size.header;
        var memory = self.writable();
        const tail = memory.items.len;
        // TODO: self._last_block = tail

        const new_size = tail + block_size;
        if (new_size > U.block_limit) return error.FeedOverflow;
        try memory.resize(new_size);
        var buffer = memory.items[tail..][0..block_size];
        var header = @ptrCast(*Header, buffer.ptr);
        const psig = [_]u8{0} ** 64; // TODO: lookup prev || genesis
        std.mem.copy(u8, &header.parent_signature, &psig);
        header.writeSize(@truncate(u32, data.len));
        std.mem.copy(u8, buffer[U.size.header..], data);

        const sign_data = buffer[U.size.sig..];
        const kp = try Sign.KeyPair.fromSecretKey(try Sign.SecretKey.fromBytes(secret_key));
        const signature = try kp.sign(sign_data, undefined);
        const sig = signature.toBytes();
        log.debug("SigGen: L:{}, Hex: {s}", .{ sig.len, hex(&sig) });
        std.mem.copy(u8, &header.signature, &sig);
        const block = try Block.from(buffer);
        try block.verify(secret_key[32..]);
        log.debug("Block s: {s}", .{block.body});
    }

    /// Attach to an existing buffer in readonly mode
    pub fn wrap(alc: std.mem.Allocator, data: []const u8) !Feed {
        var f = Feed{
            .buffer = .{ .ro = data },
            .keychain = ArrayList([32]u8).init(alc),
            .cache = ArrayList(Block).init(alc),
        };
        try f.index();
        return f;
    }

    /// Creates new writable Feed
    pub fn create(alc: std.mem.Allocator) !Feed {
        return Feed{
            .buffer = .{ .rw = ArrayList(u8).init(alc) },
            .keychain = ArrayList([32]u8).init(alc),
            .cache = ArrayList(Block).init(alc),
        };
    }

    pub fn deinit(self: *Self) void {
        switch (self.buffer) {
            .rw => |list| list.deinit(),
            .ro => {},
        }
        self.keychain.deinit();
        self.cache.deinit();
    }

    pub fn iterator(self: *Self) FeedIterator {
        return .{ .data = self.items(), .offset = 0 };
    }

    pub fn length(self: *Self) usize {
        var iter = self.iterator();
        var l: usize = 0;
        while (iter.next()) |segment| {
            switch (segment) {
                .block => |_| l += 1,
                else => {},
            }
        }
        return l;
    }

    fn index(self: *Self) !void {
        log.debug("Indexing, tail: {}", .{self.items().len});
        // var blockIdx = 0;
        var iter = self.iterator();
        while (iter.next()) |segment| {
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
                    const b: Block = block;
                    // try block.verify(&self.keyAt(0));
                    // try self.cache.append(block);
                    U.log.debug("Indexing block {s}", .{b.body});
                },
            }
        }
    }
};

const FeedSegment = union(enum) {
    key: []const u8,
    block: Block,
};
const FeedIterator = struct {
    data: []const u8,
    offset: usize,
    pub fn next(self: *FeedIterator) ?FeedSegment {
        return self.nextErr() catch null;
    }
    pub fn nextErr(self: *FeedIterator) !?FeedSegment {
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
            return .{ .key = self.data[start..][0..32] };
        } else {
            const start = self.offset;
            // Block.from handles size validations.
            const block = try Block.from(self.data[start..]);
            self.offset += block.bytes.len;
            return .{ .block = block };
        }
    }
};

test "Writable feed" {
    testing.log_level = .debug;
    const test_allocator = testing.allocator;
    const pair = try Sign.KeyPair.create(undefined);
    const sk = pair.secret_key.bytes;

    // Init writable feed
    var feed = try Feed.create(test_allocator);
    defer feed.deinit();

    // try testing.expect(feed.length == 0);

    // Merge remote feed into empty writable
    // try feed.merge(otherFeed);
    // try testing.expect(feed.length == 3);

    // Append to remote blocks
    try feed.append(@as([]const u8, "Hello"), sk);
    try feed.append(@as([]const u8, "World"), sk);
    const l: usize = feed.length();
    try testing.expectEqual(l, 5);

    // Print contents of each block
    var iter = feed.iterator();
    while (iter.next()) |segment| {
        switch (segment) {
            .block => |v| log.debug("Block contents: {s}", .{v.body}),
            .key => |v| log.debug("Key contents: {s}", .{v}),
        }
    }
}

test "readonly Feed from Pickle" {
    testing.log_level = .debug;
    const pickle = "PIC0.K0.f5DSHew0QQ9MAmVBoySpiTMqq2UWHNizQdcvta21UuEB0.x70mwrzUXOLTB-SvQrWjEMhn9Y5CSCRTOWPAfS6xXuh_C5IqhIfxtaJLZSz3kY3ot9iiZdO3_yDTQjM5ij74AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdQWxsIHlvdXIgYmFzZSBpcyBhbGwgb3VyIGJhc2U";
    const arr = try Pickle.decode_pickle(testing.allocator, pickle);
    defer arr.deinit();

    var f = try Feed.wrap(testing.allocator, arr.items);
    defer f.deinit();
    try f.index();
    const b: Block = try f.block_at(0);
    try testing.expectEqualStrings(b.body, "All your base is all our base");
}

// SK '653e9ae8f5ede09442895291afac3f587310a6ba6209d5b350d9c85b7b074f1d7f90d21dec34410f4c026541a324a989332aab65161cd8b341d72fb5adb552e1'
// Pickle: 'PIC0.K0.f5DSHew0QQ9MAmVBoySpiTMqq2UWHNizQdcvta21UuEB0.x70mwrzUXOLTB-SvQrWjEMhn9Y5CSCRTOWPAfS6xXuh_C5IqhIfxtaJLZSz3kY3ot9iiZdO3_yDTQjM5ij74AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdQWxsIHlvdXIgYmFzZSBpcyBhbGwgb3VyIGJhc2U'
// BinHex: 4b302e7f90d21dec34410f4c026541a324a989332aab65161cd8b341d72fb5adb552e1c7bd26c2bcd45ce2d307e4af42b5a310c867f58e424824533963c07d2eb15ee87f0b922a8487f1b5a24b652cf7918de8b7d8a265d3b7ff20d34233398a3ef801000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001d416c6c20796f7572206261736520697320616c6c206f75722062617365
