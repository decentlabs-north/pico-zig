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
pub const genesis_signature = [_]u8{0} ** U.size.sig;
pub const Feed = struct {
    const Self = @This();
    pub const KEY_GLYPH = U.key_glyph;
    pub const PK_LEN = U.size.pk;
    pub const SK_LEN = U.size.sk;
    buffer: union(enum) { ro: []const u8, rw: ArrayList(u8) },

    inline fn items(self: *const Self) []const u8 {
        switch (self.buffer) {
            .rw => |v| return v.items,
            .ro => |v| return v,
        }
    }

    pub fn blockAt(self: *const Self, idx: usize) !Block {
        var iter = self.iterator();
        var n: usize = 0;
        while (iter.nextBlock()) |b| {
            if (n == idx) return b;
            n += 1;
        }
        return error.InvalidIndex;
    }

    pub fn firstBlock(self: *const Self) ?Block {
        var iter = self.iterator();
        return iter.nextBlock();
    }

    pub fn lastBlock(self: *const Self) ?Block {
        var block: Block = undefined;
        var iter = self.iterator();
        var n: usize = 0;
        while (iter.nextBlock()) |b| : (n += 1) block = b;
        if (n == 0) return null;
        return block;
    }

    pub fn ensureKey(self: *Self, public_key: [PK_LEN]u8) !void {
        // Check if key already exists
        var iter = self.iterator();
        while (iter.nextKey()) |key| {
            const same = std.mem.eql(u8, &public_key, &key);
            if (same) return; // Key exists
        }
        // Key not found. append it.
        // TODO: throw comptime error
        const buffer = &self.buffer.rw;
        const tail = buffer.items.len;
        try buffer.resize(tail + PK_LEN + KEY_GLYPH.len);
        std.mem.copy(u8, buffer.items[tail..], KEY_GLYPH);
        std.mem.copy(u8, buffer.items[tail + KEY_GLYPH.len ..], &public_key);
    }

    pub fn append(self: *Self, data: []const u8, secret_key: [SK_LEN]u8) !void {
        const pk = secret_key[PK_LEN..];
        try self.ensureKey(pk.*);
        const block_size = data.len + U.size.header;
        const memory = &self.buffer.rw;
        const tail = memory.items.len;
        // TODO: self._last_block = tail (if we reimplement cache)

        const new_size = tail + block_size;
        if (new_size > U.block_limit) return error.FeedOverflow;
        try memory.resize(new_size);

        var buffer = memory.items[tail..][0..block_size];
        var header = @ptrCast(*Header, buffer.ptr);

        const parent = self.lastBlock();
        if (parent == null) {
            std.mem.copy(u8, &header.parent_signature, &genesis_signature);
        } else {
            const parent_header = parent.?.header;
            std.mem.copy(u8, &header.parent_signature, &parent_header.signature);
        }

        header.writeSize(@truncate(u32, data.len));
        std.mem.copy(u8, buffer[U.size.header..], data);

        const sign_data = buffer[U.size.sig..];
        const sig: [64]u8 = try U.sign(sign_data, secret_key, undefined);
        std.mem.copy(u8, &header.signature, &sig);
        const block = try Block.from(buffer);
        try block.verify(secret_key[32..].*);
    }

    /// Attach to an readonly buffer
    /// without verifying signatures.
    /// Use Feed.from(allocator, data) to
    /// decode feeds from untrusted sources.
    /// `data` must not contain any additional bytes/whitespace.
    pub fn wrap(data: []const u8) Feed {
        const f = Feed{
            .buffer = .{ .ro = data },
        };
        return f;
    }

    // Attach feed to an readonly buffer,
    // and validate it verifying singatures & integrity.
    pub fn from(allocator: std.mem.Allocator, data: []const u8) !Feed {
        const f = Feed.wrap(data);
        try f.validate(allocator);
        return f;
    }

    /// Creates new writable Feed
    pub fn create(alc: std.mem.Allocator) !Feed {
        return Feed{
            .buffer = .{ .rw = ArrayList(u8).init(alc) },
        };
    }

    // Only required for writable Feeds
    // that were created via Feed.create()
    // this function is a no-op for readonly Feeds
    pub fn deinit(self: *Self) void {
        switch (self.buffer) {
            .rw => |list| list.deinit(),
            .ro => {},
        }
    }

    pub fn iterator(self: *const Self) FeedIterator {
        return .{ .data = self.items(), .offset = 0 };
    }

    pub fn length(self: *const Self) usize {
        var iter = self.iterator();
        var l: usize = 0;
        while (iter.nextBlock()) |_| l += 1;
        return l;
    }

    fn validate(self: *const Self, allocator: std.mem.Allocator) !void {
        var keychain = ArrayList(*const [32]u8).init(allocator);
        defer keychain.deinit();
        var parent: Block = undefined;
        var is_first: bool = true;
        var iter = self.iterator();
        while (iter.next()) |segment| {
            switch (segment) {
                .key => |public_key| {
                    var found = false;
                    for (keychain.items) |other| {
                        if (found) break;
                        found = std.mem.eql(u8, &public_key, other);
                    }
                    if (!found) try keychain.append(public_key[0..PK_LEN]);
                },
                .block => |block| {
                    const b: Block = block;
                    if (is_first) {
                        is_first = false;
                    } else { // Commpare signatures
                        const eql = std.mem.eql(u8, &parent.header.signature, &b.header.parent_signature);
                        if (!eql) return error.InvalidParent;
                    }
                    parent = block;
                    try block.verify(keychain.items[0].*);
                },
            }
        }
    }

    pub fn hasGenesis(self: *const Self) bool {
        const block = self.firstBlock() orelse return false;
        return std.mem.eql(u8, &block.header.parent_signature, &genesis_signature);
    }
};

const FeedSegment = union(enum) {
    key: [U.size.pk]u8,
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
            return .{ .key = self.data[start..][0..32].* };
        } else {
            const start = self.offset;
            // Block.from handles size validations.
            const block = try Block.from(self.data[start..]);
            self.offset += block.bytes.len;
            return .{ .block = block };
        }
    }
    /// Scan to next block, skipping over keys.
    pub fn nextBlock(self: *FeedIterator) ?Block {
        while (self.next()) |segment| {
            switch (segment) {
                .block => |b| return b,
                .key => {},
            }
        }
        return null;
    }

    // Scan to next key, skipping over blocks.
    pub fn nextKey(self: *FeedIterator) ?[32]u8 {
        while (self.next()) |segment| {
            switch (segment) {
                .block => {},
                .key => |k| return k,
            }
        }
        return null;
    }
};

const expectEqual = testing.expectEqual;
test "Writable feed" {
    testing.log_level = .debug;
    const test_allocator = testing.allocator;
    const pair = try Sign.KeyPair.create(undefined);
    const sk = pair.secret_key.bytes;

    // Init writable feed
    var feed = try Feed.create(test_allocator);
    defer feed.deinit();
    try expectEqual(false, feed.hasGenesis());
    try expectEqual(@as(usize, 0), feed.length());
    // Append
    try feed.append(@as([]const u8, "Hello"), sk);
    try feed.append(@as([]const u8, "World"), sk);
    try expectEqual(@as(usize, 2), feed.length());
    try expectEqual(true, feed.hasGenesis());

    // Print contents of each block
    var iter = feed.iterator();
    while (iter.next()) |segment| {
        switch (segment) {
            .block => |v| log.debug("Block contents: {s}", .{v.body}),
            .key => |v| log.debug("Pub Key: {} {s}", .{ v.len, hex(&v) }),
        }
    }
    try feed.validate(testing.allocator);
}

test "readonly Feed from Pickle" {
    testing.log_level = .debug;
    const pickle = "PIC0.K0.f5DSHew0QQ9MAmVBoySpiTMqq2UWHNizQdcvta21UuEB0.x70mwrzUXOLTB-SvQrWjEMhn9Y5CSCRTOWPAfS6xXuh_C5IqhIfxtaJLZSz3kY3ot9iiZdO3_yDTQjM5ij74AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdQWxsIHlvdXIgYmFzZSBpcyBhbGwgb3VyIGJhc2U";
    const arr = try Pickle.decode_pickle(testing.allocator, pickle);
    defer arr.deinit();

    var f = try Feed.from(testing.allocator, arr.items);
    defer f.deinit();
    try f.validate(testing.allocator);
    const b: Block = try f.blockAt(0);
    try testing.expectEqualStrings(b.body, "All your base is all our base");
}

// SK '653e9ae8f5ede09442895291afac3f587310a6ba6209d5b350d9c85b7b074f1d7f90d21dec34410f4c026541a324a989332aab65161cd8b341d72fb5adb552e1'
// Pickle: 'PIC0.K0.f5DSHew0QQ9MAmVBoySpiTMqq2UWHNizQdcvta21UuEB0.x70mwrzUXOLTB-SvQrWjEMhn9Y5CSCRTOWPAfS6xXuh_C5IqhIfxtaJLZSz3kY3ot9iiZdO3_yDTQjM5ij74AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdQWxsIHlvdXIgYmFzZSBpcyBhbGwgb3VyIGJhc2U'
// BinHex: 4b302e7f90d21dec34410f4c026541a324a989332aab65161cd8b341d72fb5adb552e1c7bd26c2bcd45ce2d307e4af42b5a310c867f58e424824533963c07d2eb15ee87f0b922a8487f1b5a24b652cf7918de8b7d8a265d3b7ff20d34233398a3ef801000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001d416c6c20796f7572206261736520697320616c6c206f75722062617365
