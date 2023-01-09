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
        const parent = self.lastBlock();
        var psig: [U.size.sig]u8 = genesis_signature;
        if (parent != null) {
            psig = parent.?.header.signature;
        }
        const pk = secret_key[PK_LEN..];
        try self.ensureKey(pk.*);
        const block_size = data.len + U.size.header;
        const memory = &self.buffer.rw;
        const tail = memory.items.len;
        // TODO: self._last_block = tail (if we reimplement iterator-cache)
        const new_size = tail + block_size;
        if (new_size > U.size.max_block) return error.FeedOverflow;
        try memory.resize(new_size);

        var buffer = memory.items[tail..][0..block_size];
        var header = @ptrCast(*Header, buffer.ptr);

        std.mem.copy(u8, &header.parent_signature, &psig);

        header.writeSize(@truncate(u32, data.len));
        std.mem.copy(u8, buffer[U.size.header..], data);

        const sign_data = buffer[U.size.sig..];
        const sig: [64]u8 = try U.sign(sign_data, secret_key, undefined);
        std.mem.copy(u8, &header.signature, &sig);
        const block = try Block.from(buffer);
        block.verify(secret_key[32..].*) catch |err| {
            log.err("Created block failed sigcheck! {!}", .{err});
            return err;
        };
    }

    /// Attach to an readonly buffer without verifying signatures.
    /// Use Feed.from(allocator, data) to decode feeds from untrusted sources.
    /// Additional bytes/whitespace in `data` are ignored with a warning.
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

    /// Decodes a string that starts with `PIC0`
    /// heads up, this method returns a writable feed
    /// that you have to deinit() yourself.
    /// TODO: Refactor into template Feed(T: .read|.read_write) for comp visibilty
    pub fn unpickle(allocator: std.mem.Allocator, pickle: []const u8) !Feed {
        const list = try Pickle.decode_pickle(allocator, pickle);
        errdefer list.deinit(); // Dealloc if validation fails/ no memory was returned
        const feed = Feed{ .buffer = .{ .rw = list } };
        try feed.validate(allocator);
        return feed;
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
                    } else { // Compare signatures
                        const eql = std.mem.eql(u8, &parent.header.signature, &b.header.parent_signature);
                        if (!eql) {
                            log.err("\nERROR! InvalidParent\nexpected:\t{s}\ninstead\t{s}\n", .{
                                hex(&parent.header.signature),
                                hex(&b.header.parent_signature),
                            });
                            return error.InvalidParent;
                        }
                    }
                    parent = block;
                    var i: usize = 0;
                    var verified = false;
                    while (!verified and i < keychain.items.len) : (i += 1) {
                        block.verify(keychain.items[i].*) catch |err| {
                            if (err != error.SignatureVerificationFailed) return err;
                            continue;
                        };
                        verified = true;
                    }
                },
            }
        }
    }

    pub fn hasGenesis(self: *const Self) bool {
        const block = self.firstBlock() orelse return false;
        return std.mem.eql(u8, &block.header.parent_signature, &genesis_signature);
    }

    // Summarizes feed providing quick overview
    pub fn format(
        self: *const Feed,
        comptime _: []const u8, // fmt
        _: std.fmt.FormatOptions, // fmtOpts
        writer: anytype,
    ) !void {
        var mf = Macrofilm{};
        try mf.magnify(writer, self);
    }

    pub fn inspect(self: *const Feed) void {
        log.debug("{}", .{self});
    }
};

/// **Macrofilm (tm)** \('>')/
/// The only medium capable of capturing and magnifying pico-blocks.
///  ___
/// |._.|
/// :[_]:
/// |._.|
/// :[_]:
/// |._.|
/// :___:
///
const Macrofilm = struct {
    const Self = @This();
    const bufPrint = std.fmt.bufPrint;
    const wall0 = "| |";
    const wall1 = "|¤|";
    buffer: [80]u8 = undefined,
    state: u8 = 0,
    pub fn startE(self: *Self, writer: anytype, comptime fmt: []const u8, v: anytype) !void {
        try writer.print(fmt, v);
        self.state += 1;
    }
    pub fn magnify(self: *Self, writer: anytype, f: *const Feed) !void {
        var iter = f.iterator();
        var n_blocks: usize = 0;
        var n_keys: usize = 0;
        while (iter.next()) |seg| {
            switch (seg) {
                .block => n_blocks += 1,
                .key => n_keys += 1,
            }
        }
        const feed_size = f.items().len;
        const feed_type: u8 = if (f.hasGenesis()) 'G' else 'P';
        try writer.print("\n. .{s}. .\n", .{"_" ** 32});
        const feed_header = try bufPrint(&self.buffer, "PiC0FEED {c} K{d:0>2} B{d:0>2} {s}", .{ feed_type, n_keys, n_blocks, std.fmt.fmtIntSizeBin(feed_size) });
        try self.line(writer, feed_header);
        try self.line(writer, "_" ** 32);
        iter = f.iterator();
        n_keys = 0; // Reuse as key-index
        while (iter.nextKey()) |key| : (n_keys += 1) {
            const key_line = try bufPrint(&self.buffer, "KEY{d: >2}: {s}...{s}", .{ n_keys, hex(key[0..8]), hex(key[29..]) });
            try self.line(writer, key_line);
        }
        try self.line(writer, "_" ** 32);
        iter = f.iterator();
        n_blocks = 0; // Reuse as block-index
        while (iter.nextBlock()) |block| : (n_blocks += 1) {
            const block_header = try bufPrint(&self.buffer, "BLOCK{d: >2}" ++ "{s: >25}", .{
                n_blocks,
                std.fmt.fmtIntSizeBin(block.body.len),
            });
            try self.line(writer, block_header);
            const chain = try bufPrint(&self.buffer, "{s}  <=  {s}", .{
                hex(block.header.parent_signature[0..6]),
                hex(block.header.signature[0..6]),
            });
            try self.line(writer, chain);
            try self.hr(writer);
            var offset: usize = 0;
            const n_bytes = 8;
            const max_lines = 12 * n_bytes;
            while (offset < block.body.len and offset < max_lines) : (offset += n_bytes) {
                const ws = @min(block.body.len - offset, n_bytes);
                const line_bytes = block.body[offset..][0..ws];
                var i: usize = 0;
                var line_buffer: [32]u8 = undefined;
                while (i < line_buffer.len) : (i += 1) line_buffer[i] = 0; // clear line
                i = 0;
                while (i < ws) : (i += 1) { // print one 1 byte + 1space
                    _ = try bufPrint(line_buffer[i * 3 ..], "{x:0>2} ", .{line_bytes[i]});
                }
                const hex_chars = line_buffer[0 .. ws * 3];
                const hex_dump = try bufPrint(&self.buffer, "{s: <24}{s: <8}", .{ hex_chars, line_bytes });
                try self.line(writer, hex_dump);
            }
            try self.line(writer, "_" ** 32);
        }
        try writer.print(". ." ++ (" " ** 32) ++ ". .\n", .{});
    }
    pub fn hr(self: *Self, w: anytype) !void {
        try self.line(w, "." ** 32);
    }

    pub fn line(self: *Self, writer: anytype, value: []const u8) !void {
        const wall = if (self.state == 0) wall0 else wall1;
        try writer.print("{s}{s: ^32}{0s}\n", .{ wall, value });
        self.state = (self.state + 1) % 2;
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
        const chunk = self.nextErr() catch |err| {
            log.debug("Warning! FeedIterator stopped prematurely: {!}", .{err});
            return null;
        };
        return chunk;
    }

    pub fn nextErr(self: *FeedIterator) !?FeedSegment {
        const key_glyph = U.key_glyph;
        if (self.offset >= self.data.len) return null;
        if (self.offset + key_glyph.len > self.data.len) return null;
        const is_key = std.mem.eql(u8, key_glyph, self.data[self.offset..][0..key_glyph.len]);
        // TODO: prevent key-less feeds? if (!isKey and 0 == self.keychain.items.len);
        if (is_key) {
            const start = self.offset + key_glyph.len;
            const end = start + U.size.pk;
            if (end > self.data.len) return error.InvalidLength;
            self.offset += key_glyph.len + U.size.pk;
            return .{ .key = self.data[start..][0..U.size.pk].* };
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
    try feed.validate(testing.allocator);
    // feed.inspect();
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
    // f.inspect();
}

test "multi author feed" {
    testing.log_level = .debug;
    const test_allocator = testing.allocator;
    var pair = try Sign.KeyPair.create(undefined);
    const a_sk = pair.secret_key.bytes;
    pair = try Sign.KeyPair.create(undefined);
    const b_sk = pair.secret_key.bytes;
    try testing.expect(!std.mem.eql(u8, &a_sk, &b_sk));

    // Init writable feed
    var feed = try Feed.create(test_allocator);
    defer feed.deinit();
    try feed.append("Hello Bob", a_sk);
    try feed.append("Alice, sup!", b_sk);
    try feed.append("All good", a_sk);
    try feed.append("Very good!", b_sk);
    try feed.validate(testing.allocator);
    try testing.expectEqual(@as(usize, 4), feed.length());
}

// Found a bug.
test "Quickload feed.unpickle()" {
    testing.log_level = .debug;
    // var f = try Feed.unpickle(testing.allocator, "PIC0.K0.4fBbJtXDXdApELB2kM9qbryCLlZETa1533F5sxup42UB0.eLGtEIiQ15g-haNjGcZgy0aryxIRP3NwY7feFsyG8XYQNU4VQFc4lrqQWBEDVGFYH1NKpjwLmouwlsnb9wPVDgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwPEFsaWNlPlRha2Ugb2ZmIGV2ZXJ5IHppZyEKRGlkJ3lhIGhlYXIgdGhlIG5ld3M_K0.cBTeJ2otiOWSuFCmeC-NuVFo76FU1uEBlhhggUc_WI4B0.CjSIoFMwcS_bnQs7jkKJLQ80Urj1xsCq3KTBiYn7dZtZQilNtYI6gYeXusomSBqswWYrzKcClFqJZg0mTbi_DnixrRCIkNeYPoWjYxnGYMtGq8sSET9zcGO33hbMhvF2EDVOFUBXOJa6kFgRA1RhWB9TSqY8C5qLsJbJ2_cD1Q4AAAAKPEJvYj5OZXdzPwB0.xcP0pQlgp20zkPPZGHmztBTTO_wKJY2ORjf2WmoFet60ge5BLBmLdHN-8O8kyueFq2A9Yr9FPFY9CVcVyX5VDQo0iKBTMHEv250LO45CiS0PNFK49cbAqtykwYmJ+3WbWUIpTbWCOoGHl7rKJkgarMFmK8ynApRaiWYNJk24vw4AAAAhPEFsaWNlPlBpY28qIHdpbGwgcnVuIG9uIEVTUDMyISEhB0.jl4AXA9j6aAk_VENsgO204gy5oVdg0sc0EA8n20dH-IGuNZipAtgxFyIkUFgfie9FccewXm7aSOLUABqS4eYBsXD9KUJYKdtM5Dz2Rh5s7QU0zv8CiWNjkY39lpqBXretIHuQSwZi3RzfvDvJMrnhatgPWK_RTxWPQlXFcl+VQ0AAAAsPEJvYj4gIkh5cGVyIE1vZGVtNTYgVHVyYm8gSUkiIGZvciByZWFsPz8gOk8B0.pvLkfMRzyZflLlP3nTsrZRa5yLNLPxAZf1Z_lqlrKGsX_aL4rKmheEu09W3qfIDlkR5x99b_Y1I_DLGowXx4DI5eAFwPY-mgJP1RDbIDttOIMuaFXYNLHNBAPJ9tHR_iBrjWYqQLYMRciJFBYH4nvRXHHsF5u2kji1AAakuHmAYAAAAQPEFsaWNlPiBZZXMhIDonKQ");
    var f = try Feed.unpickle(testing.allocator, "PIC0.K0.4fBbJtXDXdApELB2kM9qbryCLlZETa1533F5sxup42UB0.eLGtEIiQ15g-haNjGcZgy0aryxIRP3NwY7feFsyG8XYQNU4VQFc4lrqQWBEDVGFYH1NKpjwLmouwlsnb9wPVDgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwPEFsaWNlPlRha2Ugb2ZmIGV2ZXJ5IHppZyEKRGlkJ3lhIGhlYXIgdGhlIG5ld3M_K0.cBTeJ2otiOWSuFCmeC-NuVFo76FU1uEBlhhggUc_WI4B0.CjSIoFMwcS_bnQs7jkKJLQ80Urj1xsCq3KTBiYn7dZtZQilNtYI6gYeXusomSBqswWYrzKcClFqJZg0mTbi_DnixrRCIkNeYPoWjYxnGYMtGq8sSET9zcGO33hbMhvF2EDVOFUBXOJa6kFgRA1RhWB9TSqY8C5qLsJbJ2_cD1Q4AAAAKPEJvYj5OZXdzPwB0.xcP0pQlgp20zkPPZGHmztBTTO_wKJY2ORjf2WmoFet60ge5BLBmLdHN-8O8kyueFq2A9Yr9FPFY9CVcVyX5VDQo0iKBTMHEv250LO45CiS0PNFK49cbAqtykwYmJ-3WbWUIpTbWCOoGHl7rKJkgarMFmK8ynApRaiWYNJk24vw4AAAAhPEFsaWNlPlBpY28qIHdpbGwgcnVuIG9uIEVTUDMyISEhB0.jl4AXA9j6aAk_VENsgO204gy5oVdg0sc0EA8n20dH-IGuNZipAtgxFyIkUFgfie9FccewXm7aSOLUABqS4eYBsXD9KUJYKdtM5Dz2Rh5s7QU0zv8CiWNjkY39lpqBXretIHuQSwZi3RzfvDvJMrnhatgPWK_RTxWPQlXFcl-VQ0AAAAsPEJvYj4gIkh5cGVyIE1vZGVtNTYgVHVyYm8gSUkiIGZvciByZWFsPz8gOk8B0.pvLkfMRzyZflLlP3nTsrZRa5yLNLPxAZf1Z_lqlrKGsX_aL4rKmheEu09W3qfIDlkR5x99b_Y1I_DLGowXx4DI5eAFwPY-mgJP1RDbIDttOIMuaFXYNLHNBAPJ9tHR_iBrjWYqQLYMRciJFBYH4nvRXHHsF5u2kji1AAakuHmAYAAAAQPEFsaWNlPiBZZXMhIDonKQ");
    defer f.deinit();
    // f.inspect();
}
