/// "Pickling" was intended to encode a binary feed for
/// ultra-portability.
/// Enable sharing a Feed easy via URL/link, QRCode. You name it.
///
/// In hindsight this encoding scheme leaves much to be desired...
/// But there are already many feeds published that
/// would be nice to excavate in the future.
const testing = std.testing;
const std = @import("std");
const ArrayList = std.ArrayList;
const U = @import("util.zig");

pub const pickle_glyph = "PIC0.";
pub const block_glyph = "B0.";
pub const key_glyph = "K0."; // Pickled
const KEY_GLYPH = U.key_glyph; // Binary; May change in the future!

const Chunk = union(enum) {
    block: []const u8,
    key: []const u8,
};

/// Decodes unpadded url-safe b64 feeds.
/// returns ArrayList that needs to be deinitialized.
/// (Alpha quality code i fell out of zen)
pub fn decode_pickle(allocator: std.mem.Allocator, src: []const u8) !ArrayList(u8) {
    const Decoder = std.base64.url_safe_no_pad.Decoder;
    var iter = PickleTokenizer{ .buffer = src, .index = 0 };
    var chunks = ArrayList(Chunk).init(allocator);
    defer chunks.deinit();
    var total_size: usize = 0;

    while (iter.next()) |chunk| {
        const data = switch (chunk) {
            .key => |d| blk: {
                total_size += KEY_GLYPH.len;
                break :blk d;
            },
            .block => |d| d,
        };
        total_size += try Decoder.calcSizeForSlice(data);
        try chunks.append(chunk);
    }
    var out = try ArrayList(u8).initCapacity(allocator, total_size);
    errdefer out.deinit(); // Exported mem, deinit only on fail.
    out.expandToCapacity();
    var o: usize = 0;
    for (chunks.items) |chunk| {
        const data = switch (chunk) {
            .key => |d| blk: {
                std.mem.copy(u8, out.items[o..], KEY_GLYPH);
                o += KEY_GLYPH.len;
                break :blk d;
            },
            .block => |d| d,
        };
        const required = try Decoder.calcSizeForSlice(data);
        Decoder.decode(out.items[o..], data) catch |err| {
            U.log.debug("Base64 Decode failed for: {s}", .{data});
            return err;
        };
        o += required;
    }
    return out;
}

pub const PickleTokenizer = struct {
    const Self = @This();
    const Token = struct { key: bool, offset: usize };
    buffer: []const u8,
    index: usize,

    pub fn next(self: *Self) ?Chunk {
        // Fastforward index past pickle identifier on first run
        if (self.index == 0) {
            const o = std.mem.indexOf(u8, self.buffer[self.index..], pickle_glyph) orelse return null;
            self.index = o + pickle_glyph.len;
        }
        // Head of casette should be a glyph
        const start_token = self.seek(self.index) orelse return null;
        const c_start = self.index + start_token.offset + tSize(start_token.key);
        const endToken = self.seek(c_start);
        const c_end = if (endToken != null) c_start + endToken.?.offset else self.buffer.len;

        if (c_end - c_start < 1) return null;
        self.index = c_end;
        const d = self.buffer[c_start..c_end];
        return if (start_token.key) .{ .key = d } else .{ .block = d };
    }
    inline fn tSize(key: bool) usize {
        return if (key) key_glyph.len else block_glyph.len;
    }

    /// returns relative offset to input offset.
    fn seek(self: *Self, offset: usize) ?Token {
        const kr = std.mem.indexOf(u8, self.buffer[offset..], key_glyph);
        const br = std.mem.indexOf(u8, self.buffer[offset..], block_glyph);
        if (kr == null and br == null) return null;
        if (kr != null and br != null and kr.? < br.?) {
            return .{ .key = true, .offset = kr.? };
        } else if (kr == null) {
            return .{ .key = false, .offset = br.? };
        } else {
            return .{ .key = false, .offset = br.? };
        }
    }
};

test "decode" {
    testing.log_level = .debug;
    var allocator: std.mem.Allocator = testing.allocator;
    const pickle = "PIC0.K0.f5DSHew0QQ9MAmVBoySpiTMqq2UWHNizQdcvta21UuEB0.x70mwrzUXOLTB-SvQrWjEMhn9Y5CSCRTOWPAfS6xXuh_C5IqhIfxtaJLZSz3kY3ot9iiZdO3_yDTQjM5ij74AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdQWxsIHlvdXIgYmFzZSBpcyBhbGwgb3VyIGJhc2U";
    const expected_hex = comptime U.fromHex("4b302e7f90d21dec34410f4c026541a324a989332aab65161cd8b341d72fb5adb552e1c7bd26c2bcd45ce2d307e4af42b5a310c867f58e424824533963c07d2eb15ee87f0b922a8487f1b5a24b652cf7918de8b7d8a265d3b7ff20d34233398a3ef801000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001d416c6c20796f7572206261736520697320616c6c206f75722062617365");

    const decoded = try decode_pickle(allocator, pickle);
    defer decoded.deinit();

    try testing.expectEqualSlices(u8, expected_hex, decoded.items);

    // TODO:
    // var encoded = try allocator.alloc([]u8, PickleEncoder.calcSize(decoded));
    // defer allocator.free(encoded);
    // PickleEncoder.encode(encoded, blocks)
    // try testing.expectEqualStrings(pickle, encoded);
}
