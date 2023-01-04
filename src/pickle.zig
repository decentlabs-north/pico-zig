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

const ChunkType = enum { Key, Block };
const Chunk = struct {
    chunk_type: ChunkType,
    data: []const u8,
};

/// Decodes unpadded url-safe b64 feeds.
/// returns ArrayList that needs to be deinitialized.
/// (Alpha quality code i fell out of zen)
pub fn decode_pickle(allocator: std.mem.Allocator, src: []const u8) !ArrayList(u8) {
    const Decoder = std.base64.url_safe_no_pad.Decoder;
    var iter = PickleIterator{ .buffer = src, .index = 0 };
    var chunks = ArrayList(Chunk).init(allocator);
    defer chunks.deinit();
    var total_size: usize = 0;
    while (iter.next()) |chunk| {
        if (chunk.chunk_type == ChunkType.Key) {
            total_size += KEY_GLYPH.len;
        }
        total_size += try Decoder.calcSizeForSlice(chunk.data);
        try chunks.append(chunk);
    }
    var out = try ArrayList(u8).initCapacity(allocator, total_size);
    errdefer out.deinit();
    out.expandToCapacity();
    var o: usize = 0;
    for (chunks.items) |chunk| {
        if (chunk.chunk_type == ChunkType.Key) {
            std.mem.copy(u8, out.items[o..], KEY_GLYPH);
            o += KEY_GLYPH.len;
        }
        const required = try Decoder.calcSizeForSlice(chunk.data);
        try Decoder.decode(out.items[o..], chunk.data);
        o += required;
    }
    return out;
}

pub const PickleIterator = struct {
    buffer: []const u8,
    index: usize,
    const Self = @This();

    pub fn next(self: *Self) ?Chunk {
        if (self.index == 0) {
            // Fastforward index past pickle identifier
            self.index = std.mem.indexOf(u8, self.buffer[self.index..], pickle_glyph) orelse return null;
        }
        // Head of casette should be a glyph
        const startToken = seek(self.buffer, self.index) orelse return null;
        const start = startToken.end;
        const endToken = seek(self.buffer, start);
        const end = if (endToken != null) endToken.?.start else self.buffer.len;
        if (end - start < 1) return null;
        self.index += end;
        return .{
            .chunk_type = startToken.c_type,
            .data = self.buffer[start..end],
        };
    }

    const Token = struct { start: usize, end: usize, c_type: ChunkType };

    // returns indexOf next glyph
    fn seek(buffer: []const u8, offset: ?usize) ?Token {
        var o = offset orelse 0;
        var key_inc: usize = 0;
        var block_inc: usize = 0;
        while (o < buffer.len) : (o += 1) {
            const c = buffer[o];
            if (c == key_glyph[key_inc]) {
                key_inc += 1;
                if (key_inc == key_glyph.len) return .{
                    .c_type = ChunkType.Key,
                    .start = o - key_glyph.len + 1,
                    .end = o + 1,
                };
            } else key_inc = 0;
            if (c == block_glyph[block_inc]) {
                block_inc += 1;
                if (block_inc == block_glyph.len) return .{
                    .c_type = ChunkType.Block,
                    .start = o - block_glyph.len + 1,
                    .end = o + 1,
                };
            } else block_inc = 0;
        }
        return null;
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
