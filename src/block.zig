const std = @import("std");
const testing = std.testing;
const U = @import("util.zig");
const Sign = U.Sign;

pub const Header = extern struct {
    signature: [U.size.sig]u8,
    parent_signature: [U.size.sig]u8,
    /// Use readSize() for correct endianess
    _size: [U.size.body_counter]u8,

    pub inline fn readSize(self: *const Header) u32 {
        return std.mem.readIntBig(u32, &self._size);
    }

    pub inline fn writeSize(self: *Header, size: u32) void {
        // @truncate(u32, data.len)
        std.mem.writeIntBig(u32, &self._size, size);
    }
};

pub const Block = struct {
    pub const DecodingError = error{InvalidLength};
    // Slice to entire block
    bytes: []const u8,
    // Block Header
    header: *const Header,
    /// Userspace data
    body: []const u8,
    /// Cryptographically signed data
    dat: []const u8,

    pub fn from(bytes: []const u8) !Block {
        // `bytes` needs to be at least Header + 1byte Body in length
        if (bytes.len < U.size.header + 1) return DecodingError.InvalidLength;
        const h = @ptrCast(*const Header, bytes.ptr);
        const body_size = h.readSize();
        const block_size = U.size.header + body_size;
        // `bytes` needs to contain enough data to cover body.
        if (bytes.len < block_size) {
            U.log.err("BlockError InvalidLength: remain [{}]u8 requested [{}]u8", .{ bytes.len, block_size });
            U.log.err("BigEndian hex: {s}", .{U.hex(bytes[128..][0..4])});
            try U.hexdump(bytes);
            return DecodingError.InvalidLength;
        }
        return .{
            .header = h,
            .bytes = bytes[0..block_size],
            .dat = bytes[U.size.sig..block_size],
            .body = bytes[U.size.header..][0..body_size],
        };
    }

    pub fn verify(self: *const Block, public_key: [U.size.pk]u8) !void {
        try U.signVerify(self.header.signature, self.dat, public_key);
    }
};

test "Header access via ptrCast" {
    // Fixtures
    const ex_sig = [_]u8{'A'} ** 64;
    const ex_psig = [_]u8{'B'} ** 64;
    const ex_body = "Hello";
    const dummy = ex_sig ++ ex_psig ++ [_]u8{ 0, 0, 0, 5 } ++ ex_body;

    // Test reading
    const header = @ptrCast(*const Header, dummy);
    try testing.expectEqual(U.size.header, @sizeOf(Header));
    try testing.expectEqualSlices(u8, &ex_sig, &header.signature);
    try testing.expectEqualSlices(u8, &ex_psig, &header.parent_signature);
    try testing.expectEqual(header.readSize(), 5);

    // Test writing
    var block: [U.size.header + 5]u8 = undefined;
    var h = @ptrCast(*Header, &block);
    var i: usize = 0;
    while (i < 64) : (i += 1) {
        h.signature[i] = 'A';
        h.parent_signature[i] = 'B';
    }
    h.writeSize(5);
    for (ex_body) |c, n| block[@sizeOf(Header) + n] = c;
    try testing.expectEqualSlices(u8, dummy, &block);
}

// Demystifying pointers...
//test "I'm an idiot" {
//testing.log_level = .debug;
//const A = struct {
//b: []const u8,
//c: []const u8,
//};
//const bin = [_]u8{ 0, 1, 2, 3, 4, 5 };
//const a = A{
//.b = bin[0..4],
//.c = bin[3..],
//};
//U.log.debug("bin@{}, b@{}, c{}", .{
//@ptrToInt(&bin),
//@ptrToInt(a.b.ptr),
//@ptrToInt(a.c.ptr),
//});
//var b2: [32]u8 = undefined;
//const a2 = A{ .b = b2[1..], .c = b2[2..] };
//U.log.debug("bin2@{}, b@{}, c{}", .{
//@ptrToInt(&b2),
//@ptrToInt(a2.b.ptr),
//@ptrToInt(a2.c.ptr),
//});
//}
