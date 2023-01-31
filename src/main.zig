const std = @import("std");
const builtin = @import("builtin");

const FeedMain = @import("./feed/feed.zig");
const U = @import("./feed/util.zig");
// Use this struct from other Zig projects
pub const Feed = FeedMain.Feed;
pub const Block = FeedMain.Block;

// TODO: MOVE TO wasm.zig, add addition build target
// RUN:
// figlet "WASM" && zig build-lib src/main.zig -target wasm32-freestanding -dynamic -OReleaseSmall

const ally = if (builtin.target.isWasm()) std.heap.wasm_allocator else std.heap.c_allocator;

extern fn consoleLog(ptr: [*]const u8, size: usize) void;
extern fn randomBytes(ptr: [*]const u8, size: usize) void;

/// Returns a 64byte signing pair
//export fn signPair(out: [*]u8) i8 {
//const Sign = std.crypto.sign.Ed25519;
//var seed: [Sign.KeyPair.seed_length]u8 = undefined;
//randomBytes(&seed, seed.len);
//var pair = Sign.KeyPair.create(seed) catch return -1;
//std.mem.copy(u8, out[0..64], &pair.secret_key.bytes);
//return 0;
//}

// var log_buffer: [2000]u8 = undefined;
pub const log_level: std.log.Level = .debug;
pub fn log(
    comptime _: std.log.Level,
    comptime _: @TypeOf(.EnumLiteral), // scope
    comptime format: []const u8,
    args: anytype,
) void {
    var buffer = std.ArrayList(u8).init(ally);
    defer buffer.deinit();
    consoleLog(format.ptr, format.len);
    std.fmt.format(buffer.writer(), "Args: {} @{*}", .{ @TypeOf(args), &args }) catch return {
        const errName = "FormatError"; // @as([]const u8, @errorName(e));
        return consoleLog(errName, errName.len);
    };
    consoleLog(buffer.items.ptr, buffer.items.len);
}

export fn alloc(size: usize) ?[*]u8 {
    const buf = ally.alloc(u8, size) catch return null;
    U.log.debug("Allocated {d}b => *{*}", .{ size, buf.ptr });
    return buf.ptr;
}
export fn free(ptr: [*]u8, size: usize) void {
    ally.free(ptr[0..size]);
    U.log.debug("Free {d}b => *{*}", .{ size, ptr });
}

export fn dummy() i8 {
    U.log.debug("Dummy() call", .{});
    const allocator = ally;
    // var pair = Sign.KeyPair.create(undefined) catch return -1;
    const sk = [_]u8{ 18, 71, 114, 177, 251, 67, 53, 151, 104, 29, 40, 37, 115, 230, 200, 209, 67, 97, 53, 122, 115, 16, 1, 173, 124, 102, 79, 124, 95, 242, 181, 181, 122, 104, 78, 16, 198, 116, 8, 54, 194, 218, 190, 38, 120, 255, 181, 203, 255, 123, 30, 153, 25, 249, 101, 22, 79, 207, 23, 229, 137, 236, 36, 188 };
    var f = Feed.create(allocator) catch -2;
    defer f.deinit();
    f.append("Pure Xorcery", sk) catch return -3;
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    const s = f.pickle(allocator, buffer.writer()) catch return -4;
    U.log.debug("Pickle size {d}", .{s});
    return 0;
}

export fn parse() i32 { // str: [*:0]u8) i32 {
    const str = "PIC0.K0.4fBbJtXDXdApELB2kM9qbryCLlZETa1533F5sxup42UB0.eLGtEIiQ15g-haNjGcZgy0aryxIRP3NwY7feFsyG8XYQNU4VQFc4lrqQWBEDVGFYH1NKpjwLmouwlsnb9wPVDgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwPEFsaWNlPlRha2Ugb2ZmIGV2ZXJ5IHppZyEKRGlkJ3lhIGhlYXIgdGhlIG5ld3M_K0.cBTeJ2otiOWSuFCmeC-NuVFo76FU1uEBlhhggUc_WI4B0.CjSIoFMwcS_bnQs7jkKJLQ80Urj1xsCq3KTBiYn7dZtZQilNtYI6gYeXusomSBqswWYrzKcClFqJZg0mTbi_DnixrRCIkNeYPoWjYxnGYMtGq8sSET9zcGO33hbMhvF2EDVOFUBXOJa6kFgRA1RhWB9TSqY8C5qLsJbJ2_cD1Q4AAAAKPEJvYj5OZXdzPwB0.xcP0pQlgp20zkPPZGHmztBTTO_wKJY2ORjf2WmoFet60ge5BLBmLdHN-8O8kyueFq2A9Yr9FPFY9CVcVyX5VDQo0iKBTMHEv250LO45CiS0PNFK49cbAqtykwYmJ-3WbWUIpTbWCOoGHl7rKJkgarMFmK8ynApRaiWYNJk24vw4AAAAhPEFsaWNlPlBpY28qIHdpbGwgcnVuIG9uIEVTUDMyISEhB0.jl4AXA9j6aAk_VENsgO204gy5oVdg0sc0EA8n20dH-IGuNZipAtgxFyIkUFgfie9FccewXm7aSOLUABqS4eYBsXD9KUJYKdtM5Dz2Rh5s7QU0zv8CiWNjkY39lpqBXretIHuQSwZi3RzfvDvJMrnhatgPWK_RTxWPQlXFcl-VQ0AAAAsPEJvYj4gIkh5cGVyIE1vZGVtNTYgVHVyYm8gSUkiIGZvciByZWFsPz8gOk8B0.pvLkfMRzyZflLlP3nTsrZRa5yLNLPxAZf1Z_lqlrKGsX_aL4rKmheEu09W3qfIDlkR5x99b_Y1I_DLGowXx4DI5eAFwPY-mgJP1RDbIDttOIMuaFXYNLHNBAPJ9tHR_iBrjWYqQLYMRciJFBYH4nvRXHHsF5u2kji1AAakuHmAYAAAAQPEFsaWNlPiBZZXMhIDonKQ";
    const allocator = ally;
    var f = Feed.unpickle(allocator, str) catch return -1;
    defer f.deinit();
    f.inspect();
    var pic_v2 = std.ArrayList(u8).init(allocator);
    defer pic_v2.deinit();
    const size = f.pickle(allocator, pic_v2.writer()) catch return -2;
    // print(@ptrCast([*:0]u8, pic_v2.items.ptr));
    return @as(i32, @truncate(u16, size));
}
