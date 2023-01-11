// Borrowed from (public domain) https://github.com/tetsu-koba/hexdump/blob/main/src/hexdump.zig
const std = @import("std");
const mem = std.mem;
const expect = std.testing.expect;

pub fn toHex(input: []const u8, output: []u8) ![]u8 {
    var fbs = std.io.fixedBufferStream(output);
    const w = fbs.writer();
    for (input) |x| {
        try w.print("{x:0>2} ", .{x});
    }
    return fbs.getWritten();
}

pub fn toPrintable(input: []const u8, output: []u8) ![]u8 {
    var fbs = std.io.fixedBufferStream(output);
    const w = fbs.writer();
    for (input) |x| {
        switch (x) {
            0x00...0x1f, 0x7f...0xff => try w.writeByte('.'),
            else => try w.writeByte(x),
        }
    }
    return fbs.getWritten();
}

pub fn toOctalPrintable(input: []const u8, output: []u8) ![]u8 {
    var fbs = std.io.fixedBufferStream(output);
    const w = fbs.writer();
    for (input) |x| {
        switch (x) {
            0x00...0x1f, 0x7f...0xff => try w.print("\\{o}", .{x}),
            else => try w.writeByte(x),
        }
    }
    return fbs.getWritten();
}

test "toHex" {
    const buf = [_]u8{
        0x01,
        0x02,
        0x7f,
        0xff,
        0x80,
        0x41,
        0x61,
        0x32,
    };
    var wbuf: [32]u8 = undefined;
    const x = try toHex(&buf, &wbuf);
    try expect(mem.eql(u8, x, "01 02 7f ff 80 41 61 32 "));
}

test "toHex NoSpaceLeft" {
    const buf = [_]u8{ 0x01, 0x02, 0x7f };
    var wbuf: [2]u8 = undefined;
    _ = toHex(&buf, &wbuf) catch |e| {
        try expect(e == error.NoSpaceLeft);
        return;
    };
    unreachable;
}

test "toPrintable" {
    const buf = [_]u8{
        0x01,
        0x02,
        0x7f,
        0xff,
        0x80,
        0x41,
        0x61,
        0x32,
    };
    var wbuf: [32]u8 = undefined;
    const x = try toPrintable(&buf, &wbuf);
    try expect(mem.eql(u8, x, ".....Aa2"));
}

test "toPrintable NoSpaceLeft" {
    const buf = [_]u8{ 0x01, 0x02, 0x7f };
    var wbuf: [2]u8 = undefined;
    _ = toPrintable(&buf, &wbuf) catch |e| {
        try expect(e == error.NoSpaceLeft);
        return;
    };
    unreachable;
}

test "toOctalPrintable" {
    const buf = "\x00\x01hello.txt\x00octet\x00";
    var wbuf: [32]u8 = undefined;
    const x = try toOctalPrintable(buf, &wbuf);
    try expect(mem.eql(u8, x, "\\0\\1hello.txt\\0octet\\0"));
}

test "toOctalPrintable NoSpaceLeft" {
    const buf = [_]u8{ 0x01, 0x02, 0x7f };
    var wbuf: [2]u8 = undefined;
    _ = toPrintable(&buf, &wbuf) catch |e| {
        try expect(e == error.NoSpaceLeft);
        return;
    };
    unreachable;
}
