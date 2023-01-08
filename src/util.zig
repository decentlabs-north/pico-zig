const std = @import("std");
const hd = @import("hexdump.zig"); // soz, i'm a newb at printdebugging

pub const Sign = std.crypto.sign.Ed25519;
pub const log = std.log.scoped(.pico);

// Magic numbers
pub const key_glyph = "K0."; // Maybe redesign into segment-header?

pub const size = struct {
    /// 32Bytes
    pub const pk = Sign.PublicKey.encoded_length;
    /// 64Bytes (SK + PK)
    pub const sk = Sign.SecretKey.encoded_length;
    /// 64Bytes
    pub const sig = Sign.Signature.encoded_length;
    /// Body-Size Counter: BigEndian u32
    pub const body_counter = 4;
    /// 132bytes
    pub const header = body_counter + sig * 2;
    pub const min_block = header + 1;
    pub const max_block = 65536; // 64k
};

pub const hex = std.fmt.fmtSliceHexLower;
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

// TODO: replace with some builtin
pub fn fromHex(comptime txt: []const u8) []const u8 {
    var bin: [txt.len >> 1]u8 = undefined;
    var prev: u8 = ' ';
    for (txt) |chr, i| {
        if (i % 2 != 0) {
            bin[i >> 1] = (parse16(prev) << 4) + parse16(chr);
        } else {
            prev = chr;
        }
    }
    return &bin;
}

pub fn sign(message: []const u8, secret: [size.sk]u8, noise: ?[Sign.noise_length]u8) ![size.sig]u8 {
    const kp = try Sign.KeyPair.fromSecretKey(try Sign.SecretKey.fromBytes(secret));
    const signature = try kp.sign(message, noise);
    return signature.toBytes();
}
pub fn signVerify(signature: [size.sig]u8, message: []const u8, public_key: [size.pk]u8) !void {
    const sig = Sign.Signature.fromBytes(signature);
    const pk = try Sign.PublicKey.fromBytes(public_key);
    try sig.verify(message, pk);
}

pub fn hexdump(bin: []const u8) !void {
    const stdout_file = std.io.getStdErr().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();
    var hbuf1: [32]u8 = undefined;
    var hbuf2: [32]u8 = undefined;
    var abuf: [16]u8 = undefined;
    var offset: usize = 0;
    var n: usize = 16;
    while (n == 16) : (offset += n) {
        n = @min(16, bin.len - offset);
        const buf = bin[offset..][0..n];
        try stdout.print("{x:0>8}  ", .{offset});
        if (n > 8) {
            try stdout.print("{s} {s: <24} |{s}|\n", .{ try hd.toHex(buf[0..8], &hbuf1), try hd.toHex(buf[8..n], &hbuf2), try hd.toPrintable(buf[0..n], &abuf) });
        } else {
            try stdout.print("{s: <49} |{s}|\n", .{ try hd.toHex(buf[0..n], &hbuf1), try hd.toPrintable(buf[0..n], &abuf) });
        }
    } else {
        try stdout.print("{x:0>8}\n", .{offset});
    }
    bw.flush() catch {};
}
