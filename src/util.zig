const std = @import("std");
pub const Sign = std.crypto.sign.Ed25519;
pub const log = std.log.scoped(.pico);

// Magic numbers
pub const key_glyph = "K0."; // Maybe redesign into segment-header?
pub const block_limit = 65536; // 64k

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
