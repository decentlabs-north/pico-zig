const std = @import("std");
pub const log = std.log.scoped(.pico);

// Magic numbers
pub const key_glyph = "K0."; // Maybe redesign into segment-header?

pub const Sign = std.crypto.sign.Ed25519;
pub const size = struct {
    /// 32Bytes
    pub const pk = Sign.PublicKey.encoded_length;
    /// 64Bytes (SK + PK)
    pub const sk = Sign.SecretKey.encoded_length;
    /// 64Bytes
    pub const sig = Sign.Signature.encoded_length;
    /// Body-Size Counter: BigEndian u32
    pub const body_counter = 4;
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
