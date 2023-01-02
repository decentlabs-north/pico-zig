const std = @import("std");
const U = @import("util.zig");
const log = U.log;
const Sign = U.Sign;

pub const Block = struct {
    pub const DecodingError = error{InvalidLength};
    /// 132bytes
    pub const HEADER_LENGTH = U.size.body_counter + U.size.sig * 2;

    /// Block signature / BlockIdentity
    sig: *[U.size.sig]u8,
    /// Signature of parent block
    parent_sig: *[U.size.sig]u8,
    /// 4 Bytes
    /// block-body size
    size: usize,
    /// total block size in bytes
    block_size: usize,
    /// Cryptographically signed data
    dat: []u8,
    /// Userspace data
    body: []u8,

    pub fn from(bytes: []u8) !Block {
        const hz = U.size.sig * 2;
        const oz = U.size.body_counter; // @divExact(@typeInfo(u32).Int.bits, 8);
        // `bytes` needs to be at least Header + 1byte Body in length
        if (bytes.len < comptime hz + oz + 1) return DecodingError.InvalidLength;

        const body_size = std.mem.readIntBig(u32, bytes[hz..][0..oz]);
        const block_size = hz + oz + body_size;
        log.debug("HUUUBBOOO body_size: {}, block_size: {}, bytes.len: {}", .{ body_size, block_size, bytes.len });
        // `bytes` needs to contain enough data to cover body.
        if (bytes.len < block_size) return DecodingError.InvalidLength;

        return Block{
            .sig = bytes[0..U.size.sig],
            .parent_sig = bytes[U.size.sig..hz],
            .size = body_size,
            .block_size = block_size,
            .dat = bytes[U.size.sig..block_size],
            .body = bytes[hz + oz ..][0..body_size],
        };
    }

    pub fn verify(self: *const Block, public_key: [U.size.pk]u8) !void {
        const pk = try Sign.PublicKey.fromBytes(public_key[0..U.size.pk].*);
        const signature = Sign.Signature.fromBytes(self.sig.*);
        try signature.verify(self.dat, pk);
    }
};
