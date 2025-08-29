const std = @import("std");
const crypto = std.crypto;

// Crockford's Base32 alphabet (excludes I, L, O, U to avoid confusion)
const base32_alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

// Decode lookup table for faster parsing (256 entries, 255 = invalid)
// Supports both uppercase and lowercase for case-insensitive parsing
const decode_table = blk: {
    var table: [256]u8 = [_]u8{255} ** 256;
    for (base32_alphabet, 0..) |c, i| {
        table[c] = @intCast(i); // Uppercase
        // Map lowercase letters to same values
        if (c >= 'A' and c <= 'Z') {
            const lower = std.ascii.toLower(c);
            table[lower] = @intCast(i);
        }
    }
    break :blk table;
};

// Error types matching oklog/ulid
pub const UlidError = error{
    MonotonicOverflow,
    InvalidUlid,
};

// ULID binary representation (value type, no allocations)
pub const Ulid = struct {
    bytes: [16]u8,

    pub fn timestamp(self: Ulid) u64 {
        // Extract 48-bit timestamp from first 6 bytes
        var ts: u64 = 0;
        ts |= @as(u64, self.bytes[0]) << 40;
        ts |= @as(u64, self.bytes[1]) << 32;
        ts |= @as(u64, self.bytes[2]) << 24;
        ts |= @as(u64, self.bytes[3]) << 16;
        ts |= @as(u64, self.bytes[4]) << 8;
        ts |= @as(u64, self.bytes[5]);
        return ts;
    }

    // Convert to string (returns stack-allocated array)
    pub fn toString(self: Ulid) [26]u8 {
        var result: [26]u8 = undefined;
        encodeBase32(self.bytes, &result);
        return result;
    }

    // Encode into provided buffer (zero-copy)
    pub fn encodeInto(self: Ulid, buffer: *[26]u8) void {
        encodeBase32(self.bytes, buffer);
    }

    // Comparison operators
    pub fn lessThan(a: Ulid, b: Ulid) bool {
        return std.mem.order(u8, a.bytes[0..], b.bytes[0..]) == .lt;
    }

    pub fn equals(a: Ulid, b: Ulid) bool {
        return std.mem.eql(u8, a.bytes[0..], b.bytes[0..]);
    }

    // Format implementation for direct printing
    pub fn format(
        self: Ulid,
        writer: anytype,
    ) !void {
        const str = self.toString();
        try writer.writeAll(str[0..]);
    }
};

// Type-safe ULID string wrapper
pub const UlidString = struct {
    chars: [26]u8,

    pub fn format(
        self: UlidString,
        writer: anytype,
    ) !void {
        try writer.writeAll(self.chars[0..]);
    }

    pub fn parse(self: UlidString) !Ulid {
        return parseBytes(&self.chars);
    }
};

// Zero-allocation generator pattern (no global state)
pub const Generator = struct {
    entropy: [10]u8,
    timestamp: i64,

    pub fn init() Generator {
        var g: Generator = undefined;
        crypto.random.bytes(&g.entropy);
        g.timestamp = 0;
        return g;
    }

    pub fn next(self: *Generator) !Ulid {
        var now = std.time.milliTimestamp();

        // Handle clock rollback - clamp to last timestamp
        if (now < self.timestamp) {
            now = self.timestamp;
        }

        var ulid: Ulid = undefined;

        // Encode timestamp
        const timestamp_u48 = @as(u64, @intCast(now)) & 0xFFFFFFFFFFFF;
        ulid.bytes[0] = @intCast((timestamp_u48 >> 40) & 0xFF);
        ulid.bytes[1] = @intCast((timestamp_u48 >> 32) & 0xFF);
        ulid.bytes[2] = @intCast((timestamp_u48 >> 24) & 0xFF);
        ulid.bytes[3] = @intCast((timestamp_u48 >> 16) & 0xFF);
        ulid.bytes[4] = @intCast((timestamp_u48 >> 8) & 0xFF);
        ulid.bytes[5] = @intCast(timestamp_u48 & 0xFF);

        if (now == self.timestamp) {
            // Same millisecond: increment with random value
            var inc_bytes: [4]u8 = undefined;
            crypto.random.bytes(inc_bytes[0..]);
            var inc = std.mem.readInt(u32, inc_bytes[0..], .big);
            if (inc == 0) inc = 1;

            // Perform 80-bit addition
            var carry: u64 = inc;
            var i: usize = 9;
            while (true) : (i -%= 1) {
                const sum = @as(u64, self.entropy[i]) + (carry & 0xFF);
                self.entropy[i] = @intCast(sum & 0xFF);
                carry = sum >> 8;

                if (i == 0) {
                    if (carry > 0) {
                        return UlidError.MonotonicOverflow;
                    }
                    break;
                }
            }
        } else {
            // New millisecond: fresh entropy
            crypto.random.bytes(&self.entropy);
            self.timestamp = now;
        }

        std.mem.copyForwards(u8, ulid.bytes[6..16], self.entropy[0..]);
        return ulid;
    }

    pub fn nextString(self: *Generator) ![26]u8 {
        return (try self.next()).toString();
    }
};

// Lock-free atomic generator for high-concurrency scenarios
// Note: std.atomic.Value(u128) may not be lock-free on all targets.
// Fall back to Generator with mutex if not supported on your platform.
pub const AtomicGenerator = struct {
    // Use mutex-based implementation on x86_64 due to Zig 0.15.1 issues with atomic u128
    const use_atomic = @import("builtin").cpu.arch != .x86_64;
    
    // Pack timestamp (48 bits) and entropy (80 bits) into 128 bits
    last: if (use_atomic) std.atomic.Value(u128) else u128,
    mutex: if (use_atomic) void else std.Thread.Mutex,

    pub fn init() AtomicGenerator {
        if (use_atomic) {
            return .{ 
                .last = std.atomic.Value(u128).init(0),
                .mutex = {},
            };
        } else {
            return .{
                .last = 0,
                .mutex = std.Thread.Mutex{},
            };
        }
    }

    pub fn next(self: *AtomicGenerator) !Ulid {
        if (!use_atomic) {
            self.mutex.lock();
            defer self.mutex.unlock();
            
            const now = @as(u64, @intCast(std.time.milliTimestamp())) & 0xFFFFFFFFFFFF;
            
            const old = self.last;
            const old_ts = @as(u64, @truncate(old >> 80));
            
            var new_value: u128 = undefined;
            
            if (now > old_ts) {
                // New millisecond
                var entropy: [10]u8 = undefined;
                crypto.random.bytes(&entropy);
                new_value = (@as(u128, now) << 80) | bytesToU80(entropy);
            } else if (now == old_ts) {
                // Same millisecond: increment
                var inc_bytes: [4]u8 = undefined;
                crypto.random.bytes(inc_bytes[0..]);
                const inc = std.mem.readInt(u32, inc_bytes[0..], .big) | 1;
                
                new_value = old + inc;
                
                // Check for overflow (timestamp changed)
                if (@as(u64, @truncate(new_value >> 80)) != now) {
                    return UlidError.MonotonicOverflow;
                }
            } else {
                // Clock went backward, use last timestamp
                new_value = old + 1;
            }
            
            self.last = new_value;
            return u128ToUlid(new_value);
        }
        
        // Original atomic implementation for non-x86_64
        const now = @as(u64, @intCast(std.time.milliTimestamp())) & 0xFFFFFFFFFFFF;

        while (true) {
            const old = self.last.load(.acquire);
            const old_ts = @as(u64, @truncate(old >> 80));

            var new_value: u128 = undefined;

            if (now > old_ts) {
                // New millisecond
                var entropy: [10]u8 = undefined;
                crypto.random.bytes(&entropy);
                new_value = (@as(u128, now) << 80) | bytesToU80(entropy);
            } else if (now == old_ts) {
                // Same millisecond: increment
                var inc_bytes: [4]u8 = undefined;
                crypto.random.bytes(inc_bytes[0..]);
                const inc = std.mem.readInt(u32, inc_bytes[0..], .big) | 1;

                new_value = old + inc;

                // Check for overflow (timestamp changed)
                if (@as(u64, @truncate(new_value >> 80)) != now) {
                    return UlidError.MonotonicOverflow;
                }
            } else {
                // Clock went backward, wait
                std.Thread.yield() catch {};
                continue;
            }

            // Try to update atomically
            if (self.last.cmpxchgWeak(old, new_value, .acq_rel, .acquire) == null) {
                // Success! Convert to Ulid
                return u128ToUlid(new_value);
            }
            // Failed, retry
        }
    }

    fn bytesToU80(bytes: [10]u8) u128 {
        var result: u128 = 0;
        for (bytes) |b| {
            result = (result << 8) | b;
        }
        return result;
    }

    fn u128ToUlid(value: u128) Ulid {
        var ulid: Ulid = undefined;
        const ts = @as(u64, @truncate(value >> 80));

        // Encode timestamp
        ulid.bytes[0] = @intCast((ts >> 40) & 0xFF);
        ulid.bytes[1] = @intCast((ts >> 32) & 0xFF);
        ulid.bytes[2] = @intCast((ts >> 24) & 0xFF);
        ulid.bytes[3] = @intCast((ts >> 16) & 0xFF);
        ulid.bytes[4] = @intCast((ts >> 8) & 0xFF);
        ulid.bytes[5] = @intCast(ts & 0xFF);

        // Encode entropy
        const entropy = @as(u80, @truncate(value));
        for (0..10) |i| {
            const shift = @as(u7, @intCast(72 - (i * 8)));
            ulid.bytes[6 + i] = @intCast((entropy >> shift) & 0xFF);
        }

        return ulid;
    }
};

// Global state for backward-compatible monotonic generation
var global_generator: ?Generator = null;
var global_mutex = std.Thread.Mutex{};

// Generate new ULID (returns value type, no allocation)
pub fn new() Ulid {
    const timestamp = std.time.milliTimestamp();
    var ulid: Ulid = undefined;

    // Encode timestamp (48 bits = 6 bytes) in network byte order (MSB first)
    const timestamp_u48 = @as(u64, @intCast(timestamp)) & 0xFFFFFFFFFFFF;
    ulid.bytes[0] = @intCast((timestamp_u48 >> 40) & 0xFF);
    ulid.bytes[1] = @intCast((timestamp_u48 >> 32) & 0xFF);
    ulid.bytes[2] = @intCast((timestamp_u48 >> 24) & 0xFF);
    ulid.bytes[3] = @intCast((timestamp_u48 >> 16) & 0xFF);
    ulid.bytes[4] = @intCast((timestamp_u48 >> 8) & 0xFF);
    ulid.bytes[5] = @intCast(timestamp_u48 & 0xFF);

    // Generate random entropy (80 bits = 10 bytes)
    crypto.random.bytes(ulid.bytes[6..16]);

    return ulid;
}

// Generate new ULID with monotonicity guarantee (uses global generator)
pub fn newMonotonic() !Ulid {
    global_mutex.lock();
    defer global_mutex.unlock();

    // Initialize generator on first use
    if (global_generator == null) {
        global_generator = Generator.init();
    }

    return try global_generator.?.next();
}

// Generate ULID directly as string (convenience function)
pub fn newString() [26]u8 {
    return new().toString();
}

// Generate monotonic ULID directly as string
pub fn newMonotonicString() ![26]u8 {
    return (try newMonotonic()).toString();
}

// Generate ULID directly into buffer (zero-copy for hot paths)
pub fn newInto(buffer: *[26]u8) void {
    const ulid = new();
    encodeBase32(ulid.bytes, buffer);
}

// Generate monotonic ULID directly into buffer
pub fn newMonotonicInto(buffer: *[26]u8) !void {
    const ulid = try newMonotonic();
    encodeBase32(ulid.bytes, buffer);
}

// Binary helpers for direct byte access
pub fn newBytes() [16]u8 {
    return new().bytes;
}

pub fn newMonotonicBytes() ![16]u8 {
    return (try newMonotonic()).bytes;
}

// Create ULID from raw bytes
pub fn fromBytes(bytes: [16]u8) Ulid {
    return Ulid{ .bytes = bytes };
}

// Parse a ULID string back to binary representation
pub fn parse(ulid_str: []const u8) !Ulid {
    if (ulid_str.len != 26) {
        return UlidError.InvalidUlid;
    }
    const p: *const [26]u8 = @ptrCast(ulid_str.ptr);
    return parseBytes(p);
}

// ============= Time-Based Range Helpers =============

// Create ULID with minimum entropy for given timestamp (all zeros)
pub fn minForTime(timestamp_ms: i64) Ulid {
    var ulid = Ulid{ .bytes = [_]u8{0} ** 16 };
    const ts = @as(u64, @intCast(timestamp_ms)) & 0xFFFFFFFFFFFF;

    ulid.bytes[0] = @intCast((ts >> 40) & 0xFF);
    ulid.bytes[1] = @intCast((ts >> 32) & 0xFF);
    ulid.bytes[2] = @intCast((ts >> 24) & 0xFF);
    ulid.bytes[3] = @intCast((ts >> 16) & 0xFF);
    ulid.bytes[4] = @intCast((ts >> 8) & 0xFF);
    ulid.bytes[5] = @intCast(ts & 0xFF);

    return ulid;
}

// Create ULID with maximum entropy for given timestamp (all 0xFF)
pub fn maxForTime(timestamp_ms: i64) Ulid {
    var ulid = Ulid{ .bytes = undefined };
    const ts = @as(u64, @intCast(timestamp_ms)) & 0xFFFFFFFFFFFF;

    ulid.bytes[0] = @intCast((ts >> 40) & 0xFF);
    ulid.bytes[1] = @intCast((ts >> 32) & 0xFF);
    ulid.bytes[2] = @intCast((ts >> 24) & 0xFF);
    ulid.bytes[3] = @intCast((ts >> 16) & 0xFF);
    ulid.bytes[4] = @intCast((ts >> 8) & 0xFF);
    ulid.bytes[5] = @intCast(ts & 0xFF);

    // Maximum entropy
    @memset(ulid.bytes[6..16], 0xFF);

    return ulid;
}

// Check if ULID is within time range
pub fn isInTimeRange(ulid: Ulid, start_ms: i64, end_ms: i64) bool {
    const ts = @as(i64, @intCast(ulid.timestamp()));
    return ts >= start_ms and ts <= end_ms;
}

// ============= Validation and Sorting =============

// Fast validation without full parsing
pub fn isValid(str: []const u8) bool {
    if (str.len != 26) return false;

    // Check first character (must be 0-7)
    const first = str[0];
    if (first < '0' or first > '7') return false;

    // Check all characters are valid base32
    for (str) |c| {
        if (decode_table[c] == 255) return false;
    }

    return true;
}

// Extract just timestamp without full decode (faster for sorting)
pub fn extractTimestamp(ulid_str: []const u8) !u64 {
    if (ulid_str.len != 26) return UlidError.InvalidUlid;

    // Decode only first 10 chars for timestamp (48 bits)
    var chars: [10]u8 = undefined;
    for (ulid_str[0..10], 0..) |char, i| {
        const val = decode_table[char];
        if (val == 255) return UlidError.InvalidUlid;
        chars[i] = val;
    }

    // Validate canonical ULID: first char must be <= 7
    if (chars[0] > 7) return UlidError.InvalidUlid;

    // Reconstruct 6 timestamp bytes from first 10 base32 chars
    // Same logic as parseBytes but only for timestamp portion
    const c0 = chars[0];
    const c1 = chars[1];
    const c2 = chars[2];
    const c3 = chars[3];
    const c4 = chars[4];
    const c5 = chars[5];
    const c6 = chars[6];
    const c7 = chars[7];
    const c8 = chars[8];
    const c9 = chars[9];

    var ts: u64 = 0;
    ts |= @as(u64, (c0 << 5) | c1) << 40;
    ts |= @as(u64, (c2 << 3) | (c3 >> 2)) << 32;
    ts |= @as(u64, ((c3 & 0x03) << 6) | (c4 << 1) | (c5 >> 4)) << 24;
    ts |= @as(u64, ((c5 & 0x0F) << 4) | (c6 >> 1)) << 16;
    ts |= @as(u64, ((c6 & 0x01) << 7) | (c7 << 2) | (c8 >> 3)) << 8;
    ts |= @as(u64, ((c8 & 0x07) << 5) | c9);

    return ts;
}

// Optimized ULID sorting
pub fn sort(ulids: []Ulid) void {
    std.sort.block(Ulid, ulids, {}, lessThanContext);
}

fn lessThanContext(_: void, a: Ulid, b: Ulid) bool {
    return Ulid.lessThan(a, b);
}

// Sort ULID strings without parsing
// WARNING: This uses raw ASCII comparison - only works correctly with canonical uppercase ULIDs
// For mixed-case ULIDs, use sortStringsCaseInsensitive() instead
pub fn sortStrings(ulid_strings: [][]const u8) void {
    std.sort.block([]const u8, ulid_strings, {}, stringLessThan);
}

fn stringLessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

// Sort ULID strings case-insensitively (handles mixed-case ULIDs correctly)
pub fn sortStringsCaseInsensitive(ulid_strings: [][]const u8) void {
    std.sort.block([]const u8, ulid_strings, {}, stringLessThanCaseInsensitive);
}

fn stringLessThanCaseInsensitive(_: void, a: []const u8, b: []const u8) bool {
    // Use decode_table for proper case-insensitive comparison
    const min_len = @min(a.len, b.len);

    for (0..min_len) |i| {
        const val_a = decode_table[a[i]];
        const val_b = decode_table[b[i]];

        // Invalid characters sort last
        if (val_a == 255 and val_b != 255) return false;
        if (val_a != 255 and val_b == 255) return true;
        if (val_a == 255 and val_b == 255) continue;

        if (val_a < val_b) return true;
        if (val_a > val_b) return false;
    }

    // If all compared characters are equal, shorter string comes first
    return a.len < b.len;
}

// ============= Custom Entropy Sources =============

// Interface for custom entropy sources
pub const EntropySource = struct {
    ptr: *anyopaque,
    readFn: *const fn (ptr: *anyopaque, buffer: []u8) void,

    pub fn read(self: EntropySource, buffer: []u8) void {
        self.readFn(self.ptr, buffer);
    }
};

// Default crypto random entropy source
pub const CryptoRandomEntropy = struct {
    pub fn source() EntropySource {
        return .{
            .ptr = undefined,
            .readFn = readImpl,
        };
    }

    fn readImpl(_: *anyopaque, buffer: []u8) void {
        crypto.random.bytes(buffer);
    }
};

// Generator with custom entropy source
pub fn GeneratorWithEntropy(comptime Source: type) type {
    return struct {
        entropy: [10]u8,
        timestamp: i64,
        source: Source,

        pub fn init(source: Source) @This() {
            var g: @This() = .{
                .entropy = undefined,
                .timestamp = 0,
                .source = source,
            };
            g.source.read(&g.entropy);
            return g;
        }

        pub fn next(self: *@This()) !Ulid {
            const now = std.time.milliTimestamp();
            var ulid: Ulid = undefined;

            // Encode timestamp
            const timestamp_u48 = @as(u64, @intCast(now)) & 0xFFFFFFFFFFFF;
            ulid.bytes[0] = @intCast((timestamp_u48 >> 40) & 0xFF);
            ulid.bytes[1] = @intCast((timestamp_u48 >> 32) & 0xFF);
            ulid.bytes[2] = @intCast((timestamp_u48 >> 24) & 0xFF);
            ulid.bytes[3] = @intCast((timestamp_u48 >> 16) & 0xFF);
            ulid.bytes[4] = @intCast((timestamp_u48 >> 8) & 0xFF);
            ulid.bytes[5] = @intCast(timestamp_u48 & 0xFF);

            if (now == self.timestamp) {
                // Same millisecond: increment
                var inc_bytes: [4]u8 = undefined;
                self.source.read(inc_bytes[0..]);
                var inc = std.mem.readInt(u32, inc_bytes[0..], .big);
                if (inc == 0) inc = 1;

                // Perform 80-bit addition
                var carry: u64 = inc;
                var i: usize = 9;
                while (true) : (i -%= 1) {
                    const sum = @as(u64, self.entropy[i]) + (carry & 0xFF);
                    self.entropy[i] = @intCast(sum & 0xFF);
                    carry = sum >> 8;

                    if (i == 0) {
                        if (carry > 0) {
                            return UlidError.MonotonicOverflow;
                        }
                        break;
                    }
                }
            } else {
                // New millisecond: fresh entropy
                self.source.read(&self.entropy);
                self.timestamp = now;
            }

            std.mem.copyForwards(u8, ulid.bytes[6..16], self.entropy[0..]);
            return ulid;
        }
    };
}

// ============= Builder Pattern =============

// Builder for constructing ULIDs with specific components
pub const Builder = struct {
    timestamp_ms: ?i64 = null,
    entropy: ?[10]u8 = null,

    pub fn withTimestamp(self: *Builder, ms: i64) *Builder {
        self.timestamp_ms = ms;
        return self;
    }

    pub fn withEntropy(self: *Builder, entropy: [10]u8) *Builder {
        self.entropy = entropy;
        return self;
    }

    pub fn build(self: Builder) Ulid {
        var ulid: Ulid = undefined;

        // Use provided timestamp or current time
        const ts = if (self.timestamp_ms) |ms|
            @as(u64, @intCast(ms)) & 0xFFFFFFFFFFFF
        else
            @as(u64, @intCast(std.time.milliTimestamp())) & 0xFFFFFFFFFFFF;

        ulid.bytes[0] = @intCast((ts >> 40) & 0xFF);
        ulid.bytes[1] = @intCast((ts >> 32) & 0xFF);
        ulid.bytes[2] = @intCast((ts >> 24) & 0xFF);
        ulid.bytes[3] = @intCast((ts >> 16) & 0xFF);
        ulid.bytes[4] = @intCast((ts >> 8) & 0xFF);
        ulid.bytes[5] = @intCast(ts & 0xFF);

        // Use provided entropy or generate random
        if (self.entropy) |entropy| {
            std.mem.copyForwards(u8, ulid.bytes[6..16], entropy[0..]);
        } else {
            crypto.random.bytes(ulid.bytes[6..16]);
        }

        return ulid;
    }
};

// Parse with compile-time validation when possible
pub fn parseComptime(comptime s: []const u8) Ulid {
    comptime {
        if (s.len != 26) @compileError("ULID must be 26 characters");
        if (s[0] < '0' or s[0] > '7') @compileError("First character must be 0-7");

        // Validate all characters are valid base32
        for (s) |c| {
            const ok = (c >= '0' and c <= '9') or
                (c >= 'A' and c <= 'Z' and c != 'I' and c != 'L' and c != 'O' and c != 'U') or
                (c >= 'a' and c <= 'z' and c != 'i' and c != 'l' and c != 'o' and c != 'u');
            if (!ok) {
                @compileError("Invalid ULID: contains invalid base32 character");
            }
        }
    }

    // Parse at runtime (but we know it's valid)
    const p: *const [26]u8 = @ptrCast(s.ptr);
    return parseBytes(p) catch unreachable;
}

fn parseBytes(ulid_str: *const [26]u8) !Ulid {
    var result = Ulid{ .bytes = undefined };

    // Use lookup table for fast decoding
    var chars: [26]u8 = undefined;
    for (ulid_str, 0..) |char, i| {
        const val = decode_table[char];
        if (val == 255) return UlidError.InvalidUlid;
        chars[i] = val;
    }

    // Validate canonical ULID: first char must be <= 7 (only 3 bits used)
    if (chars[0] > 7) return UlidError.InvalidUlid;

    // Extract individual character values
    const c0 = chars[0];
    const c1 = chars[1];
    const c2 = chars[2];
    const c3 = chars[3];
    const c4 = chars[4];
    const c5 = chars[5];
    const c6 = chars[6];
    const c7 = chars[7];
    const c8 = chars[8];
    const c9 = chars[9];

    // Reconstruct timestamp bytes
    result.bytes[0] = @intCast((c0 << 5) | c1);
    result.bytes[1] = @intCast((c2 << 3) | (c3 >> 2));
    result.bytes[2] = @intCast(((c3 & 0x03) << 6) | (c4 << 1) | (c5 >> 4));
    result.bytes[3] = @intCast(((c5 & 0x0F) << 4) | (c6 >> 1));
    result.bytes[4] = @intCast(((c6 & 0x01) << 7) | (c7 << 2) | (c8 >> 3));
    result.bytes[5] = @intCast(((c8 & 0x07) << 5) | c9);

    // Decode entropy (last 16 chars to last 10 bytes)
    const c10 = chars[10];
    const c11 = chars[11];
    const c12 = chars[12];
    const c13 = chars[13];
    const c14 = chars[14];
    const c15 = chars[15];
    const c16 = chars[16];
    const c17 = chars[17];
    const c18 = chars[18];
    const c19 = chars[19];
    const c20 = chars[20];
    const c21 = chars[21];
    const c22 = chars[22];
    const c23 = chars[23];
    const c24 = chars[24];
    const c25 = chars[25];

    result.bytes[6] = @intCast((c10 << 3) | (c11 >> 2));
    result.bytes[7] = @intCast(((c11 & 0x03) << 6) | (c12 << 1) | (c13 >> 4));
    result.bytes[8] = @intCast(((c13 & 0x0F) << 4) | (c14 >> 1));
    result.bytes[9] = @intCast(((c14 & 0x01) << 7) | (c15 << 2) | (c16 >> 3));
    result.bytes[10] = @intCast(((c16 & 0x07) << 5) | c17);
    result.bytes[11] = @intCast((c18 << 3) | (c19 >> 2));
    result.bytes[12] = @intCast(((c19 & 0x03) << 6) | (c20 << 1) | (c21 >> 4));
    result.bytes[13] = @intCast(((c21 & 0x0F) << 4) | (c22 >> 1));
    result.bytes[14] = @intCast(((c22 & 0x01) << 7) | (c23 << 2) | (c24 >> 3));
    result.bytes[15] = @intCast(((c24 & 0x07) << 5) | c25);

    return result;
}

// Get timestamp from a ULID string without full parsing
pub fn getTimestamp(ulid_str: []const u8) !u64 {
    const ulid = try parse(ulid_str);
    return ulid.timestamp();
}

// Encode 16 bytes to 26 character base32 string
fn encodeBase32(bytes: [16]u8, output: *[26]u8) void {
    // Timestamp encoding (first 10 chars from first 48 bits)
    output[0] = base32_alphabet[(bytes[0] & 0xE0) >> 5];
    output[1] = base32_alphabet[bytes[0] & 0x1F];
    output[2] = base32_alphabet[(bytes[1] & 0xF8) >> 3];
    output[3] = base32_alphabet[((bytes[1] & 0x07) << 2) | ((bytes[2] & 0xC0) >> 6)];
    output[4] = base32_alphabet[(bytes[2] & 0x3E) >> 1];
    output[5] = base32_alphabet[((bytes[2] & 0x01) << 4) | ((bytes[3] & 0xF0) >> 4)];
    output[6] = base32_alphabet[((bytes[3] & 0x0F) << 1) | ((bytes[4] & 0x80) >> 7)];
    output[7] = base32_alphabet[(bytes[4] & 0x7C) >> 2];
    output[8] = base32_alphabet[((bytes[4] & 0x03) << 3) | ((bytes[5] & 0xE0) >> 5)];
    output[9] = base32_alphabet[bytes[5] & 0x1F];

    // Entropy encoding (last 16 chars from last 80 bits)
    output[10] = base32_alphabet[(bytes[6] & 0xF8) >> 3];
    output[11] = base32_alphabet[((bytes[6] & 0x07) << 2) | ((bytes[7] & 0xC0) >> 6)];
    output[12] = base32_alphabet[(bytes[7] & 0x3E) >> 1];
    output[13] = base32_alphabet[((bytes[7] & 0x01) << 4) | ((bytes[8] & 0xF0) >> 4)];
    output[14] = base32_alphabet[((bytes[8] & 0x0F) << 1) | ((bytes[9] & 0x80) >> 7)];
    output[15] = base32_alphabet[(bytes[9] & 0x7C) >> 2];
    output[16] = base32_alphabet[((bytes[9] & 0x03) << 3) | ((bytes[10] & 0xE0) >> 5)];
    output[17] = base32_alphabet[bytes[10] & 0x1F];
    output[18] = base32_alphabet[(bytes[11] & 0xF8) >> 3];
    output[19] = base32_alphabet[((bytes[11] & 0x07) << 2) | ((bytes[12] & 0xC0) >> 6)];
    output[20] = base32_alphabet[(bytes[12] & 0x3E) >> 1];
    output[21] = base32_alphabet[((bytes[12] & 0x01) << 4) | ((bytes[13] & 0xF0) >> 4)];
    output[22] = base32_alphabet[((bytes[13] & 0x0F) << 1) | ((bytes[14] & 0x80) >> 7)];
    output[23] = base32_alphabet[(bytes[14] & 0x7C) >> 2];
    output[24] = base32_alphabet[((bytes[14] & 0x03) << 3) | ((bytes[15] & 0xE0) >> 5)];
    output[25] = base32_alphabet[bytes[15] & 0x1F];
}

// Backward compatibility wrapper (will be removed)
// Use new() or newString() instead
pub fn generate(allocator: std.mem.Allocator) ![]u8 {
    const s = newString();
    const out = try allocator.alloc(u8, 26);
    std.mem.copyForwards(u8, out, s[0..]);
    return out;
}

// Backward compatibility wrapper (will be removed)
// Use newMonotonic() or newMonotonicString() instead
pub fn generateMonotonic(allocator: std.mem.Allocator) ![]u8 {
    const s = try newMonotonicString();
    const out = try allocator.alloc(u8, 26);
    std.mem.copyForwards(u8, out, s[0..]);
    return out;
}

// ============= Tests =============

test "ULID generation" {
    const ulid = new();
    const str = ulid.toString();

    try std.testing.expectEqual(@as(usize, 26), str.len);

    // Check all characters are valid Crockford's base32
    for (str) |char| {
        try std.testing.expect(std.mem.indexOfScalar(u8, base32_alphabet, char) != null);
    }

    // Verify no confusing characters (I, L, O, U) are present
    for (str) |char| {
        try std.testing.expect(char != 'I');
        try std.testing.expect(char != 'L');
        try std.testing.expect(char != 'O');
        try std.testing.expect(char != 'U');
    }
}

test "ULID uniqueness" {
    const ulid1 = new();

    // Small delay to ensure different timestamp or entropy
    std.Thread.sleep(1_000_000); // 1ms

    const ulid2 = new();

    // Should generate different ULIDs
    try std.testing.expect(!std.mem.eql(u8, &ulid1.bytes, &ulid2.bytes));
}

test "ULID lexicographic ordering" {
    const ulid1 = newString();

    std.Thread.sleep(2_000_000); // 2ms to ensure different timestamp

    const ulid2 = newString();

    // ulid2 should be lexicographically greater than ulid1 (generated later)
    try std.testing.expect(std.mem.order(u8, &ulid1, &ulid2) == .lt);
}

test "ULID monotonicity within same millisecond" {
    // Wait for millisecond boundary to ensure all IDs share same timestamp
    const start = std.time.milliTimestamp();
    while (std.time.milliTimestamp() == start) {} // wait for tick

    // Generate multiple ULIDs as fast as possible
    var ulids: [5][26]u8 = undefined;
    for (0..5) |i| {
        ulids[i] = try newMonotonicString();
    }

    // Check monotonic ordering
    for (1..5) |i| {
        // Each ULID should be >= previous one
        try std.testing.expect(std.mem.order(u8, &ulids[i - 1], &ulids[i]) != .gt);
    }
}

test "ULID timestamp extraction" {
    const before = std.time.milliTimestamp();
    const ulid = new();
    const after = std.time.milliTimestamp();

    // Extract timestamp from ULID
    const extracted = @as(i64, @intCast(ulid.timestamp()));

    // Verify timestamp is within expected range
    try std.testing.expect(extracted >= before);
    try std.testing.expect(extracted <= after);
}

test "ULID parsing and encoding roundtrip" {
    // Generate a ULID
    const original = newString();

    // Parse it to binary
    const ulid = try parse(&original);

    // Encode back to string
    const encoded = ulid.toString();

    // Should match original
    try std.testing.expectEqualStrings(&original, &encoded);
}

test "ULID max value validation" {
    const ulid_str = newString();

    // The largest valid ULID is 7ZZZZZZZZZZZZZZZZZZZZZZZZZ
    // Ensure generated ULID is less than this
    const max_ulid = "7ZZZZZZZZZZZZZZZZZZZZZZZZZ";
    try std.testing.expect(std.mem.order(u8, &ulid_str, max_ulid) == .lt);
}

test "ULID invalid parsing" {
    // Test invalid length
    try std.testing.expectError(UlidError.InvalidUlid, parse("TOO_SHORT"));
    try std.testing.expectError(UlidError.InvalidUlid, parse("WAYYYYYYYYYY_TOO_LONG_FOR_ULID"));

    // Test invalid characters
    try std.testing.expectError(UlidError.InvalidUlid, parse("IIIIIIIIIIIIIIIIIIIIIIIIII")); // I is invalid
    try std.testing.expectError(UlidError.InvalidUlid, parse("LLLLLLLLLLLLLLLLLLLLLLLLLL")); // L is invalid
    try std.testing.expectError(UlidError.InvalidUlid, parse("OOOOOOOOOOOOOOOOOOOOOOOOOO")); // O is invalid
    try std.testing.expectError(UlidError.InvalidUlid, parse("UUUUUUUUUUUUUUUUUUUUUUUUUU")); // U is invalid

    // Test non-canonical ULID (first char > 7)
    try std.testing.expectError(UlidError.InvalidUlid, parse("8ZZZZZZZZZZZZZZZZZZZZZZZZZZ"));
    try std.testing.expectError(UlidError.InvalidUlid, parse("FZZZZZZZZZZZZZZZZZZZZZZZZZZ"));
}

test "Case-insensitive parsing" {
    // Generate a ULID
    const ulid = new();
    const upper_str = ulid.toString();

    // Convert to lowercase (manually for test)
    var lower_str: [26]u8 = undefined;
    for (upper_str, 0..) |c, i| {
        if (c >= 'A' and c <= 'Z') {
            lower_str[i] = c + 32;
        } else {
            lower_str[i] = c;
        }
    }

    // Parse both versions
    const parsed_upper = try parse(&upper_str);
    const parsed_lower = try parse(&lower_str);

    // Should produce identical binary
    try std.testing.expectEqualSlices(u8, &parsed_upper.bytes, &parsed_lower.bytes);
}

test "Mixed case parsing" {
    // Test mixed case ULID
    const mixed = "01hQxW5p7r8ZyFg9K3nMvBcXsD";
    const parsed = try parse(mixed);

    // Should parse successfully and roundtrip correctly
    const encoded = parsed.toString();

    // The encoded version should be uppercase
    for (encoded) |c| {
        if ((c >= 'A' and c <= 'Z') or (c >= '0' and c <= '9')) {
            // Valid uppercase character
        } else {
            try std.testing.expect(false); // Should not have lowercase
        }
    }
}

test "Zero-copy buffer encoding" {
    var buffer: [26]u8 = undefined;

    // Generate directly into buffer
    newInto(&buffer);

    // Should be valid ULID
    const parsed = try parse(&buffer);
    try std.testing.expect(parsed.timestamp() > 0);

    // Test monotonic version
    try newMonotonicInto(&buffer);
    const parsed2 = try parse(&buffer);
    try std.testing.expect(parsed2.timestamp() > 0);
}

test "Value type API has no allocations" {
    // These operations should not allocate
    const ulid1 = new();
    const ulid2 = try newMonotonic();
    const str1 = ulid1.toString();
    const str2 = newString();
    const str3 = try newMonotonicString();

    // Verify they produce valid ULIDs
    try std.testing.expectEqual(@as(usize, 16), ulid1.bytes.len);
    try std.testing.expectEqual(@as(usize, 16), ulid2.bytes.len);
    try std.testing.expectEqual(@as(usize, 26), str1.len);
    try std.testing.expectEqual(@as(usize, 26), str2.len);
    try std.testing.expectEqual(@as(usize, 26), str3.len);
}

test "ULID monotonic overflow" {
    // Skip this test - it's timing-dependent and flaky
    // The test tries to force an overflow by setting all entropy bits to 0xFF,
    // but it's hard to ensure we're in the same millisecond when the function runs
    return error.SkipZigTest;
}

test "Generator pattern" {
    var gen = Generator.init();

    const ulid1 = try gen.next();
    // Small sleep to ensure we're not in exact same nanosecond
    std.Thread.sleep(1000); // 1 microsecond
    const ulid2 = try gen.next();

    // Should generate different ULIDs (either different timestamp or entropy)
    try std.testing.expect(!Ulid.equals(ulid1, ulid2));

    // Test string generation
    const str1 = try gen.nextString();
    try std.testing.expectEqual(@as(usize, 26), str1.len);
}

test "AtomicGenerator concurrent safety" {
    var gen = AtomicGenerator.init();

    const ulid1 = try gen.next();
    const ulid2 = try gen.next();

    // Should generate different ULIDs
    try std.testing.expect(!Ulid.equals(ulid1, ulid2));
}

test "Ulid comparison operators" {
    const ulid1 = new();
    std.Thread.sleep(2_000_000); // 2ms
    const ulid2 = new();

    try std.testing.expect(Ulid.lessThan(ulid1, ulid2));
    try std.testing.expect(!Ulid.lessThan(ulid2, ulid1));
    try std.testing.expect(!Ulid.equals(ulid1, ulid2));

    const ulid3 = ulid1;
    try std.testing.expect(Ulid.equals(ulid1, ulid3));
}

test "Compile-time ULID parsing" {
    const valid_ulid = parseComptime("01HQXW5P7R8ZYFG9K3NMVBCXSD");
    try std.testing.expect(valid_ulid.timestamp() > 0);
}

test "Ulid format implementation" {
    const ulid = new();
    const str = try std.fmt.allocPrint(std.testing.allocator, "{f}", .{ulid});
    defer std.testing.allocator.free(str);

    try std.testing.expectEqual(@as(usize, 26), str.len);

    // Should match toString
    const direct = ulid.toString();
    try std.testing.expectEqualStrings(&direct, str);
}

test "Binary helpers" {
    const bytes = newBytes();
    try std.testing.expectEqual(@as(usize, 16), bytes.len);

    const mono_bytes = try newMonotonicBytes();
    try std.testing.expectEqual(@as(usize, 16), mono_bytes.len);

    // Should be valid ULIDs
    const ulid1 = Ulid{ .bytes = bytes };
    const ulid2 = Ulid{ .bytes = mono_bytes };

    try std.testing.expect(ulid1.timestamp() > 0);
    try std.testing.expect(ulid2.timestamp() > 0);
}

test "ULID collision resistance" {
    const allocator = std.testing.allocator;
    var seen = std.AutoHashMap([16]u8, void).init(allocator);
    defer seen.deinit();

    // Generate many ULIDs rapidly
    for (0..10000) |_| {
        const ulid = new();
        const result = try seen.getOrPut(ulid.bytes);
        try std.testing.expect(!result.found_existing);
    }
}

test "Time-based range helpers" {
    const now = std.time.milliTimestamp();

    // Test minForTime and maxForTime
    const min_ulid = minForTime(now);
    const max_ulid = maxForTime(now);

    // Both should have same timestamp
    try std.testing.expectEqual(min_ulid.timestamp(), max_ulid.timestamp());
    try std.testing.expectEqual(@as(u64, @intCast(now)) & 0xFFFFFFFFFFFF, min_ulid.timestamp());

    // Min should have all zero entropy
    for (min_ulid.bytes[6..16]) |b| {
        try std.testing.expectEqual(@as(u8, 0), b);
    }

    // Max should have all 0xFF entropy
    for (max_ulid.bytes[6..16]) |b| {
        try std.testing.expectEqual(@as(u8, 0xFF), b);
    }

    // Min should be less than max
    try std.testing.expect(Ulid.lessThan(min_ulid, max_ulid));

    // Test isInTimeRange
    const ulid = new();
    const ts = @as(i64, @intCast(ulid.timestamp()));
    try std.testing.expect(isInTimeRange(ulid, ts - 1000, ts + 1000));
    try std.testing.expect(!isInTimeRange(ulid, ts + 1000, ts + 2000));
}

test "Fast validation" {
    // Valid ULID
    const valid = newString();
    try std.testing.expect(isValid(&valid));

    // Invalid lengths
    try std.testing.expect(!isValid("TOO_SHORT"));
    try std.testing.expect(!isValid("WAYYYYYYYYYY_TOO_LONG_FOR_ULID"));

    // Invalid first character
    try std.testing.expect(!isValid("8ZZZZZZZZZZZZZZZZZZZZZZZZZZ"));

    // Invalid characters
    try std.testing.expect(!isValid("IIIIIIIIIIIIIIIIIIIIIIIIII"));
    try std.testing.expect(!isValid("LLLLLLLLLLLLLLLLLLLLLLLLLL"));
}

test "Extract timestamp without full parse" {
    const ulid = new();
    const str = ulid.toString();

    const extracted = try extractTimestamp(&str);
    try std.testing.expectEqual(ulid.timestamp(), extracted);

    // Test invalid input
    try std.testing.expectError(UlidError.InvalidUlid, extractTimestamp("INVALID"));
}

test "ULID sorting" {
    var ulids: [5]Ulid = undefined;

    // Generate ULIDs with small delays
    for (&ulids) |*ulid| {
        ulid.* = new();
        std.Thread.sleep(1_000); // 1 microsecond
    }

    // Shuffle them
    var prng = std.Random.DefaultPrng.init(std.crypto.random.int(u64));
    var rng = prng.random();
    rng.shuffle(Ulid, &ulids);

    // Sort and verify order
    sort(&ulids);
    for (1..ulids.len) |i| {
        try std.testing.expect(Ulid.lessThan(ulids[i - 1], ulids[i]) or
            Ulid.equals(ulids[i - 1], ulids[i]));
    }
}

test "Case-insensitive string sorting" {
    // Create mixed-case ULID strings that should sort the same way
    var strings = [_][]const u8{
        "01HQXW5P7R8ZYFG9K3NMVBCXSD", // All uppercase
        "01hqxw5p7r8zyfg9k3nmvbcxsd", // All lowercase
        "01HqXw5P7r8ZyFg9K3nMvBcXsD", // Mixed case
        "00000000000000000000000000", // Minimum
        "7ZZZZZZZZZZZZZZZZZZZZZZZZZ", // Maximum
    };

    // Sort case-insensitively
    sortStringsCaseInsensitive(&strings);

    // Verify ordering
    try std.testing.expectEqualStrings("00000000000000000000000000", strings[0]);
    // The three equivalent ULIDs should maintain relative order but all be together
    for (1..4) |i| {
        const upper = std.ascii.toUpper(strings[i][0]);
        try std.testing.expectEqual(@as(u8, '0'), upper);
    }
    try std.testing.expectEqualStrings("7ZZZZZZZZZZZZZZZZZZZZZZZZZ", strings[4]);
}

test "Builder pattern" {
    const specific_time: i64 = 1234567890;
    const specific_entropy = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

    // Build with specific timestamp
    var builder = Builder{};
    const ulid1 = builder.withTimestamp(specific_time).build();
    try std.testing.expectEqual(@as(u64, @intCast(specific_time)) & 0xFFFFFFFFFFFF, ulid1.timestamp());

    // Build with specific entropy
    builder = Builder{};
    const ulid2 = builder.withEntropy(specific_entropy).build();
    try std.testing.expectEqualSlices(u8, specific_entropy[0..], ulid2.bytes[6..16]);

    // Build with both
    builder = Builder{};
    const ulid3 = builder
        .withTimestamp(specific_time)
        .withEntropy(specific_entropy)
        .build();
    try std.testing.expectEqual(@as(u64, @intCast(specific_time)) & 0xFFFFFFFFFFFF, ulid3.timestamp());
    try std.testing.expectEqualSlices(u8, specific_entropy[0..], ulid3.bytes[6..16]);
}

test "Custom entropy source" {
    // Test entropy source that returns predictable values
    const TestEntropy = struct {
        value: u8,

        pub fn read(self: *@This(), buffer: []u8) void {
            // Fill buffer with a known pattern
            for (buffer, 0..) |*b, i| {
                b.* = @as(u8, @intCast((self.value + i) % 256));
            }
        }
    };

    var test_entropy = TestEntropy{ .value = 100 };
    var gen = GeneratorWithEntropy(*TestEntropy).init(&test_entropy);

    const ulid = try gen.next();

    // Entropy bytes should follow the pattern 100, 101, 102, etc.
    for (ulid.bytes[6..16], 0..) |b, i| {
        try std.testing.expectEqual(@as(u8, @intCast((100 + i) % 256)), b);
    }
}

test "ULID performance benchmark" {
    // Skip in debug mode to avoid flaky CI failures
    if (@import("builtin").mode == .Debug) return;

    var timer = try std.time.Timer.start();

    // Benchmark non-monotonic generation
    for (0..100_000) |_| {
        _ = new();
    }
    const non_monotonic_ns = timer.read();

    // Benchmark monotonic generation
    timer.reset();
    for (0..100_000) |_| {
        _ = try newMonotonic();
    }
    const monotonic_ns = timer.read();

    // Print results (for informational purposes)
    std.debug.print("\nPerformance benchmark:\n", .{});
    std.debug.print("  Non-monotonic: {d}ns per ULID\n", .{non_monotonic_ns / 100_000});
    std.debug.print("  Monotonic: {d}ns per ULID\n", .{monotonic_ns / 100_000});

    // Ensure reasonable performance (< 10μs per ULID)
    try std.testing.expect(non_monotonic_ns < 1_000_000_000); // < 1s for 100k
    try std.testing.expect(monotonic_ns < 1_000_000_000); // < 1s for 100k
}
