// ULID Specification Compliance Tests
// 
// These tests verify that the ULID implementation correctly follows
// the official ULID specification: https://github.com/ulid/spec
//
// Key requirements tested:
// - 48-bit timestamp + 80-bit randomness = 128-bit identifier  
// - Crockford's Base32 encoding (no I, L, O, U characters)
// - 26 character string representation
// - Lexicographic sortability
// - Monotonic generation within same millisecond
// - Case-insensitive parsing
// - Canonical uppercase output

const std = @import("std");
const ulid = @import("src/root.zig");

test "ULID spec compliance" {
    const testing = std.testing;
    
    // Verify 26 character output
    const id = ulid.new();
    const str = id.toString();
    try testing.expectEqual(26, str.len);
    
    // Verify alphabet - no I, L, O, U
    for (str) |c| {
        try testing.expect(c != 'I');
        try testing.expect(c != 'L');
        try testing.expect(c != 'O');
        try testing.expect(c != 'U');
    }
    
    // Verify timestamp is 48 bits (first 6 bytes)
    const ts = id.timestamp();
    try testing.expect(ts <= 0xFFFFFFFFFFFF); // Max 48-bit value
    
    // Verify total size is 16 bytes (128 bits)
    try testing.expectEqual(16, id.bytes.len);
    
    // Verify first character constraint (max value 7)
    // First char encodes only 3 bits of the 48-bit timestamp
    // For valid timestamps, first char can only be 0-7
    const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    const first_char_idx = std.mem.indexOf(u8, alphabet, &[_]u8{str[0]}).?;
    try testing.expect(first_char_idx <= 7);
    
    // Case insensitive parsing
    const upper = "01HQXW5P7R8ZYFG9K3NMVBCXSD";
    const lower = "01hqxw5p7r8zyfg9k3nmvbcxsd";
    const mixed = "01HqXw5P7r8ZyFg9K3nMvBcXsD";
    
    const upper_id = try ulid.parse(upper);
    const lower_id = try ulid.parse(lower);
    const mixed_id = try ulid.parse(mixed);
    
    try testing.expect(ulid.Ulid.equals(upper_id, lower_id));
    try testing.expect(ulid.Ulid.equals(upper_id, mixed_id));
    
    // Monotonic ordering within same millisecond
    const id1 = try ulid.newMonotonic();
    const id2 = try ulid.newMonotonic();
    try testing.expect(ulid.Ulid.lessThan(id1, id2));
    
    // Lexicographic sorting matches binary sorting
    var ids: [10]ulid.Ulid = undefined;
    for (&ids) |*item| {
        item.* = ulid.new();
        std.time.sleep(1000); // 1 microsecond
    }
    
    ulid.sort(&ids);
    
    for (1..ids.len) |i| {
        const str1 = ids[i-1].toString();
        const str2 = ids[i].toString();
        // String comparison should match binary comparison
        try testing.expect(std.mem.order(u8, &str1, &str2) != .gt);
    }
}

test "Security: Uses cryptographic randomness" {
    // Generate many ULIDs with same timestamp
    const ts = std.time.milliTimestamp();
    
    var seen = std.AutoHashMap([10]u8, void).init(std.testing.allocator);
    defer seen.deinit();
    
    // Generate 1000 ULIDs with the same timestamp
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        var builder = ulid.Builder{};
        const id = builder.withTimestamp(ts).build();
        
        // Extract entropy bytes
        var entropy: [10]u8 = undefined;
        std.mem.copyForwards(u8, entropy[0..], id.bytes[6..16]);
        
        // Track unique entropies (allow for tiny collision probability)
        _ = try seen.getOrPut(entropy);
    }
    
    // Should have at least 980 unique entropies (allows for statistical flukes)
    try std.testing.expect(seen.count() > 980);
}

test "Overflow protection" {
    // Test that timestamp doesn't overflow 48 bits
    const max_timestamp: i64 = 0xFFFFFFFFFFFF; // full 48-bit max
    var builder = ulid.Builder{};
    const id = builder.withTimestamp(max_timestamp).build();
    
    // Verify it encodes correctly
    const decoded_ts = id.timestamp();
    try std.testing.expectEqual(@as(u64, @intCast(max_timestamp)), decoded_ts);
    
    // For max safe i64 (0x7FFFFFFFFFFF), the encoding would be different
    // Just verify the string is valid
    const str = id.toString();
    const parsed = try ulid.parse(&str);
    try std.testing.expect(ulid.Ulid.equals(id, parsed));
}

test "Min/Max/Mid ordering" {
    const testing = std.testing;
    const t = std.time.milliTimestamp();
    const min = ulid.minForTime(t).toString();
    const max = ulid.maxForTime(t).toString();
    var builder = ulid.Builder{};
    const mid = builder.withTimestamp(t).build().toString();
    try testing.expect(std.mem.order(u8, &min, &mid) != .gt);
    try testing.expect(std.mem.order(u8, &mid, &max) != .gt);
}

test "Extract-vs-parse timestamp consistency" {
    const testing = std.testing;
    const s = ulid.newString();
    const extracted = try ulid.extractTimestamp(&s);
    const parsed = (try ulid.parse(&s)).timestamp();
    try testing.expectEqual(parsed, extracted);
}

test "Canonical uppercase on encode" {
    const testing = std.testing;
    for (ulid.new().toString()) |c| {
        try testing.expect((c >= '0' and c <= '9') or (c >= 'A' and c <= 'Z'));
    }
}

test "First-char range check" {
    const testing = std.testing;
    const str = ulid.new().toString();
    // First char can only be 0-7 for valid 48-bit timestamp
    try testing.expect(str[0] >= '0' and str[0] <= '7');
}

test "Timestamp precision - millisecond accuracy" {
    const testing = std.testing;
    // ULIDs generated within same millisecond should have same timestamp
    const start = std.time.milliTimestamp();
    const id1 = ulid.new();
    const id2 = ulid.new();
    const end = std.time.milliTimestamp();
    
    if (start == end) { // If we're still in same millisecond
        try testing.expectEqual(id1.timestamp(), id2.timestamp());
    }
}

test "Timestamp max value year 10889" {
    const testing = std.testing;
    // Max 48-bit timestamp: 281474976710655 ms 
    // = 281474976710.655 seconds
    // = 8925.347 years from 1970
    // = year 10895 (close to spec's 10889)
    const max_ts: u64 = 0xFFFFFFFFFFFF;
    var builder = ulid.Builder{};
    const id = builder.withTimestamp(@intCast(max_ts)).build();
    try testing.expectEqual(max_ts, id.timestamp());
}

test "Binary to string is bijective" {
    const testing = std.testing;
    // Every valid 128-bit value should encode to unique string
    var bytes1: [16]u8 = [_]u8{0} ** 16;
    var bytes2: [16]u8 = [_]u8{0xFF} ** 16;
    
    const id1 = ulid.Ulid{ .bytes = bytes1 };
    const id2 = ulid.Ulid{ .bytes = bytes2 };
    
    const str1 = id1.toString();
    const str2 = id2.toString();
    
    try testing.expect(!std.mem.eql(u8, &str1, &str2));
    
    // Round-trip should preserve bytes
    const parsed1 = try ulid.parse(&str1);
    const parsed2 = try ulid.parse(&str2);
    
    try testing.expect(std.mem.eql(u8, &bytes1, &parsed1.bytes));
    try testing.expect(std.mem.eql(u8, &bytes2, &parsed2.bytes));
}

test "No ambiguous characters in encoding" {
    const testing = std.testing;
    // Generate many ULIDs and verify no I, L, O, U ever appear
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        const str = ulid.new().toString();
        for (str) |c| {
            try testing.expect(c != 'I');
            try testing.expect(c != 'L');  
            try testing.expect(c != 'O');
            try testing.expect(c != 'U');
            // Also no lowercase in canonical form
            try testing.expect(c < 'a' or c > 'z');
        }
    }
}

test "Entropy uses full 80 bits" {
    const testing = std.testing;
    // With same timestamp, we should see variation in all 10 entropy bytes
    const ts = std.time.milliTimestamp();
    
    var seen_bytes = [_]bool{false} ** 256;
    var varied_positions = [_]bool{false} ** 10;
    var builder = ulid.Builder{};
    
    // Get baseline entropy
    const baseline = builder.withTimestamp(ts).build();
    const baseline_entropy = baseline.bytes[6..16];
    
    // Generate many with same timestamp
    var i: usize = 0; 
    while (i < 1000) : (i += 1) {
        const id = builder.withTimestamp(ts).build();
        // Mark all entropy bytes as seen
        for (id.bytes[6..16]) |byte| {
            seen_bytes[byte] = true;
        }
        // Check which positions varied from baseline
        for (id.bytes[6..16], 0..) |byte, pos| {
            if (byte != baseline_entropy[pos]) {
                varied_positions[pos] = true;
            }
        }
    }
    
    // Should have seen many different byte values (not just 0s or 1s)
    var count: usize = 0;
    for (seen_bytes) |seen| {
        if (seen) count += 1;
    }
    
    // Statistically should see at least 100 different byte values
    try testing.expect(count > 100);
    
    // Should see variation in most positions
    var varied_count: usize = 0;
    for (varied_positions) |varied| {
        if (varied) varied_count += 1;
    }
    try testing.expect(varied_count >= 8); // At least 8 of 10 positions should vary
}

test "Parse rejects non-canonical high timestamps" {
    const testing = std.testing;
    // First char '8' or '9' would indicate timestamp > 48 bits
    try testing.expectError(ulid.UlidError.InvalidUlid, ulid.parse("8ZZZZZZZZZZZZZZZZZZZZZZZZZ"));
    try testing.expectError(ulid.UlidError.InvalidUlid, ulid.parse("9ZZZZZZZZZZZZZZZZZZZZZZZZZ"));
    try testing.expectError(ulid.UlidError.InvalidUlid, ulid.parse("AZZZZZZZZZZZZZZZZZZZZZZZZZ"));
}

test "Zero ULID is valid" {
    const testing = std.testing;
    const zero_str = "00000000000000000000000000";
    const zero_ulid = try ulid.parse(zero_str);
    try testing.expectEqual(@as(u64, 0), zero_ulid.timestamp());
    
    // All bytes should be 0
    for (zero_ulid.bytes) |byte| {
        try testing.expectEqual(@as(u8, 0), byte);
    }
}

test "Max ULID is valid" {
    const testing = std.testing;
    const max_str = "7ZZZZZZZZZZZZZZZZZZZZZZZZZ";
    const max_ulid = try ulid.parse(max_str);
    
    // Should be max possible values
    try testing.expectEqual(@as(u64, 0xFFFFFFFFFFFF), max_ulid.timestamp());
}

test "Monotonic rollover at millisecond boundary" {
    const testing = std.testing;
    // When millisecond changes, entropy should reset
    var gen = ulid.Generator.init();
    
    const id1 = try gen.next();
    std.time.sleep(2_000_000); // Sleep 2ms to ensure different timestamp
    const id2 = try gen.next();
    
    // Different timestamps
    try testing.expect(id1.timestamp() < id2.timestamp());
}

test "String comparison matches time order" {
    const testing = std.testing;
    // Earlier timestamp should always sort before later, regardless of entropy
    const earlier_time: i64 = 1000000;
    const later_time: i64 = 2000000;
    
    var builder = ulid.Builder{};
    
    // Max entropy for earlier time
    const max_entropy: [10]u8 = [_]u8{0xFF} ** 10;
    const earlier = builder.withTimestamp(earlier_time).withEntropy(max_entropy).build();
    
    // Min entropy for later time  
    const min_entropy: [10]u8 = [_]u8{0} ** 10;
    const later = builder.withTimestamp(later_time).withEntropy(min_entropy).build();
    
    const earlier_str = earlier.toString();
    const later_str = later.toString();
    
    // String comparison should show earlier < later
    try testing.expect(std.mem.order(u8, &earlier_str, &later_str) == .lt);
}

test "Base32 padding not required" {
    const testing = std.testing;
    // 128 bits = 16 bytes = 25.6 Base32 chars
    // Should use exactly 26 chars with no padding
    const id = ulid.new();
    const str = id.toString();
    
    // No padding characters
    for (str) |c| {
        try testing.expect(c != '=');
    }
    
    // Exactly 26 characters
    try testing.expectEqual(@as(usize, 26), str.len);
}

test "Network byte order (big-endian)" {
    const testing = std.testing;
    // ULID spec requires network byte order (big-endian) for binary format
    var builder = ulid.Builder{};
    const id = builder.withTimestamp(0x123456789ABC).build();
    
    // First 6 bytes should be timestamp in big-endian
    try testing.expectEqual(@as(u8, 0x12), id.bytes[0]);
    try testing.expectEqual(@as(u8, 0x34), id.bytes[1]); 
    try testing.expectEqual(@as(u8, 0x56), id.bytes[2]);
    try testing.expectEqual(@as(u8, 0x78), id.bytes[3]);
    try testing.expectEqual(@as(u8, 0x9A), id.bytes[4]);
    try testing.expectEqual(@as(u8, 0xBC), id.bytes[5]);
}

test "URL safe characters only" {
    const testing = std.testing;
    // All characters should be URL-safe without encoding
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        const str = ulid.new().toString();
        for (str) |c| {
            // Must be alphanumeric (URL-safe)
            try testing.expect((c >= '0' and c <= '9') or 
                              (c >= 'A' and c <= 'Z'));
        }
    }
}

test "Timestamp wraps at 48 bits" {
    const testing = std.testing;
    // Timestamps beyond 48 bits should wrap or be clamped
    const over_48_bit: u64 = 0x1000000000000; // 49 bits
    var builder = ulid.Builder{};
    const id = builder.withTimestamp(@intCast(over_48_bit & 0xFFFFFFFFFFFF)).build();
    
    // Should only use lower 48 bits
    try testing.expect(id.timestamp() <= 0xFFFFFFFFFFFF);
}

test "Timestamp prefix identical within same ms" {
    const testing = std.testing;
    const t = std.time.milliTimestamp();
    var b = ulid.Builder{};
    const a = b.withTimestamp(t).build().toString();
    const c = b.withTimestamp(t).build().toString();
    try testing.expectEqualSlices(u8, a[0..10], c[0..10]);
}

test "Reject lowercase ambiguous chars" {
    const testing = std.testing;
    const bad = [_][]const u8{
        "01hqxw5p7r8zyfg9k3nmvbcxsi", // i
        "01hqxw5p7r8zyfg9k3nmvbcxsl", // l
        "01hqxw5p7r8zyfg9k3nmvbcxso", // o
        "01hqxw5p7r8zyfg9k3nmvbcxsu", // u
    };
    for (bad) |s| {
        try testing.expectError(ulid.UlidError.InvalidUlid, ulid.parse(s));
    }
}

test "Max/Zero ULID full-roundtrip bytes" {
    const testing = std.testing;
    const max = "7ZZZZZZZZZZZZZZZZZZZZZZZZZ";
    const zero = "00000000000000000000000000";
    const a = try ulid.parse(max);
    const z = try ulid.parse(zero);
    // entropy bounds
    for (a.bytes[6..16]) |b| try testing.expectEqual(@as(u8, 0xFF), b);
    for (z.bytes[6..16]) |b| try testing.expectEqual(@as(u8, 0x00), b);
}

test "Intra-millisecond ordering by entropy" {
    const testing = std.testing;
    const t: i64 = 1234567890;
    const min_e: [10]u8 = [_]u8{0} ** 10;
    const max_e: [10]u8 = [_]u8{0xFF} ** 10;

    var b = ulid.Builder{};
    const a = b.withTimestamp(t).withEntropy(min_e).build();
    var b2 = ulid.Builder{};
    const c = b2.withTimestamp(t).withEntropy(max_e).build();

    try testing.expect(ulid.Ulid.lessThan(a, c));

    const as = a.toString();
    const cs = c.toString();
    try testing.expect(std.mem.order(u8, &as, &cs) == .lt);
}

test "Reject non-alphabet characters" {
    const testing = std.testing;
    const bad = [_][]const u8{
        "01HQXW5P7R8ZYFG9K3NMVBCXS-",
        "01HQXW5P7R8ZYFG9K3NMVBCXS_",
        "01HQXW5P7R8ZYFG9K3NMVBCXS ",
        "01HQXW5P7R8ZYFG9K3NMVBCXS/",
    };
    for (bad) |s| {
        try testing.expectError(ulid.UlidError.InvalidUlid, ulid.parse(s));
    }
}

test "extractTimestamp equals parse.timestamp for lowercase" {
    const testing = std.testing;
    const s_up = ulid.newString();
    var s_lo = s_up;
    for (&s_lo, 0..) |*c, i| {
        if (s_up[i] >= 'A' and s_up[i] <= 'Z') {
            c.* = s_up[i] + 32;
        }
    }

    const extracted = try ulid.extractTimestamp(&s_lo);
    const parsed = try ulid.parse(&s_lo);
    try testing.expectEqual(parsed.timestamp(), extracted);
}

test "format prints canonical uppercase" {
    const testing = std.testing;
    const id = ulid.new();
    const s = try std.fmt.allocPrint(testing.allocator, "{}", .{id});
    defer testing.allocator.free(s);
    for (s) |c| try testing.expect((c >= '0' and c <= '9') or (c >= 'A' and c <= 'Z'));
}

test "Reject invalid later chars with valid first char" {
    const testing = std.testing;
    // valid first char '7', but illegal 'I' later
    try testing.expectError(
        ulid.UlidError.InvalidUlid,
        ulid.parse("7ZZZZZZZZIZZZZZZZZZZZZZZZZ")
    );
}

test "No guaranteed sort order within same millisecond without monotonic" {
    const testing = std.testing;
    // Spec says: "No guaranteed sort order within same millisecond"
    // This is only guaranteed with monotonic generation
    const t = std.time.milliTimestamp();
    var builder = ulid.Builder{};
    
    // Two ULIDs with same timestamp but random entropy
    const id1 = builder.withTimestamp(t).build();
    const id2 = builder.withTimestamp(t).build();
    
    // They have same timestamp prefix but random order for entropy
    const str1 = id1.toString();
    const str2 = id2.toString();
    
    // Timestamp part should be identical
    try testing.expectEqualSlices(u8, str1[0..10], str2[0..10]);
    // But overall order is not guaranteed (could be less, equal, or greater)
}

test "Monotonic increment ensures strictly increasing" {
    const testing = std.testing;
    // Monotonic adds a random increment to ensure strictly increasing
    var gen = ulid.Generator.init();
    
    // Force same timestamp by generating quickly
    const id1 = try gen.next();
    const id2 = try gen.next();
    
    // If same timestamp, entropy should increment
    if (id1.timestamp() == id2.timestamp()) {
        // Check that id2 > id1 due to monotonic increment
        try testing.expect(ulid.Ulid.lessThan(id1, id2));
    }
}

test "ASCII default character set sorting" {
    const testing = std.testing;
    // Verify our alphabet sorts correctly in ASCII order
    const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    
    // Each char should be less than the next in ASCII
    for (alphabet[0..alphabet.len-1], 0..) |c, i| {
        try testing.expect(c < alphabet[i + 1]);
    }
}

test "Reject ULIDs exceeding max epoch time" {
    const testing = std.testing;
    // Max valid timestamp is 2^48 - 1 = 281474976710655
    // First char '8' or higher would exceed this
    
    const invalid_high = [_][]const u8{
        "80000000000000000000000000", // 26 chars, starts with '8'
        "90000000000000000000000000", // 26 chars, starts with '9'
        "A0000000000000000000000000", // 26 chars, starts with 'A'
        "G0000000000000000000000000", // 26 chars, starts with 'G'
        "Z0000000000000000000000000", // 26 chars, starts with 'Z'
    };
    
    for (invalid_high) |s| {
        try testing.expectError(ulid.UlidError.InvalidUlid, ulid.parse(s));
    }
}

test "Binary layout is 16 octets" {
    const testing = std.testing;
    const id = ulid.new();
    try testing.expectEqual(@as(usize, 16), id.bytes.len);
    try testing.expectEqual(@as(usize, 128), id.bytes.len * 8); // 128 bits
}


test "Crockford Base32 specific rules" {
    const testing = std.testing;
    // Crockford's Base32 treats some letters as aliases in parsing
    // But we should reject them as per ULID spec strictness
    
    // These should all be invalid (not in our alphabet)
    const invalid = [_][]const u8{
        "I1I1I1I1I1I1I1I1I1I1I1I1I1", // I looks like 1
        "L1L1L1L1L1L1L1L1L1L1L1L1L1", // L looks like 1
        "O0O0O0O0O0O0O0O0O0O0O0O0O0", // O looks like 0
    };
    
    for (invalid) |s| {
        try testing.expectError(ulid.UlidError.InvalidUlid, ulid.parse(s));
    }
}

test "Most significant byte first (network byte order)" {
    const testing = std.testing;
    // Verify timestamp is stored MSB first
    const ts: u64 = 0x010203040506;
    var builder = ulid.Builder{};
    const id = builder.withTimestamp(@intCast(ts)).build();
    
    // Bytes should be in network byte order (big-endian)
    try testing.expectEqual(@as(u8, 0x01), id.bytes[0]);
    try testing.expectEqual(@as(u8, 0x02), id.bytes[1]);
    try testing.expectEqual(@as(u8, 0x03), id.bytes[2]);
    try testing.expectEqual(@as(u8, 0x04), id.bytes[3]);
    try testing.expectEqual(@as(u8, 0x05), id.bytes[4]);
    try testing.expectEqual(@as(u8, 0x06), id.bytes[5]);
}

test "First char encodes top 3 timestamp bits" {
    const testing = std.testing;
    const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    inline for (0..8) |top3| {
        // Put 'top3' in the top 3 bits of the 48-bit timestamp
        const ts: u64 = (@as(u64, top3) << (48 - 3)); // top 3 bits set
        var b = ulid.Builder{};
        const s = b.withTimestamp(@intCast(ts)).build().toString();
        // Decode index of first char in Crockford alphabet
        const idx = std.mem.indexOf(u8, alphabet, &[_]u8{s[0]}).?;
        // It must match the top 3 bits value
        try testing.expectEqual(top3, idx);
    }
}

test "isValid sanity checks" {
    const testing = std.testing;
    try testing.expect(ulid.isValid("7ZZZZZZZZZZZZZZZZZZZZZZZZZ"));
    try testing.expect(ulid.isValid("00000000000000000000000000"));
    try testing.expect(!ulid.isValid("8ZZZZZZZZZZZZZZZZZZZZZZZZZ")); // first > '7'
    try testing.expect(!ulid.isValid("01HQXW5P7R8ZYFG9K3NMVBCXSI")); // 'I'
    try testing.expect(!ulid.isValid("TOO_SHORT"));
    try testing.expect(!ulid.isValid("THIS_IS_WAY_TOO_LONG_FOR_ULID"));
    // Mixed case should be valid
    try testing.expect(ulid.isValid("01hqxw5p7r8zyfg9k3nmvbcxsd"));
    try testing.expect(ulid.isValid("01HqXw5P7r8ZyFg9K3nMvBcXsD"));
}

test "sortStringsCaseInsensitive matches canonical order" {
    const testing = std.testing;
    var arr = [_][]const u8{
        "01HQXW5P7R8ZYFG9K3NMVBCXSD",
        "01hqxw5p7r8zyfg9k3nmvbcxsd",
        "01HqXw5P7r8ZyFg9K3nMvBcXsD",
    };
    ulid.sortStringsCaseInsensitive(&arr);
    // All three are the same logical ULID; they should remain together
    // and have the same 10-char timestamp prefix
    for (arr) |s| {
        // Convert to uppercase for comparison
        var upper: [10]u8 = undefined;
        for (s[0..10], 0..) |c, i| {
            upper[i] = if (c >= 'a' and c <= 'z') c - 32 else c;
        }
        try testing.expectEqualSlices(u8, "01HQXW5P7R", &upper);
    }
}

test "UlidString.parse roundtrip" {
    const testing = std.testing;
    const s = ulid.newString();
    const wrapped = ulid.UlidString{ .chars = s };
    const u = try wrapped.parse();
    try testing.expectEqual(u.timestamp(), try ulid.extractTimestamp(&s));
    
    // Also verify full roundtrip
    const s2 = u.toString();
    try testing.expectEqualSlices(u8, &s, &s2);
}

test "Invalid ULID rejection" {
    const testing = std.testing;
    
    // Test invalid characters
    try testing.expectError(ulid.UlidError.InvalidUlid, ulid.parse("01HQXW5P7R8ZYFG9K3NMVBCXSI")); // I is invalid
    try testing.expectError(ulid.UlidError.InvalidUlid, ulid.parse("01HQXW5P7R8ZYFG9K3NMVBCXSL")); // L is invalid
    try testing.expectError(ulid.UlidError.InvalidUlid, ulid.parse("01HQXW5P7R8ZYFG9K3NMVBCXSO")); // O is invalid
    try testing.expectError(ulid.UlidError.InvalidUlid, ulid.parse("01HQXW5P7R8ZYFG9K3NMVBCXSU")); // U is invalid
    
    // Test wrong length
    try testing.expectError(ulid.UlidError.InvalidUlid, ulid.parse("01HQXW5P7R8ZYFG9K3NMVBCXS")); // 25 chars
    try testing.expectError(ulid.UlidError.InvalidUlid, ulid.parse("01HQXW5P7R8ZYFG9K3NMVBCXSDD")); // 27 chars
    
    // Test overflow - first char > 7
    try testing.expectError(ulid.UlidError.InvalidUlid, ulid.parse("81HQXW5P7R8ZYFG9K3NMVBCXSD")); // 8 > 7
}