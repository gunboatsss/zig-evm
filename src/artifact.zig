//! Catalog of `forge build` artifacts for `vm.getCode` / `vm.deployCode`.
//! Loaded once per forge-test run. Lookups do not allocate.

const std = @import("std");
const limits = @import("limits.zig");

pub const Entry = struct {
    file_off: u32,
    file_len: u32,
    contract_off: u32,
    contract_len: u32,
    path_off: u32,
    path_len: u32,
    creation_off: u32,
    creation_len: u32,
    deployed_off: u32,
    deployed_len: u32,
};

pub const Store = struct {
    entries: [limits.forge_artifacts_max]Entry,
    count: u32,
    names: [limits.forge_name_pool_bytes_max]u8,
    names_used: u32,
    code: [limits.forge_code_pool_bytes_max]u8,
    code_used: u32,

    pub fn init(self: *Store) void {
        self.count = 0;
        self.names_used = 0;
        self.code_used = 0;
    }

    pub fn load(self: *Store, allocator: std.mem.Allocator, io: std.Io, dir_path: []const u8) !void {
        var dir = try std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true });
        defer dir.close(io);
        var walker = try dir.walk(allocator);
        defer walker.deinit();
        while (try walker.next(io)) |entry| {
            if (!is_artifact_file(entry)) continue;
            const bytes = try entry.dir.readFileAlloc(
                io,
                entry.basename,
                allocator,
                .limited(limits.forge_artifact_bytes_max),
            );
            defer allocator.free(bytes);
            self.add_json(allocator, entry.path, bytes) catch continue;
        }
    }

    pub fn put(
        self: *Store,
        file: []const u8,
        contract: []const u8,
        path: []const u8,
        creation: []const u8,
        deployed: []const u8,
    ) !void {
        if (self.count >= limits.forge_artifacts_max) return error.ArtifactLimit;
        const file_span = try self.intern_name(file);
        const contract_span = try self.intern_name(contract);
        const path_span = try self.intern_name(path);
        const creation_span = try self.intern_code(creation);
        const deployed_span = try self.intern_code(deployed);
        self.entries[self.count] = .{
            .file_off = file_span.off,
            .file_len = file_span.len,
            .contract_off = contract_span.off,
            .contract_len = contract_span.len,
            .path_off = path_span.off,
            .path_len = path_span.len,
            .creation_off = creation_span.off,
            .creation_len = creation_span.len,
            .deployed_off = deployed_span.off,
            .deployed_len = deployed_span.len,
        };
        self.count += 1;
    }

    pub fn creation_of(self: *const Store, query: []const u8) ?[]const u8 {
        const index = self.lookup(query) orelse return null;
        const e = self.entries[index];
        return self.code_slice(e.creation_off, e.creation_len);
    }

    pub fn deployed_of(self: *const Store, query: []const u8) ?[]const u8 {
        const index = self.lookup(query) orelse return null;
        const e = self.entries[index];
        return self.code_slice(e.deployed_off, e.deployed_len);
    }

    fn lookup(self: *const Store, query: []const u8) ?u32 {
        if (query.len == 0) return null;
        if (self.match_path(query)) |index| return index;
        const file, const contract = split_query(query);
        var found: ?u32 = null;
        var hits: u32 = 0;
        var index: u32 = 0;
        while (index < self.count) : (index += 1) {
            if (!self.matches(index, file, contract)) continue;
            hits += 1;
            found = index;
        }
        if (hits == 1) return found;
        return null;
    }

    fn match_path(self: *const Store, query: []const u8) ?u32 {
        var index: u32 = 0;
        while (index < self.count) : (index += 1) {
            const path = self.name_slice(self.entries[index].path_off, self.entries[index].path_len);
            if (std.mem.eql(u8, path, query)) return index;
            if (std.mem.endsWith(u8, path, query)) return index;
        }
        return null;
    }

    fn matches(self: *const Store, index: u32, file: []const u8, contract: []const u8) bool {
        const e = self.entries[index];
        const have_file = self.name_slice(e.file_off, e.file_len);
        const have_contract = self.name_slice(e.contract_off, e.contract_len);
        if (!std.mem.eql(u8, have_contract, contract)) return false;
        if (file.len == 0) return true;
        if (std.mem.eql(u8, have_file, file)) return true;
        return std.mem.eql(u8, have_file, basename(file));
    }

    fn intern_name(self: *Store, bytes: []const u8) !struct { off: u32, len: u32 } {
        const len: u32 = @intCast(bytes.len);
        if (self.names_used + len > self.names.len) return error.NamePool;
        const off = self.names_used;
        if (len > 0) @memcpy(self.names[off .. off + len], bytes);
        self.names_used += len;
        return .{ .off = off, .len = len };
    }

    fn intern_code(self: *Store, bytes: []const u8) !struct { off: u32, len: u32 } {
        const len: u32 = @intCast(bytes.len);
        if (len == 0) return .{ .off = 0, .len = 0 };
        if (self.code_used + len > self.code.len) return error.CodePool;
        const off = self.code_used;
        @memcpy(self.code[off .. off + len], bytes);
        self.code_used += len;
        return .{ .off = off, .len = len };
    }

    fn parse_code(self: *Store, hex: []const u8) ![]const u8 {
        const len = try hex_byte_len(hex);
        if (self.code_used + len > self.code.len) return error.CodePool;
        const off = self.code_used;
        _ = try parse_hex_into(hex, self.code[off..]);
        self.code_used += len;
        return self.code[off .. off + len];
    }

    fn code_span(bytes: []const u8, pool: []const u8) struct { off: u32, len: u32 } {
        if (bytes.len == 0) return .{ .off = 0, .len = 0 };
        const off: u32 = @intCast(@intFromPtr(bytes.ptr) - @intFromPtr(pool.ptr));
        return .{ .off = off, .len = @intCast(bytes.len) };
    }

    fn name_slice(self: *const Store, off: u32, len: u32) []const u8 {
        if (len == 0) return self.names[0..0];
        return self.names[off .. off + len];
    }

    fn code_slice(self: *const Store, off: u32, len: u32) []const u8 {
        if (len == 0) return self.code[0..0];
        return self.code[off .. off + len];
    }

    fn add_json(self: *Store, allocator: std.mem.Allocator, path: []const u8, json: []const u8) !void {
        var parsed = try std.json.parseFromSlice(JsonArtifact, allocator, json, .{
            .ignore_unknown_fields = true,
        });
        defer parsed.deinit();
        const creation_hex = parsed.value.bytecode.object;
        if (creation_hex.len == 0 or is_empty_hex(creation_hex)) return;
        if (std.mem.indexOf(u8, creation_hex, "__") != null) return;
        const creation = self.parse_code(creation_hex) catch return;
        const deployed_hex = parsed.value.deployedBytecode.object;
        const deployed = if (deployed_hex.len == 0 or is_empty_hex(deployed_hex))
            self.code[0..0]
        else
            self.parse_code(deployed_hex) catch self.code[0..0];
        const file, const contract = file_and_contract(path);
        const file_span = try self.intern_name(file);
        const contract_span = try self.intern_name(contract);
        const path_span = try self.intern_name(path);
        const creation_span = code_span(creation, self.code[0..]);
        const deployed_span = code_span(deployed, self.code[0..]);
        if (self.count >= limits.forge_artifacts_max) return error.ArtifactLimit;
        self.entries[self.count] = .{
            .file_off = file_span.off,
            .file_len = file_span.len,
            .contract_off = contract_span.off,
            .contract_len = contract_span.len,
            .path_off = path_span.off,
            .path_len = path_span.len,
            .creation_off = creation_span.off,
            .creation_len = creation_span.len,
            .deployed_off = deployed_span.off,
            .deployed_len = deployed_span.len,
        };
        self.count += 1;
    }
};

const JsonBytecode = struct {
    object: []const u8 = "",
};

const JsonArtifact = struct {
    bytecode: JsonBytecode = .{},
    deployedBytecode: JsonBytecode = .{},
};

pub fn is_artifact_file(entry: std.Io.Dir.Walker.Entry) bool {
    if (entry.kind != .file) return false;
    if (!std.mem.endsWith(u8, entry.basename, ".json")) return false;
    if (std.mem.endsWith(u8, entry.basename, ".dbg.json")) return false;
    if (std.mem.indexOf(u8, entry.path, "build-info") != null) return false;
    return true;
}

fn split_query(query: []const u8) struct { []const u8, []const u8 } {
    const colon = std.mem.lastIndexOfScalar(u8, query, ':') orelse {
        if (std.mem.endsWith(u8, query, ".sol")) return .{ query, stem(basename(query)) };
        return .{ "", query };
    };
    return .{ query[0..colon], query[colon + 1 ..] };
}

fn file_and_contract(path: []const u8) struct { []const u8, []const u8 } {
    const contract = stem(basename(path));
    const parent = dirname(path);
    return .{ basename(parent), contract };
}

fn basename(path: []const u8) []const u8 {
    if (std.mem.lastIndexOfScalar(u8, path, '/')) |slash| return path[slash + 1 ..];
    return path;
}

fn dirname(path: []const u8) []const u8 {
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return "";
    return path[0..slash];
}

fn stem(name: []const u8) []const u8 {
    const dot = std.mem.lastIndexOfScalar(u8, name, '.') orelse return name;
    if (dot == 0) return name;
    return name[0..dot];
}

fn is_empty_hex(text: []const u8) bool {
    return std.mem.eql(u8, text, "0x") or std.mem.eql(u8, text, "0X");
}

fn hex_byte_len(text: []const u8) !u32 {
    var trimmed = text;
    if (trimmed.len >= 2 and trimmed[0] == '0' and (trimmed[1] == 'x' or trimmed[1] == 'X')) {
        trimmed = trimmed[2..];
    }
    if (trimmed.len % 2 != 0) return error.InvalidHex;
    return @intCast(trimmed.len / 2);
}

fn parse_hex_into(text: []const u8, out: []u8) !u32 {
    var trimmed = text;
    if (trimmed.len >= 2 and trimmed[0] == '0' and (trimmed[1] == 'x' or trimmed[1] == 'X')) {
        trimmed = trimmed[2..];
    }
    if (trimmed.len % 2 != 0) return error.InvalidHex;
    const n = trimmed.len / 2;
    if (n > out.len) return error.HexTooLong;
    var index: u32 = 0;
    while (index < n) : (index += 1) {
        out[index] = try std.fmt.parseInt(u8, trimmed[index * 2 .. index * 2 + 2], 16);
    }
    return @intCast(n);
}

test "lookup src path and contract name" {
    const store = try std.testing.allocator.create(Store);
    defer std.testing.allocator.destroy(store);
    store.init();
    const code = [_]u8{ 0x60, 0x00, 0xf3 };
    try store.put("Counter.sol", "Counter", "Counter.sol/Counter.json", &code, &code);
    try std.testing.expectEqualSlices(u8, &code, store.creation_of("src/Counter.sol:Counter").?);
    try std.testing.expectEqualSlices(u8, &code, store.creation_of("Counter.sol:Counter").?);
    try std.testing.expectEqualSlices(u8, &code, store.creation_of("Counter").?);
    try std.testing.expectEqualSlices(u8, &code, store.creation_of("Counter.sol/Counter.json").?);
    try std.testing.expect(store.creation_of("Missing") == null);
}
