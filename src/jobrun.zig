//! Parallel JSON fixture walking for `jsontest` / `chaintest`.

const std = @import("std");

pub fn resolve_jobs(jobs: u32) u32 {
    if (jobs != 0) return jobs;
    const n = std.Thread.getCpuCount() catch 1;
    return @max(1, @as(u32, @intCast(n)));
}

pub fn collect_json_files(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir_path: []const u8,
) ![][]const u8 {
    var dir = try std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true });
    defer dir.close(io);
    var walker = try dir.walk(allocator);
    defer walker.deinit();
    var list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (list.items) |path| allocator.free(path);
        list.deinit(allocator);
    }
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.basename, ".json")) continue;
        const path = try std.mem.concat(allocator, u8, &.{ dir_path, "/", entry.path });
        try list.append(allocator, path);
    }
    return try list.toOwnedSlice(allocator);
}

pub fn free_paths(allocator: std.mem.Allocator, paths: [][]const u8) void {
    for (paths) |path| allocator.free(path);
    allocator.free(paths);
}

pub const Mutex = std.c.pthread_mutex_t;
pub const mutex_init: Mutex = std.c.PTHREAD_MUTEX_INITIALIZER;

pub fn lock(m: *Mutex) void {
    _ = std.c.pthread_mutex_lock(m);
}

pub fn unlock(m: *Mutex) void {
    _ = std.c.pthread_mutex_unlock(m);
}
