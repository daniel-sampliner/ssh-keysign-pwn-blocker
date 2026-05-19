// SPDX-FileCopyrightText: 2026 Daniel Sampliner <samplinerD@gmail.com>
//
// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0-only

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const upstream = b.dependency("libcap", .{});
    const src = upstream.path("libcap");

    const cap_names_h = genCapNamesH(b, target, optimize, src);

    const cap = b.addLibrary(.{
        .name = "cap",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    cap.root_module.addCSourceFiles(.{
        .root = src,
        .files = capfiles,
    });
    cap.root_module.addIncludePath(cap_names_h.dirname());
    cap.root_module.addSystemIncludePath(src.path(b, "include"));
    cap.root_module.addCMacro("LIBPSX_PTHREAD_LINKAGE", "");

    b.installArtifact(cap);
    cap.installHeadersDirectory(
        src.path(b, "include/sys"),
        "sys",
        .{ .include_extensions = &.{"capability.h"} },
    );
}

fn genCapNamesH(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, src: std.Build.LazyPath) std.Build.LazyPath {
    const exe = b.addExecutable(.{
        .name = "_makenames",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    exe.root_module.addCSourceFiles(.{
        .root = src,
        .files = &.{"_makenames.c"},
    });

    if (genCapNamesListH(b, src, &exe.step)) |header|
        exe.root_module.addIncludePath(header.dirname())
    else |_|
        _ = {};

    const run = b.addRunArtifact(exe);
    const stdout = run.captureStdOut();
    run.captured_stdout.?.basename = "cap_names.h";
    return stdout;
}

fn genCapNamesListH(b: *std.Build, src: std.Build.LazyPath, asking_step: ?*std.Build.Step) !std.Build.LazyPath {
    const step = asking_step orelse b.getInstallStep();

    const maybe_sh = findProgram(b, "sh", step);
    const maybe_grep = findProgram(b, "grep", step);
    const maybe_sed = findProgram(b, "sed", step);

    errdefer step.dependOn(&b.addFail("failed to generate cap_names.list.h").step);

    const sh = try maybe_sh;
    const grep = try maybe_grep;
    const sed = try maybe_sed;

    const cmd = b.addSystemCommand(&.{
        sh,
        "-c",
        \\grep=$1
        \\sed=$2
        \\"$grep" -E '^#define\s+CAP_([^\s]+)\s+[0-9]+\s*$' \
        \\| "$sed" \
        \\  -e 's/^#define\s\+/{"/' \
        \\  -e 's/\s*$/},/' \
        \\  -e 's/\s\+/",/' \
        \\  -e 'y/ABCDEFGHIJKLMNOPQRSTUVWXYZ/abcdefghijklmnopqrstuvwxyz/'
        ,
        "sh",
        grep,
        sed,
    });
    cmd.setStdIn(.{ .lazy_path = src.path(b, "include/uapi/linux/capability.h") });
    const stdout = cmd.captureStdOut();
    cmd.captured_stdout.?.basename = "cap_names.list.h";
    return stdout;
}

fn findProgram(b: *std.Build, name: []const u8, asking_step: ?*std.Build.Step) ![]const u8 {
    const step = asking_step orelse b.getInstallStep();
    return b.findProgram(&.{name}, &.{}) catch |err| switch (err) {
        error.FileNotFound => {
            step.dependOn(&b.addFail(b.fmt("{s} binary not found", .{name})).step);
            return err;
        },
    };
}

const capfiles = &.{
    "cap_alloc.c",
    "cap_extint.c",
    "cap_file.c",
    "cap_flag.c",
    "cap_proc.c",
    "cap_syscalls.c",
    "cap_text.c",
};
