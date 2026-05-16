// SPDX-FileCopyrightText: 2026 Daniel Sampliner <samplinerD@gmail.com>
//
// SPDX-License-Identifier: GPL-2.0-only

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const bpf_target = b.resolveTargetQuery(.{
        .cpu_arch = switch (target.result.cpu.arch.endian()) {
            .big => .bpfeb,
            .little => .bpfel,
        },
        .os_tag = .freestanding,
    });

    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseFast });

    const install_all = b.option(bool, "install-all", "Install all build artifacts") orelse false;

    const include_dirs = b.option([]const std.Build.LazyPath, "include-dir", "Add directory to include search path") orelse blk: {
        const lps = [_]std.Build.LazyPath{
            .{ .cwd_relative = b.fmt("/usr/src/kernels/{s}", .{std.posix.uname().release}) },
        };
        break :blk &lps;
    };

    const system_include_dirs = b.option([]const std.Build.LazyPath, "system-include-dir", "Add directory to SYSTEM include search path") orelse blk: {
        const lps = [_]std.Build.LazyPath{
            .{ .cwd_relative = "/usr/include" },
        };
        break :blk &lps;
    };

    const bpf_object = b.addObject(.{
        .name = "ptrace_no_mm",
        .root_module = b.createModule(.{
            .target = bpf_target,
            .optimize = .ReleaseFast,
            .unwind_tables = .none,
            .strip = false,
        }),
    });
    bpf_object.root_module.addCSourceFile(.{ .file = b.path("src/ptrace_no_mm.bpf.c") });
    for (include_dirs) |dir| {
        bpf_object.root_module.addIncludePath(dir);
    }
    for (system_include_dirs) |dir| {
        bpf_object.root_module.addSystemIncludePath(dir);
    }
    if (install_all)
        b.getInstallStep().dependOn(&b.addInstallArtifact(bpf_object, .{ .dest_dir = .{ .override = .bin } }).step);

    const bpftool = b.findProgram(&.{"bpftool"}, &.{}) catch |err| switch (err) {
        error.FileNotFound => {
            b.getInstallStep().dependOn(&b.addFail("bpftool binary not found in PATH").step);
            return;
        },
    };

    const run_bpftool_gen_skeleton = b.addSystemCommand(&.{
        bpftool,
        "gen",
        "skeleton",
    });
    run_bpftool_gen_skeleton.addArtifactArg(bpf_object);

    b.h_dir = b.pathJoin(&.{ b.install_prefix, "usr/include" });
    const bpf_object_header = run_bpftool_gen_skeleton.captureStdOut();
    run_bpftool_gen_skeleton.captured_stdout.?.basename = "ptrace_no_mm.skel.h";
    if (install_all)
        b.getInstallStep().dependOn(&b.addInstallHeaderFile(bpf_object_header, "ptrace_no_mm.skel.h").step);

    const loader = b.addExecutable(.{
        .name = "ptrace_no_mm",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    loader.root_module.addCSourceFile(.{ .file = b.path("src/loader.c") });
    loader.root_module.addIncludePath(bpf_object_header.dirname());
    for (system_include_dirs) |dir| {
        loader.root_module.addSystemIncludePath(dir);
    }

    const link_mode = b.option(std.builtin.LinkMode, "link-mode", "Preferred link mode for libraries") orelse .static;
    loader.root_module.linkSystemLibrary("libbpf", .{ .preferred_link_mode = link_mode });
    loader.root_module.linkSystemLibrary("libelf", .{ .preferred_link_mode = link_mode });
    loader.root_module.linkSystemLibrary("z", .{ .preferred_link_mode = link_mode });

    b.installArtifact(loader);

    const run_step = b.step("run", "Run the app");

    const run_cmd = b.addRunArtifact(loader);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());

    const sudo_run_step = b.step("sudo-run", "Run the app with sudo");

    const sudo = b.findProgram(&.{"sudo"}, &.{}) catch |err| switch (err) {
        error.FileNotFound => {
            sudo_run_step.dependOn(&b.addFail("sudo binary not found in PATH").step);
            return;
        },
    };

    const sudo_run_cmd = b.addSystemCommand(&.{sudo});
    sudo_run_cmd.addArtifactArg(loader);
    sudo_run_step.dependOn(&sudo_run_cmd.step);
    sudo_run_cmd.step.dependOn(b.getInstallStep());

    const chage_pwn_options = b.addOptions();
    const chage_pwn_attempts = b.option(usize, "chage-pwn-attempts", "Number of times to attempt chage exploit") orelse 500;
    const chage_pwn_user = b.option([]const u8, "chage-pwn-user", "User to run 'chage --list' against") orelse "root";
    chage_pwn_options.addOption(usize, "attempts", chage_pwn_attempts);
    chage_pwn_options.addOption([]const u8, "user", chage_pwn_user);

    const chage_pwn = b.addExecutable(.{
        .name = "chage_pwn",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/chage_pwn.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    chage_pwn.root_module.addOptions("config", chage_pwn_options);

    const build_exploit_step = b.step("install-exploit", "Copy exploit build artifacts to prefix path");
    const install_chage_pwn = b.addInstallArtifact(chage_pwn, .{});
    build_exploit_step.dependOn(&install_chage_pwn.step);
    if (install_all)
        b.getInstallStep().dependOn(&install_chage_pwn.step);

    const run_exploit_step = b.step("run-exploit", "Run the exploit");
    run_exploit_step.dependOn(&b.addRunArtifact(chage_pwn).step);
}
