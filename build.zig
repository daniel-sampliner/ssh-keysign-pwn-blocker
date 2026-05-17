// SPDX-FileCopyrightText: 2026 Daniel Sampliner <samplinerD@gmail.com>
//
// SPDX-License-Identifier: GPL-2.0-only

const std = @import("std");

const fake_path: std.Build.LazyPath = .{ .cwd_relative = "/homeless-shelter" };

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseFast });

    const install_all = b.option(bool, "install-all", "Install all build artifacts") orelse false;
    const link_mode = b.option(std.builtin.LinkMode, "link-mode", "Preferred link mode for libraries") orelse .static;
    const vmlinux_dir: std.Build.LazyPath = b.option(std.Build.LazyPath, "vmlinux-dir", "Directory containining vmlinux.h header") orelse
        if (b.lazyDependency("bcc", .{})) |dep|
            dep.path(b.pathJoin(&.{ "libbpf-tools", switch (target.result.cpu.arch) {
                .x86_64 => "x86",
                else => |arch| @tagName(arch),
            } }))
        else
            fake_path;

    const deps = .{
        .lazy = .{
            .libbpf = b.lazyDependency("libbpf", .{ .target = target, .optimize = optimize }),
        },
    };

    const options = .{
        .target = target,
        .optimize = optimize,

        .install_all = install_all,
        .link_mode = link_mode,
        .vmlinux_dir = vmlinux_dir,

        .deps = deps,
    };

    const bpf = build_bpf_program(b, options);
    const bpf_skeleton_header = generate_bpf_skeleton_header(b, bpf, options);
    const loader = build_loader(b, bpf_skeleton_header, options);

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

    build_exploit(b, options);
}

fn build_bpf_program(b: *std.Build, options: anytype) *std.Build.Step.Compile {
    const target = b.resolveTargetQuery(.{
        .cpu_arch = switch (options.target.result.cpu.arch.endian()) {
            .big => .bpfeb,
            .little => .bpfel,
        },
        .os_tag = .freestanding,
    });

    const obj = b.addObject(.{
        .name = "ptrace_no_mm",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = .ReleaseFast,
            .unwind_tables = .none,
            .strip = false,
        }),
    });
    obj.root_module.addCSourceFile(.{ .file = b.path("src/ptrace_no_mm.bpf.c") });
    obj.root_module.addIncludePath(options.vmlinux_dir);

    switch (options.link_mode) {
        .static => if (options.deps.lazy.libbpf) |dep|
            obj.root_module.include_dirs.append(
                b.allocator,
                .{ .other_step = dep.artifact("bpf") },
            ) catch @panic("OOM"),
        .dynamic => obj.root_module.addSystemIncludePath(.{ .cwd_relative = "/usr/include" }),
    }

    if (options.install_all)
        b.getInstallStep().dependOn(&b.addInstallArtifact(
            obj,
            .{ .dest_dir = .{ .override = .bin } },
        ).step);

    return obj;
}

fn generate_bpf_skeleton_header(b: *std.Build, bpf_program: *std.Build.Step.Compile, options: anytype) std.Build.LazyPath {
    const bpftool = b.findProgram(&.{"bpftool"}, &.{}) catch |err| switch (err) {
        error.FileNotFound => {
            b.getInstallStep().dependOn(&b.addFail("bpftool binary not found in PATH").step);
            return fake_path;
        },
    };

    const cmd = b.addSystemCommand(&.{
        bpftool,
        "gen",
        "skeleton",
    });
    cmd.addArtifactArg(bpf_program);

    const header = cmd.captureStdOut();
    const name = "ptrace_no_mm.skel.h";
    cmd.captured_stdout.?.basename = name;

    if (options.install_all)
        b.getInstallStep().dependOn(&b.addInstallHeaderFile(header, name).step);

    return header;
}

fn build_loader(b: *std.Build, bpf_header: std.Build.LazyPath, options: anytype) *std.Build.Step.Compile {
    const exe = b.addExecutable(.{
        .name = "ptrace_no_mm",
        .root_module = b.createModule(.{
            .target = options.target,
            .optimize = options.optimize,
            .link_libc = true,
        }),
    });
    b.installArtifact(exe);
    exe.root_module.addCSourceFile(.{ .file = b.path("src/loader.c") });
    bpf_header.addStepDependencies(&exe.step);
    exe.root_module.addIncludePath(bpf_header.dirname());

    switch (options.link_mode) {
        .static => if (options.deps.lazy.libbpf) |dep|
            exe.root_module.linkLibrary(dep.artifact("bpf")),
        .dynamic => {
            const args: std.Build.Module.LinkSystemLibraryOptions = .{ .preferred_link_mode = .dynamic };
            exe.root_module.linkSystemLibrary("libbpf", args);
        },
    }

    return exe;
}

fn build_exploit(b: *std.Build, options: anytype) void {
    const exe_options = b.addOptions();
    const attempts = b.option(usize, "exploit-attempts", "Number of times to attempt chage exploit") orelse 500;
    const user = b.option([]const u8, "exploit-user", "User to run 'chage --list' against") orelse "root";
    exe_options.addOption(usize, "attempts", attempts);
    exe_options.addOption([]const u8, "user", user);

    const exe = b.addExecutable(.{
        .name = "chage_pwn",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/chage_pwn.zig"),
            .target = options.target,
            .optimize = options.optimize,
        }),
    });
    exe.root_module.addOptions("config", exe_options);

    const install_step = b.step("install-exploit", "Copy exploit build artifacts to prefix path");
    const install_exe = b.addInstallArtifact(exe, .{});
    install_step.dependOn(&install_exe.step);
    if (options.install_all)
        b.getInstallStep().dependOn(&install_exe.step);

    const run_exploit_step = b.step("run-exploit", "Run the exploit");
    run_exploit_step.dependOn(&b.addRunArtifact(exe).step);
}
