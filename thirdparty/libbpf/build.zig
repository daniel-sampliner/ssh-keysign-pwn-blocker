// SPDX-FileCopyrightText: 2026 Daniel Sampliner <samplinerD@gmail.com>
//
// SPDX-License-Identifier: LGPL-2.1-only OR BSD-2-Clause

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const upstream = b.dependency("libbpf", .{});

    const bpf = b.addLibrary(.{
        .name = "bpf",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    b.installArtifact(bpf);
    bpf.root_module.addCSourceFiles(.{
        .root = upstream.path("src"),
        .files = sources,
        .flags = &.{
            "-fno-sanitize=undefined", // offsetof macro triggers undefined behavior
        },
    });
    bpf.root_module.addIncludePath(upstream.path("include"));
    bpf.root_module.addIncludePath(upstream.path("include/uapi"));
    bpf.root_module.addCMacro("_LARGEFILE64_SOURCE", "");
    bpf.root_module.addCMacro("_FILE_OFFSET_BITS", "64");

    bpf.installHeadersDirectory(upstream.path("src"), "bpf", .{ .include_extensions = headers });

    const dep_options = .{ .target = target, .optimize = optimize };
    const elfutils = b.dependency("elfutils", dep_options);
    const zlib = b.dependency("zlib", dep_options);

    bpf.root_module.linkLibrary(elfutils.artifact("elf"));
    bpf.root_module.linkLibrary(zlib.artifact("z"));
}

const sources = &.{
    "bpf.c",
    "bpf_prog_linfo.c",
    "btf.c",
    "btf_dump.c",
    "btf_iter.c",
    "btf_relocate.c",
    "elf.c",
    "features.c",
    "gen_loader.c",
    "hashmap.c",
    "libbpf.c",
    "libbpf_probes.c",
    "libbpf_errno.c",
    "linker.c",
    "netlink.c",
    "nlattr.c",
    "relo_core.c",
    "ringbuf.c",
    "str_error.c",
    "strset.c",
    "usdt.c",
    "zip.c",
};

const headers = &.{
    "bpf.h",
    "bpf_core_read.h",
    "bpf_endian.h",
    "bpf_helper_defs.h",
    "bpf_helpers.h",
    "bpf_tracing.h",
    "btf.h",
    "libbpf.h",
    "libbpf_common.h",
    "libbpf_legacy.h",
    "libbpf_version.h",
    "skel_internal.h",
    "usdt.bpf.h",
};
