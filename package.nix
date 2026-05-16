# SPDX-FileCopyrightText: 2026 Daniel Sampliner <samplinerD@gmail.com>
#
# SPDX-License-Identifier: GPL-2.0-only

{
  bcc,
  bpftools,
  elfutils,
  lib,
  libbpf,
  pkg-config,
  stdenv,
  zig,
  zlib,
}:
stdenv.mkDerivation {
  pname = "ssh-keysign-pwn-blocker";
  version = "0.0.1";

  src =
    lib.pipe
      [ ./build.zig ./build.zig.zon ./src ]
      [
        lib.fileset.unions
        (
          fs:
          lib.fileset.toSource {
            root = ./.;
            fileset = fs;
          }
        )
      ];

  nativeBuildInputs = [
    bpftools
    pkg-config
    zig.hook
  ];

  buildInputs = [
    elfutils
    libbpf
    zlib
  ];

  zigBuildFlags = [
    "-Dinclude-dir=${bcc.src}/libbpf-tools/x86"
    "-Dinclude-dir=${libbpf}/include"
    "-Dlink-mode=dynamic"
  ];
}
