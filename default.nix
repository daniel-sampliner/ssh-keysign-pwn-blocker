# SPDX-FileCopyrightText: 2026 Daniel Sampliner <samplinerD@gmail.com>
#
# SPDX-License-Identifier: GPL-2.0-only

{
  pkgs ? import <nixpkgs> { },
}:
pkgs.callPackage ./package.nix { }
