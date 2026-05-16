# SPDX-FileCopyrightText: 2026 Daniel Sampliner <samplinerD@gmail.com>
#
# SPDX-License-Identifier: GPL-2.0-only

FROM docker.io/library/ubuntu:jammy 

RUN apt-get update
RUN apt-get install -y \
	libbpf-dev \
	libelf-dev \
	linux-tools-generic \
	pkg-config \
	wget \
	xz-utils \
	zlib1g-dev \
	;

RUN mkdir -p /opt/zig \
	&& wget --no-verbose -O- https://ziglang.org/download/0.15.2/zig-x86_64-linux-0.15.2.tar.xz \
		| tar -xJf - -C /opt/zig --strip-components=1
ENV PATH=/opt/zig:${PATH}

COPY ./ /code
ADD https://raw.githubusercontent.com/iovisor/bcc/refs/tags/v0.29.1/libbpf-tools/x86/vmlinux_518.h /code/vmlinux.h

WORKDIR /code
RUN set -x \
	&& for b in /usr/lib/linux-tools/*/bpftool; do \
		if [ -e "$b" ]; then \
			export PATH=${b%/*}:$PATH \
			&& break \
		; fi \
	; done \
	&& zig build --release --summary all --verbose "-Dinclude-dir=$PWD"
