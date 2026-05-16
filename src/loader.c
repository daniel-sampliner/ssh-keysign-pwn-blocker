/*
 * SPDX-FileCopyrightText: 2026 Daniel Sampliner <samplinerD@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <bpf/libbpf.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

#include "ptrace_no_mm.skel.h"

static volatile sig_atomic_t exiting = 0;

static void handle_signal(int sig) {
  exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char* format,
                           va_list args) {
  return vfprintf(stderr, format, args);
}

int main(void) {
  struct ptrace_no_mm* skel = NULL;
  int err;

  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);

  libbpf_set_print(libbpf_print_fn);
  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

  skel = ptrace_no_mm__open();
  if (!skel) {
    fprintf(stderr, "failed to open BPF skeleton\n");
    return 1;
  }

  err = ptrace_no_mm__load(skel);
  if (err) {
    fprintf(stderr, "failed to load BPF skeleton: %d\n", err);
    goto cleanup;
  }

  err = ptrace_no_mm__attach(skel);
  if (err) {
    fprintf(stderr, "failed to attach BPF skeleton: %d\n", err);
    goto cleanup;
  }

  printf("BPF LSM program attached.\n");
  printf("Blocking ptrace_access_check when child->mm == NULL.\n");
  printf("Press Ctrl-C to exit.\n");

  pause();

  printf("Exiting.\n");

cleanup:
  ptrace_no_mm__destroy(skel);
  return err != 0;
}
