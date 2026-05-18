/*
 * SPDX-FileCopyrightText: 2026 Daniel Sampliner <samplinerD@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#define _GNU_SOURCE

#include <bpf/libbpf.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "ptrace_no_mm.skel.h"

void signal_handler(int sig) {
  fprintf(stderr, "%s\n", sigabbrev_np(sig));
}

int main(void) {
  struct ptrace_no_mm* skel = NULL;
  int err;

  struct sigaction sa = {.sa_handler = signal_handler, .sa_flags = 0};
  sigemptyset(&sa.sa_mask);

  if (sigaction(SIGINT, &sa, NULL) != 0) {
    perror("failed to ignore SIGINT");
    return 1;
  }

  if (sigaction(SIGTERM, &sa, NULL) != 0) {
    perror("failed to ignore SIGTERM");
    return 1;
  }

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
