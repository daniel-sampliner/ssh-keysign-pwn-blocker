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
#include <sys/capability.h>
#include <unistd.h>

#include "ptrace_no_mm.skel.h"

void signal_handler(int sig) {
  fprintf(stderr, "%s\n", sigabbrev_np(sig));
}

int signal_init(void) {
  struct sigaction sa = {.sa_handler = signal_handler, .sa_flags = 0};
  sigemptyset(&sa.sa_mask);
  int ret;

  ret = sigaction(SIGINT, &sa, NULL) != 0;
  if (ret) {
    perror("failed to ignore SIGINT");
    return ret;
  }

  ret = sigaction(SIGTERM, &sa, NULL) != 0;
  if (ret) {
    perror("failed to ignore SIGTERM");
    return ret;
  }

  return 0;
}

int acquire_capabilities(void) {
  cap_t caps = cap_get_proc();
  const cap_value_t cap_list[2] = {CAP_BPF, CAP_PERFMON};
  int ret;

  if (caps == NULL) {
    perror("failed to allocate capability state");
    return 1;
  }

  ret = cap_set_flag(caps, CAP_EFFECTIVE, 2, cap_list, CAP_SET);
  if (ret) {
    perror("failed to set all capability flags");
    goto cleanup;
  }

  ret = cap_set_proc(caps);
  if (ret) {
    perror("failed to set capability state");
    goto cleanup;
  }

  ret = 0;

cleanup:
  if (cap_free(caps) != 0)
    perror("failed to free capability state");
  return ret;
}

int drop_capabilities(void) {
  cap_t caps = cap_get_proc();
  int ret;

  if (caps == NULL) {
    perror("failed to allocate capability state");
    return 1;
  }

  ret = cap_clear(caps);
  if (ret) {
    perror("failed to clear all capability flags");
    goto cleanup;
  }

  ret = cap_set_proc(caps);
  if (ret) {
    perror("failed to set capability state");
    goto cleanup;
  }

  ret = 0;

cleanup:
  if (cap_free(caps) != 0)
    perror("failed to free capability state");
  return ret;
}

int main(void) {
  if (signal_init())
    return 1;

  if (acquire_capabilities()) {
    perror("failed to acquire capabilities");
    return 1;
  }

  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

  struct ptrace_no_mm* skel = NULL;
  int err;

  skel = ptrace_no_mm__open_and_load();
  if (!skel) {
    perror("failed to open BPF skeleton");
    return 1;
  }

  err = ptrace_no_mm__attach(skel);
  if (err) {
    perror("failed to attach BPF skeleton");
    goto cleanup;
  }

  err = drop_capabilities();
  if (err) {
    perror("failed to drop capabilities");
    goto cleanup;
  }

  printf("BPF LSM program attached.\n");
  printf("Blocking ptrace_access_check when child->mm == NULL.\n");
  printf("Press Ctrl-C to exit.\n");
  fflush(stdout);

  pause();

  printf("Exiting.\n");
  fflush(stdout);

cleanup:
  ptrace_no_mm__destroy(skel);
  return err != 0;
}
