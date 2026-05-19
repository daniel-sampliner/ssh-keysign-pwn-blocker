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

static int signal_block(sigset_t* set) {
  sigemptyset(set);
  sigaddset(set, SIGINT);
  sigaddset(set, SIGTERM);

  if (sigprocmask(SIG_BLOCK, set, NULL)) {
    perror("failed to block signals");
    return -1;
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
  sigset_t signal_set;
  if (signal_block(&signal_set))
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

  siginfo_t info;
  int sig = sigwaitinfo(&signal_set, &info);
  if (sig < 0) {
    perror("failed to wait for signals");
    err = 1;
    goto cleanup;
  }

  fprintf(stderr, "%s\n", sigabbrev_np(sig));

  printf("Exiting.\n");
  fflush(stdout);

cleanup:
  ptrace_no_mm__destroy(skel);
  return err != 0;
}
