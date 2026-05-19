/*
 * SPDX-FileCopyrightText: 2026 Daniel Sampliner <samplinerD@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#define _GNU_SOURCE

#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/prctl.h>
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
  const cap_value_t cap_list[] = {CAP_BPF, CAP_PERFMON, CAP_SETPCAP};
  int ret = 0;

  if (caps == NULL) {
    perror("failed to allocate capability state");
    return 1;
  }

  if (cap_set_flag(caps, CAP_EFFECTIVE, sizeof(cap_list) / sizeof(cap_list[0]),
                   cap_list, CAP_SET)) {
    perror("failed to set all capability flags");
    ret = -1;
    goto cleanup;
  }

  if (cap_set_proc(caps)) {
    perror("failed to set capability state");
    ret = -1;
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

  if (cap_reset_ambient()) {
    perror("failed to reset ambient capabilities");
    return -1;
  }

  int last_cap = cap_max_bits();
  if (last_cap < 0) {
    perror("failed to get max capability number");
    return -1;
  }

  for (cap_value_t cap = 0; cap < last_cap; cap++) {
    if (cap_drop_bound(cap)) {
      fprintf(stderr, "failed to drop capability %d from bounding set: %s\n",
              cap, strerror(errno));
      return -1;
    }
  }

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
    perror("failed to set no_new_privs attribute");
    return -1;
  }

  if (caps == NULL) {
    perror("failed to allocate capability state");
    return 1;
  }

  if (cap_clear(caps)) {
    perror("failed to clear all capability flags");
    ret = -1;
    goto cleanup;
  }

  if (cap_set_proc(caps)) {
    perror("failed to set capability state");
    ret = -1;
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
    fprintf(stderr, "failed to acquire capabilities\n");
    return 1;
  }

  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

  struct ptrace_no_mm* skel = NULL;
  int err;

  skel = ptrace_no_mm__open_and_load();
  if (!skel) {
    fprintf(stderr, "failed to open BPF skeleton\n");
    return 1;
  }

  err = ptrace_no_mm__attach(skel);
  if (err) {
    fprintf(stderr, "failed to attach BPF skeleton: %s\n", strerror(-err));
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
