/*
 * SPDX-FileCopyrightText: 2026 Daniel Sampliner <samplinerD@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define EPERM 1
#define ESRCH 3

char LICENSE[] SEC("license") = "GPL";

SEC("lsm/ptrace_access_check")
int BPF_PROG(ptrace_no_mm,
             struct task_struct* child,
             unsigned int mode,
             int ret) {
  struct mm_struct* mm;

  // previous LSM already denied operation, so preserve it
  if (ret != 0)
    return ret;

  if (!child)
    return -ESRCH;

  // deny ptrace when child no longer running
  mm = BPF_CORE_READ(child, mm);
  if (mm == NULL)
    return -EPERM;

  return 0;
}
