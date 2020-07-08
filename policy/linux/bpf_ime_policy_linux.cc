// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "sandbox/policy/linux/bpf_ime_policy_linux.h"

#include <sys/socket.h>

#include "sandbox/linux/bpf_dsl/bpf_dsl.h"
#include "sandbox/linux/seccomp-bpf-helpers/syscall_parameters_restrictions.h"
#include "sandbox/linux/syscall_broker/broker_process.h"
#include "sandbox/linux/system_headers/linux_syscalls.h"
#include "sandbox/policy/linux/sandbox_linux.h"

using sandbox::bpf_dsl::Allow;
using sandbox::bpf_dsl::ResultExpr;
using sandbox::bpf_dsl::Trap;
using sandbox::syscall_broker::BrokerProcess;

namespace sandbox {
namespace policy {

ImeProcessPolicy::ImeProcessPolicy() {}

ImeProcessPolicy::~ImeProcessPolicy() {}

ResultExpr ImeProcessPolicy::EvaluateSyscall(int sysno) const {
  switch (sysno) {
#if defined(__NR_uname)
    case __NR_uname:
#endif
#if defined(__NR_clock_gettime)
    case __NR_clock_gettime:
#endif
      return Allow();
// https://crbug.com/991435
#if defined(__NR_getrusage)
    case __NR_getrusage:
      return RestrictGetrusage();
#endif
    default:
      auto* broker_process = SandboxLinux::GetInstance()->broker_process();
      if (broker_process->IsSyscallAllowed(sysno))
        return Trap(BrokerProcess::SIGSYS_Handler, broker_process);

      return BPFBasePolicy::EvaluateSyscall(sysno);
  }
}

}  // namespace policy
}  // namespace sandbox
