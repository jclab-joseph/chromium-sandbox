// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SANDBOX_POLICY_LINUX_BPF_LIBASSISTANT_POLICY_LINUX_H_
#define SANDBOX_POLICY_LINUX_BPF_LIBASSISTANT_POLICY_LINUX_H_

#include "sandbox/policy/linux/bpf_base_policy_linux.h"

namespace sandbox {
namespace policy {

// This policy can be used by Libassistant utility processes.
class LibassistantProcessPolicy : public BPFBasePolicy {
 public:
  LibassistantProcessPolicy();
  LibassistantProcessPolicy(const LibassistantProcessPolicy&) = delete;
  LibassistantProcessPolicy& operator=(const LibassistantProcessPolicy&) =
      delete;
  ~LibassistantProcessPolicy() override;

  bpf_dsl::ResultExpr EvaluateSyscall(int sysno) const override;
};

}  // namespace policy
}  // namespace sandbox

#endif  // SANDBOX_POLICY_LINUX_BPF_LIBASSISTANT_POLICY_LINUX_H_
