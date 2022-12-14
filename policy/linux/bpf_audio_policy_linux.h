// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SANDBOX_POLICY_LINUX_BPF_AUDIO_POLICY_LINUX_H_
#define SANDBOX_POLICY_LINUX_BPF_AUDIO_POLICY_LINUX_H_

#include "sandbox/linux/bpf_dsl/bpf_dsl.h"
#include "sandbox/policy/export.h"
#include "sandbox/policy/linux/bpf_base_policy_linux.h"

namespace sandbox {
namespace policy {

class SANDBOX_POLICY_EXPORT AudioProcessPolicy : public BPFBasePolicy {
 public:
  AudioProcessPolicy();

  AudioProcessPolicy(const AudioProcessPolicy&) = delete;
  AudioProcessPolicy& operator=(const AudioProcessPolicy&) = delete;

  ~AudioProcessPolicy() override;

  bpf_dsl::ResultExpr EvaluateSyscall(int system_call_number) const override;
};

}  // namespace policy
}  // namespace sandbox

#endif  // SANDBOX_POLICY_LINUX_BPF_AUDIO_POLICY_LINUX_H_
