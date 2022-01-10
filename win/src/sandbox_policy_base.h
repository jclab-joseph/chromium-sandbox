// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SANDBOX_WIN_SRC_SANDBOX_POLICY_BASE_H_
#define SANDBOX_WIN_SRC_SANDBOX_POLICY_BASE_H_

#include <stddef.h>
#include <stdint.h>

#include <list>
#include <memory>
#include <string>
#include <vector>

#include "base/compiler_specific.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/process/launch.h"
#include "base/synchronization/lock.h"
#include "base/win/scoped_handle.h"
#include "base/win/windows_types.h"
#include "sandbox/win/src/app_container_base.h"
#include "sandbox/win/src/handle_closer.h"
#include "sandbox/win/src/ipc_tags.h"
#include "sandbox/win/src/policy_engine_opcodes.h"
#include "sandbox/win/src/policy_engine_params.h"
#include "sandbox/win/src/sandbox_policy.h"

namespace sandbox {

class Dispatcher;
class LowLevelPolicy;
class PolicyDiagnostic;
class PolicyInfo;
class TargetProcess;
struct PolicyGlobal;

class PolicyBase final : public TargetPolicy {
 public:
  PolicyBase();

  PolicyBase(const PolicyBase&) = delete;
  PolicyBase& operator=(const PolicyBase&) = delete;

  // TargetPolicy:
  void AddRef() override;
  void Release() override;
  ResultCode SetTokenLevel(TokenLevel initial, TokenLevel lockdown) override;
  TokenLevel GetInitialTokenLevel() const override;
  TokenLevel GetLockdownTokenLevel() const override;
  ResultCode SetJobLevel(JobLevel job_level, uint32_t ui_exceptions) override;
  JobLevel GetJobLevel() const override;
  ResultCode SetJobMemoryLimit(size_t memory_limit) override;
  ResultCode SetAlternateDesktop(bool alternate_winstation) override;
  std::wstring GetAlternateDesktop() const override;
  ResultCode CreateAlternateDesktop(bool alternate_winstation) override;
  void DestroyAlternateDesktop() override;
  ResultCode SetIntegrityLevel(IntegrityLevel integrity_level) override;
  IntegrityLevel GetIntegrityLevel() const override;
  ResultCode SetDelayedIntegrityLevel(IntegrityLevel integrity_level) override;
  ResultCode SetLowBox(const wchar_t* sid) override;
  ResultCode SetProcessMitigations(MitigationFlags flags) override;
  MitigationFlags GetProcessMitigations() override;
  ResultCode SetDelayedProcessMitigations(MitigationFlags flags) override;
  MitigationFlags GetDelayedProcessMitigations() const override;
  ResultCode SetDisconnectCsrss() override;
  void SetStrictInterceptions() override;
  ResultCode SetStdoutHandle(HANDLE handle) override;
  ResultCode SetStderrHandle(HANDLE handle) override;
  ResultCode AddRule(SubSystem subsystem,
                     Semantics semantics,
                     const wchar_t* pattern) override;
  ResultCode AddDllToUnload(const wchar_t* dll_name) override;
  ResultCode AddKernelObjectToClose(const wchar_t* handle_type,
                                    const wchar_t* handle_name) override;
  void AddHandleToShare(HANDLE handle) override;
  void SetLockdownDefaultDacl() override;
  void AddRestrictingRandomSid() override;
  ResultCode AddAppContainerProfile(const wchar_t* package_name,
                                    bool create_profile) override;
  scoped_refptr<AppContainer> GetAppContainer() override;
  void SetEffectiveToken(HANDLE token) override;
  std::unique_ptr<PolicyInfo> GetPolicyInfo() override;
  void SetAllowNoSandboxJob() override;
  bool GetAllowNoSandboxJob() override;

  // Get the AppContainer profile as its internal type.
  scoped_refptr<AppContainerBase> GetAppContainerBase();

  // Creates a Job object with the level specified in a previous call to
  // SetJobLevel().
  ResultCode MakeJobObject(base::win::ScopedHandle* job);

  // Updates the active process limit on the job to zero. Has no effect
  // if the job is allowed to spawn processes.
  ResultCode DropActiveProcessLimit(base::win::ScopedHandle* job);

  // Creates the two tokens with the levels specified in a previous call to
  // SetTokenLevel(). Also creates a lowbox token if specified based on the
  // lowbox SID.
  ResultCode MakeTokens(base::win::ScopedHandle* initial,
                        base::win::ScopedHandle* lockdown,
                        base::win::ScopedHandle* lowbox);

  // Adds a target process to the internal list of targets. Internally a
  // call to TargetProcess::Init() is issued.
  ResultCode AddTarget(std::unique_ptr<TargetProcess> target);

  // Called when there are no more active processes in a Job.
  // Removes a Job object associated with this policy and the target associated
  // with the job. If a process is not in a job, call OnProcessFinished().
  bool OnJobEmpty(HANDLE job);

  // Called when a process no longer needs to be tracked. Processes in jobs
  // should be notified via OnJobEmpty instead.
  bool OnProcessFinished(DWORD process_id);

  EvalResult EvalPolicy(IpcTag service, CountedParameterSetBase* params);

  HANDLE GetStdoutHandle();
  HANDLE GetStderrHandle();

  // Returns the list of handles being shared with the target process.
  const base::HandlesToInheritVector& GetHandlesBeingShared();

 private:
  // Allow PolicyInfo to snapshot PolicyBase for diagnostics.
  friend class PolicyDiagnostic;
  ~PolicyBase();

  // Sets up interceptions for a new target. This policy must own |target|.
  ResultCode SetupAllInterceptions(TargetProcess& target);

  // Sets up the handle closer for a new target. This policy must own |target|.
  bool SetupHandleCloser(TargetProcess& target);

  ResultCode AddRuleInternal(SubSystem subsystem,
                             Semantics semantics,
                             const wchar_t* pattern);

  // This lock synchronizes operations on the targets_ collection.
  base::Lock lock_;
  // Maintains the list of target process associated with this policy.
  // The policy takes ownership of them.
  typedef std::list<std::unique_ptr<TargetProcess>> TargetSet;
  TargetSet targets_;
  // Standard object-lifetime reference counter.
  volatile LONG ref_count;
  // The user-defined global policy settings.
  TokenLevel lockdown_level_;
  TokenLevel initial_level_;
  JobLevel job_level_;
  uint32_t ui_exceptions_;
  size_t memory_limit_;
  bool use_alternate_desktop_;
  bool use_alternate_winstation_;
  bool relaxed_interceptions_;
  HANDLE stdout_handle_;
  HANDLE stderr_handle_;
  IntegrityLevel integrity_level_;
  IntegrityLevel delayed_integrity_level_;
  MitigationFlags mitigations_;
  MitigationFlags delayed_mitigations_;
  bool is_csrss_connected_;
  // Object in charge of generating the low level policy.
  raw_ptr<LowLevelPolicy> policy_maker_;
  // Memory structure that stores the low level policy.
  raw_ptr<PolicyGlobal> policy_;
  // The list of dlls to unload in the target process.
  std::vector<std::wstring> blocklisted_dlls_;
  // This is a map of handle-types to names that we need to close in the
  // target process. A null set means we need to close all handles of the
  // given type.
  HandleCloser handle_closer_;
  std::unique_ptr<Dispatcher> dispatcher_;
  bool lockdown_default_dacl_;
  bool add_restricting_random_sid_;

  static HDESK alternate_desktop_handle_;
  static HWINSTA alternate_winstation_handle_;
  static HDESK alternate_desktop_local_winstation_handle_;
  static IntegrityLevel alternate_desktop_integrity_level_label_;
  static IntegrityLevel
      alternate_desktop_local_winstation_integrity_level_label_;

  // Contains the list of handles being shared with the target process.
  // This list contains handles other than the stderr/stdout handles which are
  // shared with the target at times.
  base::HandlesToInheritVector handles_to_share_;

  scoped_refptr<AppContainerBase> app_container_;

  HANDLE effective_token_;
  bool allow_no_sandbox_job_;
};

}  // namespace sandbox

#endif  // SANDBOX_WIN_SRC_SANDBOX_POLICY_BASE_H_
