// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "sandbox/win/src/startup_information_helper.h"

#include <Windows.h>

#include <algorithm>
#include <vector>

#include "base/check.h"
#include "base/memory/scoped_refptr.h"
#include "base/win/startup_information.h"
#include "base/win/windows_version.h"
#include "sandbox/win/src/app_container_profile.h"
#include "sandbox/win/src/security_capabilities.h"

namespace sandbox {
using base::win::StartupInformation;

StartupInformationHelper::StartupInformationHelper() {}
StartupInformationHelper::~StartupInformationHelper() {}

void StartupInformationHelper::UpdateFlags(DWORD flags) {
  startup_info_.startup_info()->dwFlags |= flags;
}

void StartupInformationHelper::SetDesktop(std::wstring desktop) {
  desktop_ = desktop;
  if (!desktop_.empty()) {
    startup_info_.startup_info()->lpDesktop =
        const_cast<wchar_t*>(desktop_.c_str());
  } else {
    startup_info_.startup_info()->lpDesktop = nullptr;
  }
}

void StartupInformationHelper::SetMitigations(MitigationFlags flags) {
  ConvertProcessMitigationsToPolicy(flags, &mitigations_[0],
                                    &mitigations_size_);
}

void StartupInformationHelper::SetRestrictChildProcessCreation(bool restrict) {
  DCHECK(base::win::GetVersion() >= base::win::Version::WIN10_TH2);
  restrict_child_process_creation_ = restrict;
}

void StartupInformationHelper::SetStdHandles(HANDLE stdout_handle,
                                             HANDLE stderr_handle) {
  stdout_handle_ = stdout_handle;
  AddInheritedHandle(stdout_handle);
  stderr_handle_ = stderr_handle;
  if (stderr_handle != stdout_handle)
    AddInheritedHandle(stderr_handle);
}

void StartupInformationHelper::AddInheritedHandle(HANDLE handle) {
  if (handle != INVALID_HANDLE_VALUE) {
    auto it = std::find(inherited_handle_list_.begin(),
                        inherited_handle_list_.end(), handle);
    if (it == inherited_handle_list_.end())
      inherited_handle_list_.push_back(handle);
  }
}

void StartupInformationHelper::SetAppContainerProfile(
    scoped_refptr<AppContainerProfileBase> profile) {
  // Only supported for Windows 8+.
  DCHECK(base::win::GetVersion() >= base::win::Version::WIN8);
  // LowPrivilegeAppContainer only supported for Windows 10+
  DCHECK(!profile->GetEnableLowPrivilegeAppContainer() ||
         base::win::GetVersion() >= base::win::Version::WIN10_RS1);

  app_container_profile_ = profile;
  security_capabilities_ = app_container_profile_->GetSecurityCapabilities();
}

void StartupInformationHelper::AddJobToAssociate(HANDLE job_handle) {
  job_handle_list_.push_back(job_handle);
}

int StartupInformationHelper::CountAttributes() {
  int attribute_count = 0;
  if (mitigations_[0] || mitigations_[1])
    ++attribute_count;

  if (restrict_child_process_creation_)
    ++attribute_count;

  if (!inherited_handle_list_.empty())
    ++attribute_count;

  if (app_container_profile_) {
    ++attribute_count;
    if (app_container_profile_->GetEnableLowPrivilegeAppContainer())
      ++attribute_count;
  }

  if (!job_handle_list_.empty())
    ++attribute_count;

  return attribute_count;
}

bool StartupInformationHelper::BuildStartupInformation() {
  // When adding new attributes, any memory referenced needs to have the
  // same lifetime as startup_info_. This is why we use members below.

  auto expected_attributes = CountAttributes();
  if (!startup_info_.InitializeProcThreadAttributeList(expected_attributes))
    return false;

  if (mitigations_[0] || mitigations_[1]) {
    if (!startup_info_.UpdateProcThreadAttribute(
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &mitigations_[0],
            mitigations_size_)) {
      return false;
    }
    expected_attributes--;
  }

  if (restrict_child_process_creation_) {
    child_process_creation_ = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
    if (!startup_info_.UpdateProcThreadAttribute(
            PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY,
            &child_process_creation_, sizeof(child_process_creation_))) {
      return false;
    }
    expected_attributes--;
  }

  if (inherited_handle_list_.size()) {
    if (!startup_info_.UpdateProcThreadAttribute(
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &inherited_handle_list_[0],
            sizeof(HANDLE) * inherited_handle_list_.size())) {
      return false;
    }
    startup_info_.startup_info()->dwFlags |= STARTF_USESTDHANDLES;
    startup_info_.startup_info()->hStdInput = INVALID_HANDLE_VALUE;
    startup_info_.startup_info()->hStdOutput = stdout_handle_;
    startup_info_.startup_info()->hStdError = stderr_handle_;
    // Allowing inheritance of handles is only secure now that we
    // have limited which handles will be inherited.
    inherit_handles_ = true;
    expected_attributes--;
  }

  if (!job_handle_list_.empty()) {
    if (!startup_info_.UpdateProcThreadAttribute(
            PROC_THREAD_ATTRIBUTE_JOB_LIST, &job_handle_list_[0],
            sizeof(HANDLE) * job_handle_list_.size())) {
      return false;
    }
    expected_attributes--;
  }

  if (app_container_profile_) {
    if (!startup_info_.UpdateProcThreadAttribute(
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            security_capabilities_.get(), sizeof(SECURITY_CAPABILITIES))) {
      return false;
    }
    expected_attributes--;
    if (app_container_profile_->GetEnableLowPrivilegeAppContainer()) {
      all_applications_package_policy_ =
          PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
      if (!startup_info_.UpdateProcThreadAttribute(
              PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
              &all_applications_package_policy_,
              sizeof(all_applications_package_policy_))) {
        return false;
      }
      expected_attributes--;
    }
  }

  CHECK(expected_attributes == 0);
  return true;
}

}  // namespace sandbox
