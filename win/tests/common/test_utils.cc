// Copyright (c) 2006-2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "sandbox/win/tests/common/test_utils.h"

#include <stddef.h>
#include <winioctl.h>

#include "base/numerics/safe_conversions.h"

namespace sandbox {

typedef struct _REPARSE_DATA_BUFFER {
  ULONG  ReparseTag;
  USHORT  ReparseDataLength;
  USHORT  Reserved;
  union {
    struct {
      USHORT SubstituteNameOffset;
      USHORT SubstituteNameLength;
      USHORT PrintNameOffset;
      USHORT PrintNameLength;
      ULONG Flags;
      WCHAR PathBuffer[1];
      } SymbolicLinkReparseBuffer;
    struct {
      USHORT SubstituteNameOffset;
      USHORT SubstituteNameLength;
      USHORT PrintNameOffset;
      USHORT PrintNameLength;
      WCHAR PathBuffer[1];
      } MountPointReparseBuffer;
    struct {
      UCHAR DataBuffer[1];
    } GenericReparseBuffer;
  };
} REPARSE_DATA_BUFFER, *PREPARSE_DATA_BUFFER;

// Sets a reparse point. |source| will now point to |target|. Returns true if
// the call succeeds, false otherwise.
bool SetReparsePoint(HANDLE source, const wchar_t* target) {
  USHORT size_target = static_cast<USHORT>(wcslen(target)) * sizeof(target[0]);

  char buffer[2000] = {0};
  DWORD returned;

  REPARSE_DATA_BUFFER* data = reinterpret_cast<REPARSE_DATA_BUFFER*>(buffer);

  data->ReparseTag = 0xa0000003;
  memcpy(data->MountPointReparseBuffer.PathBuffer, target, size_target + 2);
  data->MountPointReparseBuffer.SubstituteNameLength = size_target;
  data->MountPointReparseBuffer.PrintNameOffset = size_target + 2;
  data->ReparseDataLength = size_target + 4 + 8;

  int data_size = data->ReparseDataLength + 8;

  if (!DeviceIoControl(source, FSCTL_SET_REPARSE_POINT, &buffer, data_size,
                       NULL, 0, &returned, NULL)) {
    return false;
  }
  return true;
}

// Delete the reparse point referenced by |source|. Returns true if the call
// succeeds, false otherwise.
bool DeleteReparsePoint(HANDLE source) {
  DWORD returned;
  REPARSE_DATA_BUFFER data = {0};
  data.ReparseTag = 0xa0000003;
  if (!DeviceIoControl(source, FSCTL_DELETE_REPARSE_POINT, &data, 8, NULL, 0,
                       &returned, NULL)) {
    return false;
  }

  return true;
}

SidAndAttributes::SidAndAttributes(const SID_AND_ATTRIBUTES& sid_and_attributes)
    : attributes_(sid_and_attributes.Attributes),
      sid_(*base::win::Sid::FromPSID(sid_and_attributes.Sid)) {}

PSID SidAndAttributes::GetPSID() const {
  return sid_.GetPSID();
}

DWORD SidAndAttributes::GetAttributes() const {
  return attributes_;
}

absl::optional<base::win::Sid> GetTokenAppContainerSid(HANDLE token) {
  std::vector<char> app_container_info(sizeof(TOKEN_APPCONTAINER_INFORMATION) +
                                       SECURITY_MAX_SID_SIZE);
  DWORD return_length;

  if (!::GetTokenInformation(
          token, TokenAppContainerSid, app_container_info.data(),
          base::checked_cast<DWORD>(app_container_info.size()),
          &return_length)) {
    return absl::nullopt;
  }

  PTOKEN_APPCONTAINER_INFORMATION info =
      reinterpret_cast<PTOKEN_APPCONTAINER_INFORMATION>(
          app_container_info.data());
  if (!info->TokenAppContainer)
    return absl::nullopt;
  return base::win::Sid::FromPSID(info->TokenAppContainer);
}

absl::optional<std::vector<SidAndAttributes>> GetTokenGroups(
    HANDLE token,
    TOKEN_INFORMATION_CLASS information_class) {
  if (information_class != ::TokenCapabilities &&
      information_class != ::TokenGroups &&
      information_class != ::TokenRestrictedSids) {
    return absl::nullopt;
  }

  absl::optional<std::vector<char>> groups_buf =
      GetVariableTokenInformation(token, information_class);
  if (!groups_buf)
    return absl::nullopt;

  PTOKEN_GROUPS groups = reinterpret_cast<PTOKEN_GROUPS>(groups_buf->data());
  std::vector<SidAndAttributes> token_groups;
  token_groups.reserve(groups->GroupCount);
  for (DWORD index = 0; index < groups->GroupCount; ++index) {
    token_groups.push_back(groups->Groups[index]);
  }

  return token_groups;
}

absl::optional<std::vector<char>> GetVariableTokenInformation(
    HANDLE token,
    TOKEN_INFORMATION_CLASS information_class) {
  DWORD return_length;
  if (!::GetTokenInformation(token, information_class, nullptr, 0,
                             &return_length)) {
    if (::GetLastError() != ERROR_INSUFFICIENT_BUFFER)
      return absl::nullopt;
  }

  std::vector<char> information(return_length);
  if (!::GetTokenInformation(token, information_class, information.data(),
                             return_length, &return_length)) {
    return absl::nullopt;
  }
  return information;
}

}  // namespace sandbox
