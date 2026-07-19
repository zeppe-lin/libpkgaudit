/*
 * Copyright (C) 2026 Alexandr Savca
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include <libpkgaudit/path.h>

namespace pkgaudit {

using observation_id = std::uint64_t;

enum class observed_object_type
{
  directory,
  regular,
  symlink,
  other,
  missing,
};

enum class probe_operation
{
  inspect_object,
  read_symlink,
  resolve_symlink,
};

enum class probe_error
{
  permission_denied,
  io_error,
  object_changed,
  too_many_symlinks,
  outside_root,
};

struct probe_failure final
{
  probe_operation operation;
  probe_error error;
  int system_error{0};
};

enum class symlink_resolution
{
  not_requested,
  resolved,
  dangling,
  loop,
  outside_root,
  failed,
};

struct symlink_observation final
{
  std::string target;
  std::optional<object_path> immediate_path;
  std::optional<object_path> resolved_path;
  symlink_resolution resolution{symlink_resolution::not_requested};
  std::optional<probe_failure> failure;
};

struct observation_request final
{
  observation_id id;
  object_path path;
  bool resolve_symlink{false};
};

struct object_observation final
{
  observation_id id;
  object_path path;
  std::optional<observed_object_type> type;
  std::optional<symlink_observation> symlink;
  std::optional<probe_failure> failure;
};

} // namespace pkgaudit
