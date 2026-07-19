/*
 * Copyright (C) 2026 Alexandr Savca
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
/*! \file observation.h
 *  \brief Typed filesystem observation protocol.
 */
#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include <libpkgaudit/path.h>

namespace pkgaudit {

/*! \brief Stable identifier binding one request to one response. */
using observation_id = std::uint64_t;

/*! \brief Object class established with lstat semantics. */
enum class observed_object_type
{
  directory, /*!< Directory object. */
  regular,   /*!< Regular file. */
  symlink,   /*!< Symbolic link itself, not its target. */
  other,     /*!< FIFO, device, socket, or another non-regular class. */
  missing,   /*!< Successful observation that no object exists. */
};

/*! \brief Filesystem operation that failed while establishing a fact. */
enum class probe_operation
{
  inspect_object,  /*!< Inspect the owned object itself. */
  read_symlink,    /*!< Read a symbolic-link target. */
  resolve_symlink, /*!< Resolve a target beneath the selected root. */
};

/*! \brief Backend-neutral reason an observation could not be completed. */
enum class probe_error
{
  permission_denied,     /*!< Access was denied. */
  io_error,              /*!< Other operating-system I/O error. */
  object_changed,        /*!< Object identity changed during observation. */
  too_many_symlinks,     /*!< Configured resolution bound was exceeded. */
  outside_root,          /*!< Resolution attempted to traverse above root. */
  unrepresentable_path,  /*!< Resolved logical path violates path invariants. */
};

/*! \brief One failed filesystem operation. */
struct probe_failure final
{
  probe_operation operation; /*!< Operation that failed. */
  probe_error error;         /*!< Stable semantic failure class. */
  int system_error{0};       /*!< Optional platform errno value. */
};

/*! \brief Result of resolving a symbolic-link target. */
enum class symlink_resolution
{
  not_requested, /*!< Resolution was not requested. */
  resolved,      /*!< Target resolved beneath the selected root. */
  dangling,      /*!< A required path component was absent. */
  loop,          /*!< Resolution exceeded the link-following bound. */
  outside_root,  /*!< Relative traversal attempted to escape root. */
  failed,        /*!< Resolution failed for another explicit reason. */
};

/*! \brief Exact link target and root-contained resolution facts. */
struct symlink_observation final
{
  std::string target;                       /*!< Exact target bytes. */
  std::optional<object_path> immediate_path;/*!< Normalized direct target. */
  std::optional<object_path> resolved_path; /*!< Final resolved target. */
  symlink_resolution resolution{symlink_resolution::not_requested};
  std::optional<probe_failure> failure;     /*!< Failure when status is failed. */
};

/*! \brief One logical object requested from a filesystem backend. */
struct observation_request final
{
  observation_id id;       /*!< Stable request identifier. */
  object_path path;        /*!< Logical object path. */
  bool resolve_symlink{false}; /*!< Whether link resolution is required. */
};

/*! \brief One backend response bound to an observation request. */
struct object_observation final
{
  observation_id id;                         /*!< Echoed request identifier. */
  object_path path;                          /*!< Echoed logical path. */
  std::optional<observed_object_type> type;  /*!< Established object class. */
  std::optional<symlink_observation> symlink;/*!< Link facts when applicable. */
  std::optional<probe_failure> failure;      /*!< Object inspection failure. */
};

} // namespace pkgaudit
