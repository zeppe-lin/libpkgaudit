/*
 * Copyright (C) 2026 Alexandr Savca
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#pragma once

#include <optional>
#include <string>
#include <vector>

#include <libpkgaudit/inventory.h>
#include <libpkgaudit/observation.h>

namespace pkgaudit {

enum class finding_kind
{
  missing_object,
  object_class_mismatch,
  dangling_symlink,
  symlink_loop,
  symlink_target_outside_root,
};

struct finding final
{
  finding_kind kind;
  std::string package;
  object_path path;
  expected_object_type expected;
  std::optional<observed_object_type> observed;
  std::string target;
};

enum class ownership_relation_kind
{
  source_package_owns_target,
  other_package_owns_target,
  target_is_unowned,
};

struct ownership_relation final
{
  ownership_relation_kind kind;
  std::string package;
  object_path path;
  std::string target;
  std::optional<object_path> immediate_path;
  std::optional<object_path> resolved_path;
  std::vector<std::string> immediate_owners;
  std::vector<std::string> resolved_owners;
};

enum class audit_failure_kind
{
  probe_failed,
  backend_contract_violation,
};

struct audit_failure final
{
  audit_failure_kind kind;
  std::optional<std::string> package;
  object_path path;
  std::optional<probe_operation> operation;
  std::optional<probe_error> error;
  int system_error{0};
};

class report final
{
public:
  report(std::vector<finding> findings,
         std::vector<ownership_relation> relations,
         std::vector<audit_failure> failures);

  [[nodiscard]] const std::vector<finding>& findings() const noexcept;
  [[nodiscard]] const std::vector<ownership_relation>&
  relations() const noexcept;
  [[nodiscard]] const std::vector<audit_failure>& failures() const noexcept;
  [[nodiscard]] bool complete() const noexcept;

private:
  std::vector<finding> findings_;
  std::vector<ownership_relation> relations_;
  std::vector<audit_failure> failures_;
};

} // namespace pkgaudit
