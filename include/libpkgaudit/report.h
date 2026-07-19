/*
 * Copyright (C) 2026 Alexandr Savca
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
/*! \file report.h
 *  \brief Typed audit findings, ownership relations, and failures.
 */
#pragma once

#include <optional>
#include <string>
#include <vector>

#include <libpkgaudit/inventory.h>
#include <libpkgaudit/observation.h>

namespace pkgaudit {

/*! \brief Established mismatch between expectation and observation. */
enum class finding_kind
{
  missing_object,              /*!< Expected object is absent. */
  object_class_mismatch,       /*!< Directory/non-directory identity differs. */
  dangling_symlink,            /*!< Link target cannot be found. */
  symlink_loop,                /*!< Link chain exceeds the resolution bound. */
  symlink_target_outside_root, /*!< Link traversal attempts to escape root. */
};

/*! \brief One package-scoped integrity finding. */
struct finding final
{
  finding_kind kind;                         /*!< Finding class. */
  std::string package;                       /*!< Expected owner identifier. */
  object_path path;                          /*!< Affected logical object. */
  expected_object_type expected;             /*!< Durable expected class. */
  std::optional<observed_object_type> observed; /*!< Observed class. */
  std::string target;                        /*!< Exact link target if relevant. */
};

/*! \brief Ownership topology of a successfully resolved link target. */
enum class ownership_relation_kind
{
  source_package_owns_target, /*!< Source package owns direct or final target. */
  other_package_owns_target,  /*!< Only another package owns the target. */
  target_is_unowned,          /*!< No package owns direct or final target. */
};

/*! \brief Neutral package-ownership relation for one symbolic link. */
struct ownership_relation final
{
  ownership_relation_kind kind;          /*!< Established relation. */
  std::string package;                   /*!< Package owning the link. */
  object_path path;                      /*!< Link path. */
  std::string target;                    /*!< Exact target bytes. */
  std::optional<object_path> immediate_path; /*!< Normalized direct target. */
  std::optional<object_path> resolved_path;  /*!< Final target. */
  std::vector<std::string> immediate_owners; /*!< Direct-target owners. */
  std::vector<std::string> resolved_owners;  /*!< Final-target owners. */
};

/*! \brief Reason the audit could not establish a complete fact set. */
enum class audit_failure_kind
{
  probe_failed,               /*!< Filesystem operation failed. */
  backend_contract_violation, /*!< Backend response protocol was violated. */
};

/*! \brief One package-scoped or backend-global incomplete-audit fact. */
struct audit_failure final
{
  audit_failure_kind kind;                 /*!< Failure class. */
  std::optional<std::string> package;      /*!< Package when scoped. */
  object_path path;                        /*!< Affected logical path. */
  std::optional<probe_operation> operation;/*!< Failed operation. */
  std::optional<probe_error> error;        /*!< Semantic error class. */
  int system_error{0};                     /*!< Optional platform errno. */
};

/*! \brief Immutable result streams produced by one audit run. */
class report final
{
public:
  /*! \brief Construct a report from canonical result streams. */
  report(std::vector<finding> findings,
         std::vector<ownership_relation> relations,
         std::vector<audit_failure> failures);

  /*! \brief Return integrity findings in canonical order. */
  [[nodiscard]] const std::vector<finding>& findings() const noexcept;
  /*! \brief Return ownership relations in canonical order. */
  [[nodiscard]] const std::vector<ownership_relation>&
  relations() const noexcept;
  /*! \brief Return failures in canonical order. */
  [[nodiscard]] const std::vector<audit_failure>& failures() const noexcept;
  /*! \brief Test whether every requested fact was established. */
  [[nodiscard]] bool complete() const noexcept;

private:
  std::vector<finding> findings_;
  std::vector<ownership_relation> relations_;
  std::vector<audit_failure> failures_;
};

} // namespace pkgaudit
