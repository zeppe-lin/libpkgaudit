// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

/*! \file audit.h
 *  \brief Audit request model and deterministic semantic engine.
 */
#pragma once

#include <cstdint>
#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

#include <libpkgaudit/filesystem.h>
#include <libpkgaudit/inventory.h>
#include <libpkgaudit/report.h>

namespace pkgaudit {

/*! \brief Independent semantic check selectable by a consumer. */
enum class check : std::uint8_t
{
  object_state = 1U << 0,       /*!< Presence and durable class. */
  symlink_resolution = 1U << 1, /*!< Dangling, loop, and escape state. */
  symlink_ownership = 1U << 2,  /*!< Direct and resolved owner relation. */
};

/*! \brief Explicit set of requested semantic checks. */
class check_set final
{
public:
  check_set() = default;
  /*! \brief Construct from an explicit list of checks. */
  check_set(std::initializer_list<check> checks);

  /*! \brief Add one check. */
  void add(check value) noexcept;
  /*! \brief Test whether one check is selected. */
  [[nodiscard]] bool contains(check value) const noexcept;
  /*! \brief Test whether no checks are selected. */
  [[nodiscard]] bool empty() const noexcept;

private:
  std::uint8_t bits_{0};
};

/*! \brief Explicit all-packages or named-package selection. */
class package_selection final
{
public:
  /*! \brief Select every package in the inventory. */
  [[nodiscard]] static package_selection all();
  /*! \brief Select named packages after sorting and deduplication. */
  [[nodiscard]] static package_selection only(std::vector<std::string> packages);

  /*! \brief Test whether all packages are selected. */
  [[nodiscard]] bool selects_all() const noexcept;
  /*! \brief Return selected names in canonical order. */
  [[nodiscard]] const std::vector<std::string>& packages() const noexcept;
  /*! \brief Test whether an identifier belongs to the selection. */
  [[nodiscard]] bool contains(std::string_view package) const noexcept;

private:
  package_selection(bool all, std::vector<std::string> packages);

  bool all_{false};
  std::vector<std::string> packages_;
};

/*! \brief Complete package and check selection for one run. */
struct audit_request final
{
  package_selection packages{package_selection::all()}; /*!< Package scope. */
  check_set checks;                                     /*!< Semantic checks. */
};

/*! \brief Deterministic transformation from facts and observations to report. */
class auditor final
{
public:
  /*! \brief Run an audit against an immutable inventory.
   *
   * Shared paths are requested once.  Backend responses are validated by
   * identifier and path, then findings, relations, and failures are sorted
   * independently of backend completion order.
   *
   * \throws audit_error when no checks are selected.
   * \throws inventory_error when a selected package is absent.
   */
  [[nodiscard]] report run(const inventory& facts,
                           const audit_request& request,
                           filesystem_backend& filesystem) const;
};

} // namespace pkgaudit
