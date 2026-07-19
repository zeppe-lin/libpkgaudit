/*
 * Copyright (C) 2026 Alexandr Savca
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <libpkgaudit/filesystem.h>
#include <libpkgaudit/inventory.h>
#include <libpkgaudit/report.h>

namespace pkgaudit {

enum class check : std::uint8_t
{
  object_state = 1U << 0,
  symlink_resolution = 1U << 1,
  symlink_ownership = 1U << 2,
};

class check_set final
{
public:
  check_set() = default;
  check_set(std::initializer_list<check> checks);

  void add(check value) noexcept;
  [[nodiscard]] bool contains(check value) const noexcept;
  [[nodiscard]] bool empty() const noexcept;

private:
  std::uint8_t bits_{0};
};

class package_selection final
{
public:
  [[nodiscard]] static package_selection all();
  [[nodiscard]] static package_selection only(std::vector<std::string> packages);

  [[nodiscard]] bool selects_all() const noexcept;
  [[nodiscard]] const std::vector<std::string>& packages() const noexcept;
  [[nodiscard]] bool contains(std::string_view package) const noexcept;

private:
  package_selection(bool all, std::vector<std::string> packages);

  bool all_{false};
  std::vector<std::string> packages_;
};

struct audit_request final
{
  package_selection packages{package_selection::all()};
  check_set checks;
};

class auditor final
{
public:
  [[nodiscard]] report run(const inventory& facts,
                           const audit_request& request,
                           filesystem_backend& filesystem) const;
};

} // namespace pkgaudit
