/*
 * Copyright (C) 2026 Alexandr Savca
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <libpkgaudit/path.h>

namespace pkgaudit {

enum class expected_object_type
{
  non_directory,
  directory,
};

struct expected_object final
{
  object_path path;
  expected_object_type type;
};

[[nodiscard]] bool operator==(const expected_object& lhs,
                              const expected_object& rhs) noexcept;
[[nodiscard]] bool operator!=(const expected_object& lhs,
                              const expected_object& rhs) noexcept;

class package_facts final
{
public:
  package_facts(std::string package,
                std::vector<expected_object> objects);

  [[nodiscard]] const std::string& package() const noexcept;
  [[nodiscard]] const std::vector<expected_object>& objects() const noexcept;
  [[nodiscard]] const expected_object*
  find(const object_path& path) const noexcept;

private:
  std::string package_;
  std::vector<expected_object> objects_;
};

class inventory final
{
public:
  explicit inventory(std::vector<package_facts> packages = {});

  [[nodiscard]] const std::vector<package_facts>& packages() const noexcept;
  [[nodiscard]] const package_facts*
  find_package(std::string_view package) const noexcept;
  [[nodiscard]] std::vector<std::string_view>
  owners(const object_path& path) const;

private:
  std::vector<package_facts> packages_;
  std::unordered_map<std::string, std::vector<std::size_t>> owners_;
};

} // namespace pkgaudit
