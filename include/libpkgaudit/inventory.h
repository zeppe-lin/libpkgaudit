/*
 * Copyright (C) 2026 Alexandr Savca
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
/*! \file inventory.h
 *  \brief Immutable package expectations and exact ownership queries.
 */
#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <libpkgaudit/path.h>

namespace pkgaudit {

/*! \brief Durable object class known by the audit authority. */
enum class expected_object_type
{
  non_directory, /*!< Any owned object that is not a directory. */
  directory,     /*!< Explicitly owned directory. */
};

/*! \brief One canonical object expected by a package. */
struct expected_object final
{
  object_path path;          /*!< Logical root-relative path. */
  expected_object_type type; /*!< Durable directory distinction. */
};

/*! \brief Compare expected objects for semantic equality. */
[[nodiscard]] bool operator==(const expected_object& lhs,
                              const expected_object& rhs) noexcept;
/*! \brief Compare expected objects for semantic inequality. */
[[nodiscard]] bool operator!=(const expected_object& lhs,
                              const expected_object& rhs) noexcept;

/*! \brief Immutable expected objects owned by one package identifier. */
class package_facts final
{
public:
  /*! \brief Validate and canonicalize package facts.
   *
   * Objects are sorted by path.  Duplicate paths and empty or line-unsafe
   * package identifiers are rejected.
   */
  package_facts(std::string package,
                std::vector<expected_object> objects);

  /*! \brief Return the opaque package identifier. */
  [[nodiscard]] const std::string& package() const noexcept;
  /*! \brief Return expected objects in canonical path order. */
  [[nodiscard]] const std::vector<expected_object>& objects() const noexcept;
  /*! \brief Find an expected object by exact canonical path. */
  [[nodiscard]] const expected_object*
  find(const object_path& path) const noexcept;

private:
  std::string package_;
  std::vector<expected_object> objects_;
};

/*! \brief Complete immutable fact universe for one audit.
 *
 * Packages are sorted by identifier.  Shared ownership is retained and exact
 * owner queries return package identifiers in that same canonical order.
 */
class inventory final
{
public:
  /*! \brief Construct and index a complete package inventory.
   *  \throws inventory_error on duplicate package identifiers.
   */
  explicit inventory(std::vector<package_facts> packages = {});

  /*! \brief Return packages in canonical identifier order. */
  [[nodiscard]] const std::vector<package_facts>& packages() const noexcept;
  /*! \brief Find package facts by exact identifier. */
  [[nodiscard]] const package_facts*
  find_package(std::string_view package) const noexcept;
  /*! \brief Return every exact owner of a canonical path. */
  [[nodiscard]] std::vector<std::string_view>
  owners(const object_path& path) const;

private:
  std::vector<package_facts> packages_;
  std::unordered_map<std::string, std::vector<std::size_t>> owners_;
};

} // namespace pkgaudit
