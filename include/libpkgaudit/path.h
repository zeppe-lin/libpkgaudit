// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

/*! \file path.h
 *  \brief Canonical logical paths beneath an audit root.
 */
#pragma once

#include <iosfwd>
#include <optional>
#include <string>
#include <string_view>

#include <libpkgaudit/visibility.h>

namespace pkgaudit {

/*! \brief Canonical root-relative path of one audited object.
 *
 * Empty and `.` components are removed.  Absolute paths, `..`, NUL, carriage
 * return, newline, and paths naming no object are rejected.  Directory
 * identity is represented separately from path spelling.
 */
class object_path final
{
public:
  /*! \brief Normalize and validate a logical path.
   *  \throws path_error when the input violates the path contract.
   */
  [[nodiscard]] static PKGAUDIT_API object_path parse(std::string_view input);

  /*! \brief Return the canonical root-relative spelling. */
  [[nodiscard]] PKGAUDIT_API const std::string& string() const noexcept;
  /*! \brief Return the final path component. */
  [[nodiscard]] PKGAUDIT_API std::string_view filename() const noexcept;
  /*! \brief Return the canonical parent, or no value for a top-level path. */
  [[nodiscard]] PKGAUDIT_API std::optional<object_path> parent() const;

  /*! \brief Compare paths for semantic equality. */
  friend PKGAUDIT_API bool operator==(const object_path& lhs,
                         const object_path& rhs) noexcept;
  /*! \brief Compare paths for semantic inequality. */
  friend PKGAUDIT_API bool operator!=(const object_path& lhs,
                         const object_path& rhs) noexcept;
  /*! \brief Order paths lexicographically by canonical spelling. */
  friend PKGAUDIT_API bool operator<(const object_path& lhs,
                        const object_path& rhs) noexcept;

private:
  explicit object_path(std::string value);

  std::string value_;
};

/*! \brief Write a canonical audit path to a stream. */
PKGAUDIT_API std::ostream& operator<<(std::ostream& out, const object_path& path);

} // namespace pkgaudit
