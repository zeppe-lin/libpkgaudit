/*
 * Copyright (C) 2026 Alexandr Savca
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#pragma once

#include <iosfwd>
#include <optional>
#include <string>
#include <string_view>

namespace pkgaudit {

class object_path final
{
public:
  [[nodiscard]] static object_path parse(std::string_view input);

  [[nodiscard]] const std::string& string() const noexcept;
  [[nodiscard]] std::string_view filename() const noexcept;
  [[nodiscard]] std::optional<object_path> parent() const;

  friend bool operator==(const object_path& lhs,
                         const object_path& rhs) noexcept;
  friend bool operator!=(const object_path& lhs,
                         const object_path& rhs) noexcept;
  friend bool operator<(const object_path& lhs,
                        const object_path& rhs) noexcept;

private:
  explicit object_path(std::string value);

  std::string value_;
};

std::ostream& operator<<(std::ostream& out, const object_path& path);

} // namespace pkgaudit
