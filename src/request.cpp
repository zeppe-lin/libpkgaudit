// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include <libpkgaudit/audit.h>
#include <libpkgaudit/error.h>

#include <algorithm>
#include <utility>

namespace pkgaudit {

check_set::check_set(std::initializer_list<check> checks)
{
  for (const check value : checks)
    add(value);
}

void
check_set::add(check value) noexcept
{
  bits_ |= static_cast<std::uint8_t>(value);
}

bool
check_set::contains(check value) const noexcept
{
  return (bits_ & static_cast<std::uint8_t>(value)) != 0;
}

bool
check_set::empty() const noexcept
{
  return bits_ == 0;
}

package_selection::package_selection(bool all,
                                     std::vector<std::string> packages)
  : all_(all)
  , packages_(std::move(packages))
{
}

package_selection
package_selection::all()
{
  return package_selection(true, {});
}

package_selection
package_selection::only(std::vector<std::string> packages)
{
  for (const auto& package : packages) {
    if (package.empty())
      throw inventory_error("selected package identifier is empty");
    for (const char byte : package) {
      if (byte == '\0' || byte == '\n' || byte == '\r')
        throw inventory_error("selected package identifier is not line-safe");
    }
  }

  std::sort(packages.begin(), packages.end());
  packages.erase(std::unique(packages.begin(), packages.end()), packages.end());
  return package_selection(false, std::move(packages));
}

bool
package_selection::selects_all() const noexcept
{
  return all_;
}

const std::vector<std::string>&
package_selection::packages() const noexcept
{
  return packages_;
}

bool
package_selection::contains(std::string_view package) const noexcept
{
  return all_ || std::binary_search(packages_.begin(), packages_.end(), package);
}

} // namespace pkgaudit
