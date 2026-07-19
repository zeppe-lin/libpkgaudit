// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include <libpkgaudit/inventory.h>
#include <libpkgaudit/error.h>

#include <algorithm>
#include <utility>

namespace pkgaudit {
namespace {

void
validate_package(const std::string& package)
{
  if (package.empty())
    throw inventory_error("audit package identifier is empty");

  for (const char byte : package) {
    if (byte == '\0' || byte == '\n' || byte == '\r')
      throw inventory_error("audit package identifier is not line-safe");
  }
}

} // namespace

bool
operator==(const expected_object& lhs, const expected_object& rhs) noexcept
{
  return lhs.path == rhs.path && lhs.type == rhs.type;
}

bool
operator!=(const expected_object& lhs, const expected_object& rhs) noexcept
{
  return !(lhs == rhs);
}

package_facts::package_facts(std::string package,
                             std::vector<expected_object> objects)
  : package_(std::move(package))
  , objects_(std::move(objects))
{
  validate_package(package_);

  std::sort(objects_.begin(), objects_.end(),
            [](const expected_object& lhs, const expected_object& rhs) {
              return lhs.path < rhs.path;
            });

  const auto duplicate = std::adjacent_find(
      objects_.begin(), objects_.end(),
      [](const expected_object& lhs, const expected_object& rhs) {
        return lhs.path == rhs.path;
      });
  if (duplicate != objects_.end())
    throw inventory_error("package contains duplicate audit path: " +
                          duplicate->path.string());
}

const std::string&
package_facts::package() const noexcept
{
  return package_;
}

const std::vector<expected_object>&
package_facts::objects() const noexcept
{
  return objects_;
}

const expected_object*
package_facts::find(const object_path& path) const noexcept
{
  const auto found = std::lower_bound(
      objects_.begin(), objects_.end(), path,
      [](const expected_object& object, const object_path& wanted) {
        return object.path < wanted;
      });
  return found != objects_.end() && found->path == path ? &*found : nullptr;
}

inventory::inventory(std::vector<package_facts> packages)
  : packages_(std::move(packages))
{
  std::sort(packages_.begin(), packages_.end(),
            [](const package_facts& lhs, const package_facts& rhs) {
              return lhs.package() < rhs.package();
            });

  const auto duplicate = std::adjacent_find(
      packages_.begin(), packages_.end(),
      [](const package_facts& lhs, const package_facts& rhs) {
        return lhs.package() == rhs.package();
      });
  if (duplicate != packages_.end())
    throw inventory_error("duplicate audit package: " + duplicate->package());

  for (std::size_t package = 0; package < packages_.size(); ++package) {
    for (const auto& object : packages_[package].objects())
      owners_[object.path.string()].push_back(package);
  }
}

const std::vector<package_facts>&
inventory::packages() const noexcept
{
  return packages_;
}

const package_facts*
inventory::find_package(std::string_view package) const noexcept
{
  const auto found = std::lower_bound(
      packages_.begin(), packages_.end(), package,
      [](const package_facts& facts, std::string_view wanted) {
        return facts.package() < wanted;
      });
  return found != packages_.end() && found->package() == package
       ? &*found : nullptr;
}

std::vector<std::string_view>
inventory::owners(const object_path& path) const
{
  std::vector<std::string_view> result;
  const auto found = owners_.find(path.string());
  if (found == owners_.end())
    return result;

  result.reserve(found->second.size());
  for (const std::size_t index : found->second)
    result.emplace_back(packages_[index].package());
  return result;
}

} // namespace pkgaudit
