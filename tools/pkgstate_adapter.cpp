#include "pkgstate_adapter.h"

#include <utility>
#include <vector>

#include <libpkgstate/owned_entry.h>

namespace pkgchk {

pkgaudit::inventory
make_inventory(const pkgstate::snapshot& state)
{
  std::vector<pkgaudit::package_facts> packages;
  packages.reserve(state.packages().size());

  for (const pkgstate::installed_package& installed : state.packages()) {
    std::vector<pkgaudit::expected_object> objects;
    objects.reserve(installed.manifest().size());

    for (const pkgstate::owned_entry& entry : installed.manifest()) {
      objects.push_back({
          pkgaudit::object_path::parse(entry.path.string()),
          entry.type == pkgstate::owned_entry_type::directory
              ? pkgaudit::expected_object_type::directory
              : pkgaudit::expected_object_type::non_directory,
      });
    }

    packages.emplace_back(installed.identity().name(), std::move(objects));
  }

  return pkgaudit::inventory(std::move(packages));
}

} // namespace pkgchk
