#include <libpkgaudit/ownership_index.h>

namespace pkgaudit {

ownership_index::ownership_index(const pkgutil& util)
{
  for (const auto& [pkgname, info] : util.getPackages())
  {
    for (const auto& rel : info.files)
    {
      file_to_owners["/" + rel].insert(pkgname);
    }
  }
}

std::set<std::string>
ownership_index::owners_of(const std::string& absolute_path) const
{
  const auto it = file_to_owners.find(absolute_path);
  if (it == file_to_owners.end())
    return {};

  return it->second;
}

} // namespace pkgaudit
