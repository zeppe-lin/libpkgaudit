#pragma once

#include <map>
#include <set>
#include <string>

#include <libpkgcore/pkgcore.h>

namespace pkgaudit {

class ownership_index
{
public:
  explicit ownership_index(const pkgutil& util);

  [[nodiscard]] std::set<std::string>
  owners_of(const std::string& absolute_path) const;

private:
  std::map<std::string, std::set<std::string>> file_to_owners;
};

} // namespace pkgaudit
