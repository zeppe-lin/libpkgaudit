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
  owners_of_exact(const std::string& absolute_path) const;

  [[nodiscard]] std::set<std::string>
  owners_matching_pattern_path(const std::string& path_pattern) const;

private:
  std::map<std::string, std::set<std::string>> file_to_owners;
  std::vector<std::pair<std::string, std::string>> owned_paths;
};

} // namespace pkgaudit
