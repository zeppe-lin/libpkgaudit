#include <libpkgaudit/ownership_index.h>

#include <cstring>
#include <regex.h>

namespace pkgaudit {

namespace {

std::string
escape_regex(const std::string& path)
{
  std::string out;

  for (char c : path)
  {
    if (std::strchr(".[]*^$()+?{|}", c))
      out.push_back('\\');

    out.push_back(c);
  }

  return out;
}

} // namespace

ownership_index::ownership_index(const pkgutil& util)
{
  for (const auto& [pkgname, info] : util.getPackages())
  {
    for (const auto& rel : info.files)
    {
      const std::string abs = "/" + rel;
      file_to_owners[abs].insert(pkgname);
      owned_paths.push_back({abs, pkgname});
    }
  }
}

std::set<std::string>
ownership_index::owners_of_exact(const std::string& absolute_path) const
{
  const auto it = file_to_owners.find(absolute_path);
  if (it == file_to_owners.end())
    return {};

  return it->second;
}

std::set<std::string>
ownership_index::owners_matching_pattern_path(const std::string& path_pattern) const
{
  std::set<std::string> owners;
  regex_t preg;

  const std::string pattern = escape_regex(path_pattern);

  if (regcomp(&preg, pattern.c_str(), REG_EXTENDED | REG_NOSUB) != 0)
    return owners;

  for (const auto& [owned_path, pkgname]: owned_paths)
  {
    if (regexec(&preg, owned_path.c_str(), 0, nullptr, 0) == 0)
      owners.insert(pkgname);
  }

  regfree(&preg);
  return owners;
}

} // namespace pkgaudit
