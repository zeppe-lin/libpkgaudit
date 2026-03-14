#pragma once

#include <set>
#include <string>
#include <vector>

namespace pkgaudit {

enum class severity
{
  warning,
  error
};

enum class issue_kind
{
  broken_symlink,
  foreign_symlink_target,
  disappeared_file
};

struct issue
{
  severity level{severity::warning};
  issue_kind kind{issue_kind::broken_symlink};

  std::string package;
  std::string path;
  std::string target;
  std::string message;

  std::set<std::string> immediate_owners;
  std::set<std::string> resolved_owners;
};

struct options
{
  std::string root;
  bool check_links{false};
  bool check_disappeared{false};
  int verbosity{0};
};

} // namespace pkgaudit
