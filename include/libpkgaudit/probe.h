#pragma once

#include <memory>
#include <string>
#include <vector>

namespace pkgaudit {

struct symlink_probe
{
  std::string path;

  bool lstat_ok{false};
  bool is_symlink{false};

  bool readlink_ok{false};
  std::string target;

  std::string immediate_path;
  bool immediate_exists{false};

  bool resolved_ok{false};
  std::string resolved_path;
};

struct exists_probe
{
  std::string path;
  bool exists{false};
};

class probe_engine
{
public:
  virtual ~probe_engine() = default;

  virtual std::vector<symlink_probe>
  probe_symlinks(const std::vector<std::string>& paths) = 0;

  virtual std::vector<exists_probe>
  probe_exists(const std::vector<std::string>& paths) = 0;
};

std::unique_ptr<probe_engine> make_serial_probe_engine();

} // namespace pkgaudit
