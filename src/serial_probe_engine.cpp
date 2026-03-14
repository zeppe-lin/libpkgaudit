#include <libpkgaudit/probe.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libgen.h>

#include <memory>
#include <string>
#include <vector>

#include <libpkgcore/pkgcore.h>

namespace pkgaudit {
namespace {

[[nodiscard]] std::string
parent_dir(const std::string& path)
{
  char* dup = ::strdup(path.c_str());
  if (!dup)
    return ".";

  const std::string out(::dirname(dup));
  ::free(dup);
  return out;
}

class serial_probe_engine final : public probe_engine
{
public:
  std::vector<symlink_probe>
  probe_symlinks(const std::vector<std::string>& paths) override
  {
    std::vector<symlink_probe> out;
    out.reserve(paths.size());

    for (const auto& full : paths)
    {
      symlink_probe r;
      r.path = full;

      struct stat st {};
      if (::lstat(full.c_str(), &st) == -1)
      {
        out.push_back(std::move(r));
        continue;
      }

      r.lstat_ok = true;
      r.is_symlink = S_ISLNK(st.st_mode);

      if (!r.is_symlink)
      {
        out.push_back(std::move(r));
        continue;
      }

      char buf[PATH_MAX];
      const ssize_t len = ::readlink(full.c_str(), buf, sizeof(buf) - 1);
      if (len == -1)
      {
        out.push_back(std::move(r));
        continue;
      }

      buf[len] = '\0';
      r.readlink_ok = true;
      r.target = buf;

      if (!r.target.empty() && r.target[0] == '/')
        r.immediate_path = trim_filename(r.target);
      else
        r.immediate_path = trim_filename(parent_dir(full) + "/" + r.target);

      r.immediate_exists = file_exists(r.immediate_path);

      char* resolved = ::realpath(r.immediate_path.c_str(), nullptr);
      if (resolved != nullptr)
      {
        r.resolved_ok = true;
        r.resolved_path = resolved;
        ::free(resolved);
      }

      out.push_back(std::move(r));
    }

    return out;
  }

  std::vector<exists_probe>
  probe_exists(const std::vector<std::string>& paths) override
  {
    std::vector<exists_probe> out;
    out.reserve(paths.size());

    for (const auto& full : paths)
    {
      exists_probe r;
      r.path = full;
      r.exists = file_exists(full);
      out.push_back(std::move(r));
    }

    return out;
  }
};

} // namespace

std::unique_ptr<probe_engine>
make_serial_probe_engine()
{
  return std::make_unique<serial_probe_engine>();
}

} // namespace pkgaudit
