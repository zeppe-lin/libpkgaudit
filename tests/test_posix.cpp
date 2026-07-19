// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include "test.h"

#include <libpkgaudit/libpkgaudit.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

using namespace pkgaudit;
namespace fs = std::filesystem;

namespace {

class temporary_root final
{
public:
  temporary_root()
  {
    char pattern[] = "/tmp/libpkgaudit.XXXXXX";
    char* value = ::mkdtemp(pattern);
    if (!value)
      throw std::runtime_error("mkdtemp failed");
    path_ = value;
  }

  ~temporary_root()
  {
    std::error_code error;
    fs::remove_all(path_, error);
  }

  const fs::path& path() const noexcept { return path_; }

  void directory(const fs::path& relative)
  {
    fs::create_directories(path_ / relative);
  }

  void file(const fs::path& relative, std::string contents = "x")
  {
    fs::create_directories((path_ / relative).parent_path());
    std::ofstream output(path_ / relative, std::ios::binary);
    output << contents;
  }

  void link(const std::string& target, const fs::path& relative)
  {
    fs::create_directories((path_ / relative).parent_path());
    if (::symlink(target.c_str(), (path_ / relative).c_str()) < 0)
      throw std::runtime_error("symlink failed");
  }

private:
  fs::path path_;
};

object_observation observe(filesystem_backend& backend,
                           std::string path, bool resolve = true)
{
  auto result = backend.observe({{1, object_path::parse(path), resolve}});
  REQUIRE(result.size() == 1);
  return std::move(result[0]);
}

} // namespace

TEST_CASE("POSIX backend distinguishes durable object classes")
{
  temporary_root root;
  root.directory("usr/lib");
  root.file("usr/bin/tool");
  root.link("tool", "usr/bin/link");
  ::mkfifo((root.path() / "fifo").c_str(), 0600);

  auto backend = make_posix_filesystem_backend({root.path().string(), 40});
  REQUIRE(*observe(*backend, "usr/lib", false).type ==
          observed_object_type::directory);
  REQUIRE(*observe(*backend, "usr/bin/tool", false).type ==
          observed_object_type::regular);
  REQUIRE(*observe(*backend, "usr/bin/link", false).type ==
          observed_object_type::symlink);
  REQUIRE(*observe(*backend, "fifo", false).type ==
          observed_object_type::other);
  REQUIRE(*observe(*backend, "absent", false).type ==
          observed_object_type::missing);
}

TEST_CASE("relative and absolute symlinks resolve inside the selected root")
{
  temporary_root root;
  root.file("usr/lib/target");
  root.link("../lib/target", "usr/bin/relative");
  root.link("/usr/lib/target", "usr/bin/absolute");

  auto backend = make_posix_filesystem_backend({root.path().string(), 40});
  for (const std::string path : {"usr/bin/relative", "usr/bin/absolute"}) {
    const auto value = observe(*backend, path);
    REQUIRE(value.symlink.has_value());
    REQUIRE(value.symlink->resolution == symlink_resolution::resolved);
    REQUIRE(value.symlink->resolved_path->string() == "usr/lib/target");
  }
}

TEST_CASE("dangling symlinks are observations rather than probe failures")
{
  temporary_root root;
  root.link("missing", "etc/link");
  auto backend = make_posix_filesystem_backend({root.path().string(), 40});
  const auto value = observe(*backend, "etc/link");
  REQUIRE(value.symlink->resolution == symlink_resolution::dangling);
  REQUIRE(!value.symlink->failure.has_value());
}

TEST_CASE("symlink loops are bounded by the configured limit")
{
  temporary_root root;
  root.link("b", "a");
  root.link("a", "b");
  auto backend = make_posix_filesystem_backend({root.path().string(), 4});
  const auto value = observe(*backend, "a");
  REQUIRE(value.symlink->resolution == symlink_resolution::loop);
}

TEST_CASE("relative targets cannot escape the selected root")
{
  temporary_root root;
  root.link("../../outside", "link");
  auto backend = make_posix_filesystem_backend({root.path().string(), 40});
  const auto value = observe(*backend, "link");
  REQUIRE(value.symlink->resolution == symlink_resolution::outside_root);
}

TEST_CASE("unrepresentable target paths become explicit failures")
{
  temporary_root root;
  root.link("bad\nname", "link");
  auto backend = make_posix_filesystem_backend({root.path().string(), 40});
  const auto value = observe(*backend, "link");
  REQUIRE(value.symlink->resolution == symlink_resolution::failed);
  REQUIRE(value.symlink->failure->error == probe_error::unrepresentable_path);
}

TEST_CASE("invalid roots and zero limits are rejected")
{
  REQUIRE_THROWS_AS(
      make_posix_filesystem_backend({"/definitely/absent/libpkgaudit", 40}),
      audit_error);

  temporary_root root;
  REQUIRE_THROWS_AS(
      make_posix_filesystem_backend({root.path().string(), 0}), audit_error);
}

int main()
{
  return test::run_all();
}
