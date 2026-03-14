#pragma once

#include <string>
#include <vector>

#include <libpkgcore/pkgcore.h>

#include <libpkgaudit/ownership_index.h>
#include <libpkgaudit/probe.h>
#include <libpkgaudit/types.h>

namespace pkgaudit {

class auditor
{
public:
  auditor(pkgutil& util, probe_engine& engine);

  [[nodiscard]] std::vector<issue>
  audit_package(const std::string& pkgname, const options& opts) const;

private:
  pkgutil& util;
  probe_engine& engine;
  ownership_index owners;

  [[nodiscard]] std::vector<issue>
  audit_links(const std::string& pkgname, const options& opts) const;

  [[nodiscard]] std::vector<issue>
  audit_disappeared(const std::string& pkgname, const options& opts) const;

  [[nodiscard]] static std::string
  strip_root(const std::string& path, const std::string& root);

  [[nodiscard]] static std::string
  join_owners(const std::set<std::string>& names);
};

} // namespace pkgaudit
