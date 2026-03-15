#include <libpkgaudit/auditor.h>

#include <sstream>
#include <stdexcept>

namespace pkgaudit {

auditor::auditor(pkgutil& util_, probe_engine& engine_)
  : util(util_)
  , engine(engine_)
  , owners(util_)
{
}

std::string
auditor::strip_root(const std::string& path, const std::string& root)
{
  if (!root.empty() && path.rfind(root, 0) == 0)
    return path.substr(root.size());

  return path;
}

std::string
auditor::join_owners(const std::set<std::string>& names)
{
  if (names.empty())
    return "none";

  std::ostringstream ss;
  for (auto it = names.begin(); it != names.end(); ++it)
  {
    if (it != names.begin())
      ss << ",";
    ss << *it;
  }
  return ss.str();
}

std::vector<issue>
auditor::audit_package(const std::string& pkgname, const options& opts) const
{
  std::vector<issue> out;

  if (opts.check_links)
  {
    auto v = audit_links(pkgname, opts);
    out.insert(out.end(), v.begin(), v.end());
  }

  if (opts.check_disappeared)
  {
    auto v = audit_disappeared(pkgname, opts);
    out.insert(out.end(), v.begin(), v.end());
  }

  return out;
}

std::vector<issue>
auditor::audit_links(const std::string& pkgname, const options& opts) const
{
  const auto& pkgs = util.getPackages();
  const auto it = pkgs.find(pkgname);
  if (it == pkgs.end())
    throw std::runtime_error("package not found: " + pkgname);

  std::vector<std::string> full_paths;
  full_paths.reserve(it->second.files.size());

  for (const auto& rel : it->second.files)
    full_paths.push_back(opts.root + "/" + rel);

  const auto probed = engine.probe_symlinks(full_paths, opts.root);

  std::vector<issue> out;
  out.reserve(probed.size());

  for (const auto& p : probed)
  {
    if (!p.lstat_ok || !p.is_symlink || !p.readlink_ok)
      continue;

    if (!p.immediate_exists)
    {
      issue i;
      i.level = severity::error;
      i.kind = issue_kind::broken_symlink;
      i.package = pkgname;
      i.path = p.path;
      i.target = p.target;
      i.message = p.path + " -> " + p.target + " (broken)";
      out.push_back(std::move(i));
      continue;
    }

    const auto imm_rel = strip_root(p.immediate_path, opts.root);
    const auto res_rel = strip_root(
      p.resolved_ok ? p.resolved_path : p.immediate_path, opts.root);

    const auto imm_owners = owners.owners_of(imm_rel);
    const auto res_owners = owners.owners_of(res_rel);

    if (imm_owners.count(pkgname) || res_owners.count(pkgname))
      continue;

    issue i;
    i.level = severity::warning;
    i.kind = issue_kind::foreign_symlink_target;
    i.package = pkgname;
    i.path = p.path;
    i.target = p.target;
    i.immediate_owners = imm_owners;
    i.resolved_owners = res_owners;

    if (opts.verbosity > 0)
    {
      i.message = p.path + " -> " + p.target +
                  " (points to " + join_owners(imm_owners) +
                  ", resolves into " + join_owners(res_owners) + ")";
    }
    else
    {
      i.message = p.path + " -> " + p.target;
    }

    out.push_back(std::move(i));
  }

  return out;
}

std::vector<issue>
auditor::audit_disappeared(const std::string& pkgname, const options& opts) const
{
  const auto& pkgs = util.getPackages();
  const auto it = pkgs.find(pkgname);
  if (it == pkgs.end())
    throw std::runtime_error("package not found: " + pkgname);

  std::vector<std::string> rel_paths;
  std::vector<std::string> full_paths;
  rel_paths.reserve(it->second.files.size());
  full_paths.reserve(it->second.files.size());

  for (const auto& rel : it->second.files)
  {
    rel_paths.push_back("/" + rel);
    full_paths.push_back(opts.root + "/" + rel);
  }

  const auto probed = engine.probe_exists(full_paths);

  std::vector<issue> out;
  out.reserve(probed.size());

  for (std::size_t i = 0; i < probed.size(); ++i)
  {
    if (probed[i].exists)
      continue;

    issue is;
    is.level = severity::error;
    is.kind = issue_kind::disappeared_file;
    is.package = pkgname;
    is.path = probed[i].path;
    is.message = "disappeared file " + probed[i].path;

    if (opts.verbosity > 0)
      is.immediate_owners = owners.owners_of(rel_paths[i]);

    out.push_back(std::move(is));
  }

  return out;
}

} // namespace pkgaudit
