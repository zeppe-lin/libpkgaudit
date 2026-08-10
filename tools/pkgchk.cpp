// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include "pkgstate_adapter.h"

#include "pkgchk-config.h"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <getopt.h>

#include <libpkgaudit/libpkgaudit.h>
#include <libpkgstate-posix/canonical_generation_store.h>
#include <libpkgstate/state_target_binding.h>

namespace {

constexpr int findings_status = 1;
constexpr int usage_status = 2;

enum long_option_value {
  managed_target_option = 1000,
  state_store_option,
  root_view_option,
  state_backend_option,
  publication_domain_option,
};

enum class mode
{
  none,
  links,
  disappeared,
  audit,
};

struct options final
{
  mode selected{mode::none};
  std::filesystem::path root{"/"};
  std::filesystem::path canonical_store;
  std::optional<std::string> managed_target;
  std::optional<std::string> state_store;
  std::optional<std::string> root_view;
  std::optional<std::string> state_backend;
  std::optional<std::string> publication_domain;
  int verbosity{0};
  std::vector<std::string> packages;
};

void
print_help(std::ostream& out)
{
  out << R"(Usage:
  pkgchk {-l | -d | -a} --canonical-store path \
    --managed-target identity --state-store identity \
    --root-view identity --state-backend identity \
    --publication-domain identity [-r root-dir] [-v] [package ...]
  pkgchk {-V | -h}

Audit installed package objects against canonical native installed state.

Exactly one audit mode is required:
  -l, --links              Check symlink resolution and ownership
  -d, --disappeared        Check object presence and durable class
  -a, --audit              Run all checks

State authority:
  -c, --canonical-store=path
                           Open an existing canonical generation store
      --managed-target=id  Managed package-target identity
      --state-store=id     Durable installed-state store identity
      --root-view=id       Logical target root-view identity
      --state-backend=id   Installed-state backend identity
      --publication-domain=id
                           Publication and locking-domain identity

Other options:
  -r, --root=root-dir      Inspect objects beneath an alternate target root
  -v                       Increase presentation detail (repeatable)
  -V, --version            Print version and exit
  -h, --help               Print this help and exit

The command is read-only with respect to installed state: it never initializes,
publishes, repairs, imports, or reconstructs a state store. With no package
arguments, all installed packages are audited. Exit status is 0 for a complete
audit without integrity findings, 1 when integrity findings were reported, and
2 for usage, state, or incomplete-audit failures.
)";
}

void
print_version()
{
  std::cout << "pkgchk (libpkgaudit) " << LIBPKGAUDIT_VERSION << '\n';
}

void
select_mode(options& parsed, mode selected)
{
  if (parsed.selected != mode::none)
    throw std::invalid_argument("exactly one audit mode is required");
  parsed.selected = selected;
}

void
set_identity(std::optional<std::string>& destination,
             const char* value,
             std::string_view option_name)
{
  if (destination)
    throw std::invalid_argument(std::string(option_name) + " specified twice");
  destination = value;
}

options
parse_options(int argc, char** argv)
{
  options parsed;
  static const option long_options[] = {
      {"links", no_argument, nullptr, 'l'},
      {"disappeared", no_argument, nullptr, 'd'},
      {"audit", no_argument, nullptr, 'a'},
      {"canonical-store", required_argument, nullptr, 'c'},
      {"managed-target", required_argument, nullptr, managed_target_option},
      {"state-store", required_argument, nullptr, state_store_option},
      {"root-view", required_argument, nullptr, root_view_option},
      {"state-backend", required_argument, nullptr, state_backend_option},
      {"publication-domain", required_argument, nullptr,
       publication_domain_option},
      {"root", required_argument, nullptr, 'r'},
      {"version", no_argument, nullptr, 'V'},
      {"help", no_argument, nullptr, 'h'},
      {nullptr, 0, nullptr, 0},
  };

  opterr = 0;
  for (;;) {
    const int value = getopt_long(argc, argv, "ldac:r:vVh", long_options, nullptr);
    if (value == -1)
      break;

    switch (value) {
      case 'l':
        select_mode(parsed, mode::links);
        break;
      case 'd':
        select_mode(parsed, mode::disappeared);
        break;
      case 'a':
        select_mode(parsed, mode::audit);
        break;
      case 'c':
        if (!parsed.canonical_store.empty())
          throw std::invalid_argument("--canonical-store specified twice");
        parsed.canonical_store = optarg;
        break;
      case managed_target_option:
        set_identity(parsed.managed_target, optarg, "--managed-target");
        break;
      case state_store_option:
        set_identity(parsed.state_store, optarg, "--state-store");
        break;
      case root_view_option:
        set_identity(parsed.root_view, optarg, "--root-view");
        break;
      case state_backend_option:
        set_identity(parsed.state_backend, optarg, "--state-backend");
        break;
      case publication_domain_option:
        set_identity(parsed.publication_domain, optarg,
                     "--publication-domain");
        break;
      case 'r':
        parsed.root = optarg;
        break;
      case 'v':
        ++parsed.verbosity;
        break;
      case 'V':
        print_version();
        std::exit(EXIT_SUCCESS);
      case 'h':
        print_help(std::cout);
        std::exit(EXIT_SUCCESS);
      default:
        throw std::invalid_argument("invalid command-line option");
    }
  }

  if (parsed.selected == mode::none)
    throw std::invalid_argument("audit mode is required");
  if (parsed.root.empty())
    throw std::invalid_argument("root directory must not be empty");
  if (parsed.canonical_store.empty())
    throw std::invalid_argument("--canonical-store is required");
  if (!parsed.managed_target || !parsed.state_store || !parsed.root_view ||
      !parsed.state_backend || !parsed.publication_domain) {
    throw std::invalid_argument(
        "all canonical target-binding identities are required");
  }

  for (int index = optind; index < argc; ++index)
    parsed.packages.emplace_back(argv[index]);
  return parsed;
}

pkgstate::state_target_binding
parse_binding(const options& parsed)
{
  return pkgstate::state_target_binding::make(
      pkgstate::managed_target_identity::parse(*parsed.managed_target),
      pkgstate::state_store_identity::parse(*parsed.state_store),
      pkgstate::root_view_identity::parse(*parsed.root_view),
      pkgstate::state_backend_identity::parse(*parsed.state_backend),
      pkgstate::publication_domain_identity::parse(
          *parsed.publication_domain));
}

pkgaudit::audit_request
make_request(const options& parsed)
{
  pkgaudit::check_set checks;
  if (parsed.selected == mode::disappeared || parsed.selected == mode::audit)
    checks.add(pkgaudit::check::object_state);
  if (parsed.selected == mode::links || parsed.selected == mode::audit) {
    checks.add(pkgaudit::check::symlink_resolution);
    checks.add(pkgaudit::check::symlink_ownership);
  }

  return {
      parsed.packages.empty()
          ? pkgaudit::package_selection::all()
          : pkgaudit::package_selection::only(parsed.packages),
      checks,
  };
}

std::string
logical(const pkgaudit::object_path& path)
{
  return "/" + path.string();
}

std::string
join(const std::vector<std::string>& values)
{
  if (values.empty())
    return "none";
  std::string result;
  for (const auto& value : values) {
    if (!result.empty())
      result += ',';
    result += value;
  }
  return result;
}

const char*
probe_operation_name(pkgaudit::probe_operation operation)
{
  switch (operation) {
    case pkgaudit::probe_operation::inspect_object:
      return "inspect object";
    case pkgaudit::probe_operation::read_symlink:
      return "read symlink";
    case pkgaudit::probe_operation::resolve_symlink:
      return "resolve symlink";
  }
  return "probe";
}

const char*
probe_error_name(pkgaudit::probe_error error)
{
  switch (error) {
    case pkgaudit::probe_error::permission_denied:
      return "permission denied";
    case pkgaudit::probe_error::io_error:
      return "I/O error";
    case pkgaudit::probe_error::object_changed:
      return "object changed during observation";
    case pkgaudit::probe_error::too_many_symlinks:
      return "too many symlinks";
    case pkgaudit::probe_error::outside_root:
      return "target outside selected root";
    case pkgaudit::probe_error::unrepresentable_path:
      return "target path is not representable";
  }
  return "probe error";
}

void
print_finding(const pkgaudit::finding& finding)
{
  std::cerr << "pkgchk: " << finding.package << ": ";
  switch (finding.kind) {
    case pkgaudit::finding_kind::missing_object:
      std::cerr << "missing object " << logical(finding.path);
      break;
    case pkgaudit::finding_kind::object_class_mismatch:
      std::cerr << "object class mismatch at " << logical(finding.path);
      break;
    case pkgaudit::finding_kind::dangling_symlink:
      std::cerr << "dangling symlink " << logical(finding.path)
                << " -> " << finding.target;
      break;
    case pkgaudit::finding_kind::symlink_loop:
      std::cerr << "symlink loop at " << logical(finding.path)
                << " -> " << finding.target;
      break;
    case pkgaudit::finding_kind::symlink_target_outside_root:
      std::cerr << "symlink target escapes selected root at "
                << logical(finding.path) << " -> " << finding.target;
      break;
  }
  std::cerr << '\n';
}

void
print_relation(const pkgaudit::ownership_relation& relation, int verbosity)
{
  if (relation.kind ==
      pkgaudit::ownership_relation_kind::source_package_owns_target)
    return;

  std::cerr << "pkgchk: " << relation.package << ": warning: symlink "
            << logical(relation.path) << " -> " << relation.target;
  if (relation.kind ==
      pkgaudit::ownership_relation_kind::other_package_owns_target) {
    std::cerr << " resolves to an object owned by another package";
  } else {
    std::cerr << " resolves to an unowned object";
  }
  std::cerr << '\n';

  if (verbosity > 0) {
    std::cerr << "  immediate owners: " << join(relation.immediate_owners)
              << '\n';
    std::cerr << "  resolved owners: " << join(relation.resolved_owners)
              << '\n';
  }
}

void
print_failure(const pkgaudit::audit_failure& failure)
{
  std::cerr << "pkgchk: ";
  if (failure.package)
    std::cerr << *failure.package << ": ";
  std::cerr << logical(failure.path) << ": ";

  if (failure.kind ==
      pkgaudit::audit_failure_kind::backend_contract_violation) {
    std::cerr << "filesystem backend contract violation";
  } else {
    std::cerr << probe_operation_name(*failure.operation) << ": "
              << probe_error_name(*failure.error);
    if (failure.system_error != 0)
      std::cerr << " (errno " << failure.system_error << ')';
  }
  std::cerr << '\n';
}

} // namespace

int
main(int argc, char** argv)
{
  options parsed;
  try {
    parsed = parse_options(argc, argv);
  } catch (const std::invalid_argument& error) {
    std::cerr << "pkgchk: " << error.what() << '\n';
    print_help(std::cerr);
    return usage_status;
  }

  try {
    const pkgstate::state_target_binding binding = parse_binding(parsed);
    const pkgstate::posix::canonical_generation_store store =
        pkgstate::posix::canonical_generation_store::open_existing(
            parsed.canonical_store, binding);
    const pkgstate::snapshot state = store.read();
    const pkgaudit::inventory facts = pkgchk::make_inventory(state);
    auto filesystem = pkgaudit::make_posix_filesystem_backend(
        {parsed.root.string(), 40});

    const pkgaudit::report result =
        pkgaudit::auditor().run(facts, make_request(parsed), *filesystem);

    for (const auto& finding : result.findings())
      print_finding(finding);
    for (const auto& relation : result.relations())
      print_relation(relation, parsed.verbosity);
    for (const auto& failure : result.failures())
      print_failure(failure);

    if (!result.complete())
      return usage_status;
    return result.findings().empty() ? EXIT_SUCCESS : findings_status;
  } catch (const std::exception& error) {
    std::cerr << "pkgchk: " << error.what() << '\n';
    return usage_status;
  }
}
