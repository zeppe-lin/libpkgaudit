#include <libpkgaudit/audit.h>

#include <libpkgaudit/error.h>

#include <algorithm>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>

namespace pkgaudit {
namespace {

struct request_record final
{
  observation_request request;
  const object_observation* response{nullptr};
};

bool
contains_owner(const std::vector<std::string>& owners,
               const std::string& package)
{
  return std::binary_search(owners.begin(), owners.end(), package);
}

std::vector<std::string>
copy_owners(const inventory& facts, const std::optional<object_path>& path)
{
  std::vector<std::string> result;
  if (!path)
    return result;

  for (const std::string_view owner : facts.owners(*path))
    result.emplace_back(owner);
  return result;
}

void
sort_report(std::vector<finding>& findings,
            std::vector<ownership_relation>& relations,
            std::vector<audit_failure>& failures)
{
  std::sort(findings.begin(), findings.end(),
            [](const finding& lhs, const finding& rhs) {
              if (lhs.package != rhs.package)
                return lhs.package < rhs.package;
              if (lhs.path != rhs.path)
                return lhs.path < rhs.path;
              return lhs.kind < rhs.kind;
            });

  std::sort(relations.begin(), relations.end(),
            [](const ownership_relation& lhs,
               const ownership_relation& rhs) {
              if (lhs.package != rhs.package)
                return lhs.package < rhs.package;
              if (lhs.path != rhs.path)
                return lhs.path < rhs.path;
              return lhs.kind < rhs.kind;
            });

  std::sort(failures.begin(), failures.end(),
            [](const audit_failure& lhs, const audit_failure& rhs) {
              if (lhs.package != rhs.package)
                return lhs.package < rhs.package;
              if (lhs.path != rhs.path)
                return lhs.path < rhs.path;
              return lhs.kind < rhs.kind;
            });
}

} // namespace

report
auditor::run(const inventory& facts,
             const audit_request& request,
             filesystem_backend& filesystem) const
{
  if (request.checks.empty())
    throw audit_error("audit request contains no checks");

  std::vector<const package_facts*> selected;
  if (request.packages.selects_all()) {
    for (const auto& package : facts.packages())
      selected.push_back(&package);
  } else {
    for (const auto& name : request.packages.packages()) {
      const auto* package = facts.find_package(name);
      if (!package)
        throw inventory_error("selected package is absent: " + name);
      selected.push_back(package);
    }
  }

  const bool resolve = request.checks.contains(check::symlink_resolution) ||
                       request.checks.contains(check::symlink_ownership);

  std::map<std::string, object_path> unique_paths;
  for (const auto* package : selected) {
    for (const auto& object : package->objects())
      unique_paths.emplace(object.path.string(), object.path);
  }

  std::vector<request_record> records;
  records.reserve(unique_paths.size());
  observation_id next_id = 1;
  for (const auto& [spelling, path] : unique_paths) {
    (void)spelling;
    records.push_back({observation_request{next_id++, path, resolve}, nullptr});
  }

  std::vector<observation_request> requests;
  requests.reserve(records.size());
  for (const auto& record : records)
    requests.push_back(record.request);

  const auto responses = filesystem.observe(requests);
  std::unordered_map<observation_id, std::size_t> by_id;
  for (std::size_t index = 0; index < records.size(); ++index)
    by_id.emplace(records[index].request.id, index);

  std::vector<finding> findings;
  std::vector<ownership_relation> relations;
  std::vector<audit_failure> failures;
  std::set<observation_id> contract_failed;

  for (const auto& response : responses) {
    const auto found = by_id.find(response.id);
    if (found == by_id.end()) {
      failures.push_back({audit_failure_kind::backend_contract_violation,
                          std::nullopt, response.path, std::nullopt,
                          std::nullopt, 0});
      continue;
    }

    request_record& record = records[found->second];
    if (contract_failed.count(response.id))
      continue;

    if (record.response != nullptr || response.path != record.request.path) {
      contract_failed.insert(response.id);
      record.response = nullptr;
      failures.push_back({audit_failure_kind::backend_contract_violation,
                          std::nullopt, record.request.path, std::nullopt,
                          std::nullopt, 0});
      continue;
    }

    record.response = &response;
  }

  for (auto& record : records) {
    if (record.response == nullptr && !contract_failed.count(record.request.id)) {
      contract_failed.insert(record.request.id);
      failures.push_back({audit_failure_kind::backend_contract_violation,
                          std::nullopt, record.request.path, std::nullopt,
                          std::nullopt, 0});
      continue;
    }

    if (record.response == nullptr)
      continue;

    const object_observation& response = *record.response;
    bool valid = true;
    if (response.failure) {
      valid = !response.type && !response.symlink;
    } else if (!response.type) {
      valid = false;
    } else if (*response.type != observed_object_type::symlink) {
      valid = !response.symlink;
    } else if (!record.request.resolve_symlink) {
      valid = !response.symlink;
    } else if (!response.symlink) {
      valid = false;
    } else if (response.symlink->failure) {
      valid = response.symlink->resolution == symlink_resolution::failed;
    } else {
      valid = response.symlink->resolution != symlink_resolution::failed &&
              response.symlink->resolution != symlink_resolution::not_requested;
    }

    if (!valid) {
      contract_failed.insert(record.request.id);
      record.response = nullptr;
      failures.push_back({audit_failure_kind::backend_contract_violation,
                          std::nullopt, record.request.path, std::nullopt,
                          std::nullopt, 0});
    }
  }

  std::unordered_map<std::string, const request_record*> by_path;
  for (const auto& record : records)
    by_path.emplace(record.request.path.string(), &record);

  for (const auto* package : selected) {
    for (const auto& expected : package->objects()) {
      const request_record& record = *by_path.at(expected.path.string());
      if (!record.response)
        continue;

      const object_observation& observed = *record.response;
      if (observed.failure) {
        failures.push_back({audit_failure_kind::probe_failed,
                            package->package(), expected.path,
                            observed.failure->operation,
                            observed.failure->error,
                            observed.failure->system_error});
        continue;
      }

      if (request.checks.contains(check::object_state)) {
        if (*observed.type == observed_object_type::missing) {
          findings.push_back({finding_kind::missing_object,
                              package->package(), expected.path, expected.type,
                              observed.type, {}});
        } else {
          const bool expected_directory =
              expected.type == expected_object_type::directory;
          const bool observed_directory =
              *observed.type == observed_object_type::directory;
          if (expected_directory != observed_directory) {
            findings.push_back({finding_kind::object_class_mismatch,
                                package->package(), expected.path, expected.type,
                                observed.type, {}});
          }
        }
      }

      if (*observed.type != observed_object_type::symlink || !resolve)
        continue;

      const symlink_observation& link = *observed.symlink;
      if (link.failure) {
        failures.push_back({audit_failure_kind::probe_failed,
                            package->package(), expected.path,
                            link.failure->operation,
                            link.failure->error,
                            link.failure->system_error});
        continue;
      }

      if (request.checks.contains(check::symlink_resolution)) {
        std::optional<finding_kind> kind;
        switch (link.resolution) {
          case symlink_resolution::dangling:
            kind = finding_kind::dangling_symlink;
            break;
          case symlink_resolution::loop:
            kind = finding_kind::symlink_loop;
            break;
          case symlink_resolution::outside_root:
            kind = finding_kind::symlink_target_outside_root;
            break;
          default:
            break;
        }
        if (kind) {
          findings.push_back({*kind, package->package(), expected.path,
                              expected.type, observed.type, link.target});
        }
      }

      if (!request.checks.contains(check::symlink_ownership) ||
          link.resolution != symlink_resolution::resolved)
        continue;

      auto immediate = copy_owners(facts, link.immediate_path);
      auto resolved = copy_owners(facts, link.resolved_path);
      ownership_relation_kind kind = ownership_relation_kind::target_is_unowned;
      if (contains_owner(immediate, package->package()) ||
          contains_owner(resolved, package->package())) {
        kind = ownership_relation_kind::source_package_owns_target;
      } else if (!immediate.empty() || !resolved.empty()) {
        kind = ownership_relation_kind::other_package_owns_target;
      }

      relations.push_back({kind, package->package(), expected.path, link.target,
                           link.immediate_path, link.resolved_path,
                           std::move(immediate), std::move(resolved)});
    }
  }

  sort_report(findings, relations, failures);
  return report(std::move(findings), std::move(relations), std::move(failures));
}

} // namespace pkgaudit
