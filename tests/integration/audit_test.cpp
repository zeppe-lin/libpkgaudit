// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include "support/test.hpp"

#include <libpkgaudit/libpkgaudit.h>

#include <algorithm>
#include <functional>
#include <utility>

using namespace pkgaudit;

namespace {

class scripted_backend final : public filesystem_backend
{
public:
  using script = std::function<std::vector<object_observation>(
      const std::vector<observation_request>&)>;

  explicit scripted_backend(script run)
    : run_(std::move(run))
  {
  }

  std::vector<object_observation>
  observe(const std::vector<observation_request>& requests) override
  {
    last_requests = requests;
    return run_(requests);
  }

  std::vector<observation_request> last_requests;

private:
  script run_;
};

inventory sample_inventory()
{
  return inventory({
      package_facts("alpha", {
          {object_path::parse("etc/alpha"), expected_object_type::non_directory},
          {object_path::parse("usr/bin/shared"), expected_object_type::non_directory},
          {object_path::parse("usr/lib"), expected_object_type::directory},
      }),
      package_facts("beta", {
          {object_path::parse("usr/bin/shared"), expected_object_type::non_directory},
          {object_path::parse("usr/lib/target"), expected_object_type::non_directory},
      }),
  });
}

object_observation observed(const observation_request& request,
                            observed_object_type type)
{
  return {request.id, request.path, type, std::nullopt, std::nullopt};
}

} // namespace

TEST_CASE("object-state audit reports missing and class mismatch facts")
{
  scripted_backend backend([](const auto& requests) {
    std::vector<object_observation> result;
    for (const auto& request : requests) {
      if (request.path.string() == "etc/alpha")
        result.push_back(observed(request, observed_object_type::missing));
      else if (request.path.string() == "usr/lib")
        result.push_back(observed(request, observed_object_type::regular));
      else
        result.push_back(observed(request, observed_object_type::regular));
    }
    std::reverse(result.begin(), result.end());
    return result;
  });

  audit_request request{package_selection::only({"alpha"}),
                        check_set{check::object_state}};
  const auto result = auditor().run(sample_inventory(), request, backend);

  REQUIRE(result.complete());
  REQUIRE(result.findings().size() == 2);
  REQUIRE(result.findings()[0].kind == finding_kind::missing_object);
  REQUIRE(result.findings()[1].kind == finding_kind::object_class_mismatch);
}

TEST_CASE("shared objects are probed once and reported for each owner")
{
  scripted_backend backend([](const auto& requests) {
    std::vector<object_observation> result;
    for (const auto& request : requests)
      result.push_back(observed(request, observed_object_type::missing));
    return result;
  });

  audit_request request{package_selection::only({"beta", "alpha"}),
                        check_set{check::object_state}};
  const auto result = auditor().run(sample_inventory(), request, backend);

  REQUIRE(backend.last_requests.size() == 4);
  std::size_t shared = 0;
  for (const auto& request_value : backend.last_requests) {
    if (request_value.path.string() == "usr/bin/shared")
      ++shared;
  }
  REQUIRE(shared == 1);

  std::size_t shared_findings = 0;
  for (const auto& value : result.findings()) {
    if (value.path.string() == "usr/bin/shared")
      ++shared_findings;
  }
  REQUIRE(shared_findings == 2);
}

TEST_CASE("symlink ownership is returned as a neutral relation")
{
  scripted_backend backend([](const auto& requests) {
    std::vector<object_observation> result;
    for (const auto& request : requests) {
      auto value = observed(request, observed_object_type::regular);
      if (request.path.string() == "etc/alpha") {
        value.type = observed_object_type::symlink;
        value.symlink = symlink_observation{
            "/usr/lib/target",
            object_path::parse("usr/lib/target"),
            object_path::parse("usr/lib/target"),
            symlink_resolution::resolved,
            std::nullopt};
      }
      result.push_back(std::move(value));
    }
    return result;
  });

  audit_request request{package_selection::only({"alpha"}),
                        check_set{check::symlink_ownership}};
  const auto result = auditor().run(sample_inventory(), request, backend);

  REQUIRE(result.complete());
  REQUIRE(result.relations().size() == 1);
  REQUIRE(result.relations()[0].kind ==
          ownership_relation_kind::other_package_owns_target);
  REQUIRE(result.relations()[0].resolved_owners.size() == 1);
  REQUIRE(result.relations()[0].resolved_owners[0] == "beta");
}

TEST_CASE("symlink resolution states become typed findings")
{
  scripted_backend backend([](const auto& requests) {
    std::vector<object_observation> result;
    for (const auto& request : requests) {
      auto value = observed(request, observed_object_type::symlink);
      value.symlink = symlink_observation{"missing", std::nullopt, std::nullopt,
                                           symlink_resolution::dangling,
                                           std::nullopt};
      result.push_back(std::move(value));
    }
    return result;
  });

  audit_request request{package_selection::only({"alpha"}),
                        check_set{check::symlink_resolution}};
  const auto result = auditor().run(sample_inventory(), request, backend);
  REQUIRE(result.findings().size() == 3);
  for (const auto& value : result.findings())
    REQUIRE(value.kind == finding_kind::dangling_symlink);
}

TEST_CASE("probe errors make an audit incomplete")
{
  scripted_backend backend([](const auto& requests) {
    std::vector<object_observation> result;
    for (const auto& request : requests) {
      result.push_back({request.id, request.path, std::nullopt, std::nullopt,
                        probe_failure{probe_operation::inspect_object,
                                      probe_error::permission_denied, 13}});
    }
    return result;
  });

  audit_request request{package_selection::only({"alpha"}),
                        check_set{check::object_state}};
  const auto result = auditor().run(sample_inventory(), request, backend);
  REQUIRE(!result.complete());
  REQUIRE(result.failures().size() == 3);
  REQUIRE(result.failures()[0].kind == audit_failure_kind::probe_failed);
}

TEST_CASE("missing duplicate and mismatched backend responses are rejected")
{
  scripted_backend backend([](const auto& requests) {
    auto first = observed(requests[0], observed_object_type::regular);
    auto duplicate = first;
    auto mismatch = observed(requests[1], observed_object_type::regular);
    mismatch.path = requests[0].path;
    return std::vector<object_observation>{first, duplicate, mismatch};
  });

  audit_request request{package_selection::only({"alpha"}),
                        check_set{check::object_state}};
  const auto result = auditor().run(sample_inventory(), request, backend);
  REQUIRE(!result.complete());
  REQUIRE(result.failures().size() == 3);
  for (const auto& value : result.failures())
    REQUIRE(value.kind == audit_failure_kind::backend_contract_violation);
}

TEST_CASE("unknown selected packages are rejected before probing")
{
  scripted_backend backend([](const auto&) {
    return std::vector<object_observation>{};
  });
  audit_request request{package_selection::only({"ghost"}),
                        check_set{check::object_state}};
  REQUIRE_THROWS_AS(auditor().run(sample_inventory(), request, backend),
                    inventory_error);
  REQUIRE(backend.last_requests.empty());
}


TEST_CASE("unknown backend response identifiers are explicit contract failures")
{
  scripted_backend backend([](const auto& requests) {
    auto valid = observed(requests[0], observed_object_type::regular);
    auto unknown = valid;
    unknown.id = 999999;
    return std::vector<object_observation>{valid, unknown};
  });

  audit_request request{package_selection::only({"alpha"}),
                        check_set{check::object_state}};
  const auto result = auditor().run(sample_inventory(), request, backend);
  REQUIRE(!result.complete());
  REQUIRE(result.failures().size() == 3);
}

TEST_CASE("symlink ownership distinguishes source-owned and unowned targets")
{
  scripted_backend backend([](const auto& requests) {
    std::vector<object_observation> result;
    for (const auto& request : requests) {
      auto value = observed(request, observed_object_type::regular);
      if (request.path.string() == "etc/alpha") {
        value.type = observed_object_type::symlink;
        value.symlink = symlink_observation{
            "/usr/bin/shared", object_path::parse("usr/bin/shared"),
            object_path::parse("usr/bin/shared"),
            symlink_resolution::resolved, std::nullopt};
      } else if (request.path.string() == "usr/bin/shared") {
        value.type = observed_object_type::symlink;
        value.symlink = symlink_observation{
            "/unowned", object_path::parse("unowned"),
            object_path::parse("unowned"),
            symlink_resolution::resolved, std::nullopt};
      }
      result.push_back(std::move(value));
    }
    return result;
  });

  audit_request request{package_selection::only({"alpha"}),
                        check_set{check::symlink_ownership}};
  const auto result = auditor().run(sample_inventory(), request, backend);
  REQUIRE(result.relations().size() == 2);
  REQUIRE(result.relations()[0].kind ==
          ownership_relation_kind::source_package_owns_target);
  REQUIRE(result.relations()[1].kind ==
          ownership_relation_kind::target_is_unowned);
}


TEST_CASE("a poisoned response identifier cannot re-enter through a third reply")
{
  scripted_backend backend([](const auto& requests) {
    const auto value = observed(requests[0], observed_object_type::missing);
    return std::vector<object_observation>{value, value, value};
  });

  audit_request request{package_selection::only({"alpha"}),
                        check_set{check::object_state}};
  const auto result = auditor().run(sample_inventory(), request, backend);
  REQUIRE(!result.complete());
  REQUIRE(result.findings().empty());
  REQUIRE(result.failures().size() == 3);
}

TEST_CASE("contradictory response fields are backend contract failures")
{
  scripted_backend backend([](const auto& requests) {
    auto failed_with_type = observed(requests[0], observed_object_type::regular);
    failed_with_type.failure = probe_failure{
        probe_operation::inspect_object, probe_error::io_error, 5};

    auto regular_with_link = observed(requests[1], observed_object_type::regular);
    regular_with_link.symlink = symlink_observation{
        "target", std::nullopt, std::nullopt,
        symlink_resolution::not_requested, std::nullopt};

    auto unresolved_link = observed(requests[2], observed_object_type::symlink);
    unresolved_link.symlink = symlink_observation{
        "target", std::nullopt, std::nullopt,
        symlink_resolution::not_requested, std::nullopt};

    return std::vector<object_observation>{
        failed_with_type, regular_with_link, unresolved_link};
  });

  audit_request request{package_selection::only({"alpha"}),
                        check_set{check::object_state,
                                  check::symlink_resolution}};
  const auto result = auditor().run(sample_inventory(), request, backend);
  REQUIRE(!result.complete());
  REQUIRE(result.findings().empty());
  REQUIRE(result.failures().size() == 3);
  for (const auto& failure : result.failures())
    REQUIRE(failure.kind == audit_failure_kind::backend_contract_violation);
}

int main()
{
  return test::run_all();
}
