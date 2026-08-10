// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include "support/test.hpp"
#include "fixtures/state.hpp"

#include "../tools/pkgstate_adapter.h"

#include <libpkgstate/snapshot.h>

using namespace pkgaudit;

TEST_CASE("pkgstate adapter copies only durable audit facts")
{
  const pkgstate::state_target_binding binding = audit_state_fixture::target();
  const pkgstate::snapshot state = pkgstate::snapshot::make(
      binding, {audit_state_fixture::alpha(binding)});

  const inventory facts = pkgchk::make_inventory(state);
  REQUIRE(facts.packages().size() == 1);
  REQUIRE(facts.packages()[0].package() == "alpha");
  REQUIRE(facts.packages()[0].objects().size() == 2);
  REQUIRE(facts.packages()[0].objects()[0].path.string() == "etc/alpha");
  REQUIRE(facts.packages()[0].objects()[0].type ==
          expected_object_type::non_directory);
  REQUIRE(facts.packages()[0].objects()[1].path.string() == "usr/lib");
  REQUIRE(facts.packages()[0].objects()[1].type ==
          expected_object_type::directory);
}

TEST_CASE("pkgstate shared ownership survives adaptation")
{
  const pkgstate::state_target_binding binding = audit_state_fixture::target();
  std::vector<pkgstate::owned_entry> alpha_manifest;
  alpha_manifest.push_back(audit_state_fixture::entry(
      "usr/bin/shared", audit_state_fixture::regular(91)));
  std::vector<pkgstate::owned_entry> beta_manifest;
  beta_manifest.push_back(audit_state_fixture::entry(
      "usr/bin/shared", audit_state_fixture::regular(92)));

  const pkgstate::snapshot state = pkgstate::snapshot::make(
      binding,
      {
          audit_state_fixture::package(
              "beta", 60, binding, std::move(beta_manifest)),
          audit_state_fixture::package(
              "alpha", 20, binding, std::move(alpha_manifest)),
      });

  const inventory facts = pkgchk::make_inventory(state);
  const auto owners = facts.owners(object_path::parse("usr/bin/shared"));
  REQUIRE(owners.size() == 2);
  REQUIRE(owners[0] == "alpha");
  REQUIRE(owners[1] == "beta");
}

int
main()
{
  return test::run_all();
}
