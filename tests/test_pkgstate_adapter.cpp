// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include "test.h"

#include "../tools/pkgstate_adapter.h"

#include <libpkgimage/package_path.h>
#include <libpkgstate/installed_package.h>
#include <libpkgstate/owned_entry.h>
#include <libpkgstate/package_identity.h>
#include <libpkgstate/snapshot.h>

using namespace pkgaudit;

TEST_CASE("pkgstate adapter copies only durable audit facts")
{
  pkgstate::snapshot state({pkgstate::installed_package(
      pkgstate::package_identity::make("alpha", "1.0-1"),
      {
          {pkgimage::package_path::parse("usr/lib"),
           pkgstate::owned_entry_type::directory},
          {pkgimage::package_path::parse("usr/bin/tool"),
           pkgstate::owned_entry_type::non_directory},
      })});

  const inventory facts = pkgchk::make_inventory(state);
  REQUIRE(facts.packages().size() == 1);
  REQUIRE(facts.packages()[0].package() == "alpha");
  REQUIRE(facts.packages()[0].objects().size() == 2);
  REQUIRE(facts.packages()[0].objects()[0].path.string() == "usr/bin/tool");
  REQUIRE(facts.packages()[0].objects()[1].type ==
          expected_object_type::directory);
}

TEST_CASE("pkgstate shared ownership survives adaptation")
{
  const auto path = pkgimage::package_path::parse("usr/bin/shared");
  pkgstate::snapshot state({
      pkgstate::installed_package(
          pkgstate::package_identity::make("beta", "1"),
          {{path, pkgstate::owned_entry_type::non_directory}}),
      pkgstate::installed_package(
          pkgstate::package_identity::make("alpha", "1"),
          {{path, pkgstate::owned_entry_type::non_directory}}),
  });

  const inventory facts = pkgchk::make_inventory(state);
  const auto owners = facts.owners(object_path::parse("usr/bin/shared"));
  REQUIRE(owners.size() == 2);
  REQUIRE(owners[0] == "alpha");
  REQUIRE(owners[1] == "beta");
}

int main()
{
  return test::run_all();
}
