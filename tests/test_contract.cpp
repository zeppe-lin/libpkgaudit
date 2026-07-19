// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include "test.h"

#include <libpkgaudit/libpkgaudit.h>

using namespace pkgaudit;

TEST_CASE("check sets are explicit")
{
  check_set checks{check::object_state, check::symlink_ownership};
  REQUIRE(checks.contains(check::object_state));
  REQUIRE(!checks.contains(check::symlink_resolution));
  REQUIRE(checks.contains(check::symlink_ownership));
}

TEST_CASE("package selections sort and deduplicate names")
{
  const auto selection = package_selection::only({"zeta", "alpha", "zeta"});
  REQUIRE(!selection.selects_all());
  REQUIRE(selection.packages().size() == 2);
  REQUIRE(selection.packages()[0] == "alpha");
  REQUIRE(selection.contains("zeta"));
  REQUIRE(!selection.contains("other"));
}

TEST_CASE("reports distinguish incomplete audits")
{
  const auto path = object_path::parse("usr/bin/tool");
  report complete({}, {}, {});
  REQUIRE(complete.complete());

  report incomplete({}, {}, {{audit_failure_kind::probe_failed,
                              std::string("alpha"), path,
                              probe_operation::inspect_object,
                              probe_error::permission_denied, 13}});
  REQUIRE(!incomplete.complete());
  REQUIRE(incomplete.failures()[0].system_error == 13);
}

int main()
{
  return test::run_all();
}
