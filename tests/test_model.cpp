#include "test.h"

#include <libpkgaudit/libpkgaudit.h>

#include <string>
#include <vector>

using namespace pkgaudit;

TEST_CASE("paths are canonical root-relative values")
{
  const auto path = object_path::parse("usr//./bin/tool/");
  REQUIRE(path.string() == "usr/bin/tool");
  REQUIRE(path.filename() == "tool");
  REQUIRE(path.parent()->string() == "usr/bin");
}

TEST_CASE("paths reject empty absolute escaping and line-unsafe input")
{
  REQUIRE_THROWS_AS(object_path::parse(""), path_error);
  REQUIRE_THROWS_AS(object_path::parse("/usr/bin/tool"), path_error);
  REQUIRE_THROWS_AS(object_path::parse("usr/../etc/passwd"), path_error);
  REQUIRE_THROWS_AS(object_path::parse("usr\nlib"), path_error);
}

TEST_CASE("package facts sort objects and reject duplicate paths")
{
  package_facts facts(
      "alpha",
      {{object_path::parse("z"), expected_object_type::non_directory},
       {object_path::parse("a"), expected_object_type::directory}});
  REQUIRE(facts.objects()[0].path.string() == "a");
  REQUIRE(facts.objects()[1].path.string() == "z");
  REQUIRE(facts.find(object_path::parse("z")) != nullptr);

  REQUIRE_THROWS_AS(
      package_facts("alpha",
                    {{object_path::parse("a"),
                      expected_object_type::non_directory},
                     {object_path::parse("a"),
                      expected_object_type::directory}}),
      inventory_error);
}

TEST_CASE("inventory retains shared ownership in package order")
{
  inventory facts({
      package_facts("zeta", {{object_path::parse("usr/bin/tool"),
                               expected_object_type::non_directory}}),
      package_facts("alpha", {{object_path::parse("usr/bin/tool"),
                                expected_object_type::non_directory}}),
  });

  REQUIRE(facts.packages()[0].package() == "alpha");
  const auto owners = facts.owners(object_path::parse("usr/bin/tool"));
  REQUIRE(owners.size() == 2);
  REQUIRE(owners[0] == "alpha");
  REQUIRE(owners[1] == "zeta");
}

TEST_CASE("inventory rejects duplicate package identifiers")
{
  REQUIRE_THROWS_AS(
      inventory({package_facts("alpha", {}), package_facts("alpha", {})}),
      inventory_error);
}

int main()
{
  return test::run_all();
}
