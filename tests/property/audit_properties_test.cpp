// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include "support/test.hpp"

#include <libpkgaudit/libpkgaudit.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <random>
#include <sstream>
#include <string>
#include <vector>

using namespace pkgaudit;

namespace {

class permuting_backend final : public filesystem_backend
{
public:
  explicit permuting_backend(std::vector<std::size_t> order)
    : order_(std::move(order))
  {
  }

  std::vector<object_observation>
  observe(const std::vector<observation_request>& requests) override
  {
    std::vector<object_observation> result;
    for (const std::size_t index : order_) {
      const auto& request = requests.at(index);
      const auto type = request.path.string().back() % 2 == 0
                      ? observed_object_type::missing
                      : observed_object_type::regular;
      result.push_back({request.id, request.path, type,
                        std::nullopt, std::nullopt});
    }
    return result;
  }

private:
  std::vector<std::size_t> order_;
};

std::string
signature(const report& value)
{
  std::ostringstream out;
  for (const auto& finding : value.findings())
    out << static_cast<int>(finding.kind) << ':' << finding.package << ':'
        << finding.path.string() << '\n';
  for (const auto& relation : value.relations())
    out << static_cast<int>(relation.kind) << ':' << relation.package << ':'
        << relation.path.string() << '\n';
  for (const auto& failure : value.failures())
    out << static_cast<int>(failure.kind) << ':' << failure.path.string() << '\n';
  return out.str();
}

} // namespace

TEST_CASE("inventory semantics are independent of input permutations")
{
  std::vector<std::string> package_order{"gamma", "alpha", "beta"};
  std::string expected;

  do {
    std::vector<package_facts> packages;
    for (const auto& name : package_order) {
      std::vector<expected_object> objects{
          {object_path::parse("usr/bin/shared"),
           expected_object_type::non_directory},
          {object_path::parse("etc/" + name),
           expected_object_type::non_directory},
      };
      if (name != "alpha")
        std::reverse(objects.begin(), objects.end());
      packages.emplace_back(name, std::move(objects));
    }

    inventory value(std::move(packages));
    std::ostringstream current;
    for (const auto& package : value.packages())
      current << package.package() << '\n';
    for (const auto owner : value.owners(object_path::parse("usr/bin/shared")))
      current << owner << '\n';

    if (expected.empty())
      expected = current.str();
    REQUIRE(current.str() == expected);
  } while (std::next_permutation(package_order.begin(), package_order.end()));
}

TEST_CASE("audit reports are independent of backend completion order")
{
  inventory facts({package_facts("alpha", {
      {object_path::parse("p0"), expected_object_type::non_directory},
      {object_path::parse("p1"), expected_object_type::non_directory},
      {object_path::parse("p2"), expected_object_type::non_directory},
      {object_path::parse("p3"), expected_object_type::non_directory},
  })});
  audit_request request{package_selection::all(),
                        check_set{check::object_state}};

  std::vector<std::size_t> order{0, 1, 2, 3};
  std::string expected;
  std::size_t permutations = 0;
  do {
    permuting_backend backend(order);
    const std::string current = signature(auditor().run(facts, request, backend));
    if (expected.empty())
      expected = current;
    REQUIRE(current == expected);
    ++permutations;
  } while (std::next_permutation(order.begin(), order.end()));
  REQUIRE(permutations == 24);
}

TEST_CASE("random object-state audits agree with an independent count oracle")
{
  std::mt19937 generator(0x504b4741U);
  std::uniform_int_distribution<int> count_distribution(1, 32);
  std::uniform_int_distribution<int> type_distribution(0, 4);

  for (int iteration = 0; iteration < 2000; ++iteration) {
    const int count = count_distribution(generator);
    std::vector<expected_object> objects;
    std::vector<observed_object_type> observed_types;
    std::size_t expected_findings = 0;

    for (int index = 0; index < count; ++index) {
      const bool directory = (generator() & 1U) != 0;
      objects.push_back({object_path::parse("object/" + std::to_string(1000 + index)),
                         directory ? expected_object_type::directory
                                   : expected_object_type::non_directory});

      const auto observed = static_cast<observed_object_type>(
          type_distribution(generator));
      observed_types.push_back(observed);
      if (observed == observed_object_type::missing ||
          (directory != (observed == observed_object_type::directory)))
        ++expected_findings;
    }

    inventory facts({package_facts("random", std::move(objects))});
    class backend final : public filesystem_backend {
    public:
      explicit backend(const std::vector<observed_object_type>& types)
        : types_(types) {}
      std::vector<object_observation>
      observe(const std::vector<observation_request>& requests) override {
        std::vector<object_observation> result;
        for (std::size_t index = 0; index < requests.size(); ++index)
          result.push_back({requests[index].id, requests[index].path,
                            types_[index], std::nullopt, std::nullopt});
        return result;
      }
    private:
      const std::vector<observed_object_type>& types_;
    } filesystem(observed_types);

    audit_request request{package_selection::all(),
                          check_set{check::object_state}};
    const auto result = auditor().run(facts, request, filesystem);
    REQUIRE(result.complete());
    REQUIRE(result.findings().size() == expected_findings);
  }
}

TEST_CASE("path normalization is stable under redundant separators and dots")
{
  for (int index = 0; index < 1000; ++index) {
    const std::string canonical =
        "root/segment" + std::to_string(index) + "/leaf";
    const std::string redundant =
        "./root//segment" + std::to_string(index) + "/./leaf/";
    REQUIRE(object_path::parse(redundant).string() == canonical);
    REQUIRE(object_path::parse(canonical).string() == canonical);
  }
}

int main()
{
  return test::run_all();
}
