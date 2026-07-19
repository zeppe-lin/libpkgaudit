#pragma once

#include <exception>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace test {

using function = std::function<void()>;

struct entry final {
  std::string name;
  function run;
};

inline std::vector<entry>& registry()
{
  static std::vector<entry> value;
  return value;
}

struct registration final {
  registration(const char* name, function run)
  {
    registry().push_back({name, std::move(run)});
  }
};

inline void require(bool condition, const char* expression,
                    const char* file, int line)
{
  if (!condition)
    throw std::runtime_error(std::string(file) + ':' + std::to_string(line) +
                             ": requirement failed: " + expression);
}

template<typename Exception, typename Function>
void require_throws(Function&& function, const char* expression,
                    const char* file, int line)
{
  try {
    function();
  } catch (const Exception&) {
    return;
  }
  throw std::runtime_error(std::string(file) + ':' + std::to_string(line) +
                           ": expected exception: " + expression);
}

inline int run_all()
{
  int failures = 0;
  for (const auto& value : registry()) {
    try {
      value.run();
    } catch (const std::exception& error) {
      ++failures;
      std::cerr << "FAIL " << value.name << ": " << error.what() << '\n';
    }
  }
  if (failures == 0)
    std::cout << "ok " << registry().size() << " tests\n";
  return failures == 0 ? 0 : 1;
}

} // namespace test

#define TEST_JOIN_(a, b) a##b
#define TEST_JOIN(a, b) TEST_JOIN_(a, b)
#define TEST_CASE(name) \
  static void TEST_JOIN(test_function_, __LINE__)(); \
  static ::test::registration TEST_JOIN(test_registration_, __LINE__)( \
      name, TEST_JOIN(test_function_, __LINE__)); \
  static void TEST_JOIN(test_function_, __LINE__)()
#define REQUIRE(expression) \
  ::test::require(static_cast<bool>(expression), #expression, __FILE__, __LINE__)
#define REQUIRE_THROWS_AS(expression, exception) \
  ::test::require_throws<exception>([&] { (void)(expression); }, #expression, \
                                    __FILE__, __LINE__)
