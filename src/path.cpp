#include <libpkgaudit/path.h>

#include <libpkgaudit/error.h>

#include <ostream>
#include <utility>
#include <vector>

namespace pkgaudit {

object_path::object_path(std::string value)
  : value_(std::move(value))
{
}

object_path
object_path::parse(std::string_view input)
{
  if (input.empty())
    throw path_error("audit path is empty");
  if (input.front() == '/')
    throw path_error("audit path is absolute");

  std::vector<std::string_view> components;
  std::size_t offset = 0;

  while (offset <= input.size()) {
    const std::size_t separator = input.find('/', offset);
    const std::size_t end = separator == std::string_view::npos
                          ? input.size() : separator;
    const std::string_view component = input.substr(offset, end - offset);

    for (const char byte : component) {
      if (byte == '\0' || byte == '\n' || byte == '\r')
        throw path_error("audit path is not line-safe");
    }

    if (!component.empty() && component != ".") {
      if (component == "..")
        throw path_error("audit path escapes through '..'");
      components.push_back(component);
    }

    if (separator == std::string_view::npos)
      break;
    offset = separator + 1;
  }

  if (components.empty())
    throw path_error("audit path names no object");

  std::string normalized;
  for (const auto component : components) {
    if (!normalized.empty())
      normalized.push_back('/');
    normalized.append(component.data(), component.size());
  }

  return object_path(std::move(normalized));
}

const std::string&
object_path::string() const noexcept
{
  return value_;
}

std::string_view
object_path::filename() const noexcept
{
  const std::size_t separator = value_.rfind('/');
  return separator == std::string::npos
       ? std::string_view(value_)
       : std::string_view(value_).substr(separator + 1);
}

std::optional<object_path>
object_path::parent() const
{
  const std::size_t separator = value_.rfind('/');
  if (separator == std::string::npos)
    return std::nullopt;
  return object_path(value_.substr(0, separator));
}

bool
operator==(const object_path& lhs, const object_path& rhs) noexcept
{
  return lhs.value_ == rhs.value_;
}

bool
operator!=(const object_path& lhs, const object_path& rhs) noexcept
{
  return !(lhs == rhs);
}

bool
operator<(const object_path& lhs, const object_path& rhs) noexcept
{
  return lhs.value_ < rhs.value_;
}

std::ostream&
operator<<(std::ostream& out, const object_path& path)
{
  return out << path.string();
}

} // namespace pkgaudit
