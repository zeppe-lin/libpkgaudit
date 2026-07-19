#include <libpkgaudit/error.h>

namespace pkgaudit {

audit_error::audit_error(const std::string& message)
  : std::runtime_error(message)
{
}

path_error::path_error(const std::string& message)
  : audit_error(message)
{
}

inventory_error::inventory_error(const std::string& message)
  : audit_error(message)
{
}

} // namespace pkgaudit
