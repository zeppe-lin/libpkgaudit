// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

/*! \file filesystem.h
 *  \brief Filesystem observation backend contract and POSIX implementation.
 */
#pragma once

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

#include <libpkgaudit/observation.h>

namespace pkgaudit {

/*! \brief Backend that establishes typed facts for requested objects.
 *
 * Responses may be returned in any order but must contain exactly one matching
 * response for every request identifier and path.
 */
class filesystem_backend
{
public:
  virtual ~filesystem_backend() = default;

  /*! \brief Observe a batch of logical objects. */
  [[nodiscard]] virtual std::vector<object_observation>
  observe(const std::vector<observation_request>& requests) = 0;
};

/*! \brief Configuration for the root-bound POSIX backend. */
struct filesystem_options final
{
  std::string root{"/"};          /*!< Host pathname of the selected root. */
  std::size_t symlink_limit{40};  /*!< Maximum links followed per request. */
};

/*! \brief Construct the descriptor-relative Linux/POSIX backend.
 *  \throws audit_error when the root cannot be opened or options are invalid.
 */
[[nodiscard]] std::unique_ptr<filesystem_backend>
make_posix_filesystem_backend(filesystem_options options = {});

} // namespace pkgaudit
