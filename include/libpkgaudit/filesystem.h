/*
 * Copyright (C) 2026 Alexandr Savca
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#pragma once

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

#include <libpkgaudit/observation.h>

namespace pkgaudit {

class filesystem_backend
{
public:
  virtual ~filesystem_backend() = default;

  [[nodiscard]] virtual std::vector<object_observation>
  observe(const std::vector<observation_request>& requests) = 0;
};

struct filesystem_options final
{
  std::string root{"/"};
  std::size_t symlink_limit{40};
};

[[nodiscard]] std::unique_ptr<filesystem_backend>
make_posix_filesystem_backend(filesystem_options options = {});

} // namespace pkgaudit
