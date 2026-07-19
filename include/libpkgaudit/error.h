/*
 * Copyright (C) 2026 Alexandr Savca
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#pragma once

#include <stdexcept>
#include <string>

namespace pkgaudit {

class audit_error : public std::runtime_error
{
public:
  explicit audit_error(const std::string& message);
};

class path_error final : public audit_error
{
public:
  explicit path_error(const std::string& message);
};

class inventory_error final : public audit_error
{
public:
  explicit inventory_error(const std::string& message);
};

} // namespace pkgaudit
