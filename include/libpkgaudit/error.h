// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

/*! \file error.h
 *  \brief Exceptions raised while constructing audit inputs or requests.
 */
#pragma once

#include <stdexcept>
#include <string>

namespace pkgaudit {

/*! \brief Base exception for synchronous libpkgaudit contract errors. */
class audit_error : public std::runtime_error
{
public:
  /*! \brief Construct an audit error with a diagnostic message. */
  explicit audit_error(const std::string& message);
};

/*! \brief Invalid canonical audit path. */
class path_error final : public audit_error
{
public:
  /*! \brief Construct a path validation error. */
  explicit path_error(const std::string& message);
};

/*! \brief Invalid package facts, inventory, or package selection. */
class inventory_error final : public audit_error
{
public:
  /*! \brief Construct an inventory validation error. */
  explicit inventory_error(const std::string& message);
};

} // namespace pkgaudit
