// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

/*! \file visibility.h
 *  \brief Shared-library symbol visibility annotations.
 */
#pragma once

#if defined(__GNUC__) || defined(__clang__)
#define PKGAUDIT_API __attribute__((visibility("default")))
#define PKGAUDIT_LOCAL __attribute__((visibility("hidden")))
#else
#define PKGAUDIT_API
#define PKGAUDIT_LOCAL
#endif
