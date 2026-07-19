// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include <libpkgaudit/report.h>

#include <utility>

namespace pkgaudit {

report::report(std::vector<finding> findings,
               std::vector<ownership_relation> relations,
               std::vector<audit_failure> failures)
  : findings_(std::move(findings))
  , relations_(std::move(relations))
  , failures_(std::move(failures))
{
}

const std::vector<finding>&
report::findings() const noexcept
{
  return findings_;
}

const std::vector<ownership_relation>&
report::relations() const noexcept
{
  return relations_;
}

const std::vector<audit_failure>&
report::failures() const noexcept
{
  return failures_;
}

bool
report::complete() const noexcept
{
  return failures_.empty();
}

} // namespace pkgaudit
