// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include "fixtures/state.hpp"

#include <libpkgstate-posix/canonical_generation_store.h>

#include <cstdlib>
#include <filesystem>
#include <iostream>

int
main(int argc, char** argv)
{
  if (argc != 2) {
    std::cerr << "usage: pkgchk-fixture canonical-store\n";
    return EXIT_FAILURE;
  }

  try {
    const pkgstate::state_target_binding binding = audit_state_fixture::target();
    pkgstate::posix::canonical_generation_store store(
        std::filesystem::path(argv[1]), binding);
    audit_state_fixture::publish(store, audit_state_fixture::alpha(binding));
    audit_state_fixture::publish(store, audit_state_fixture::beta(binding));

    std::cout << "--managed-target " << binding.managed_target().string() << ' '
              << "--state-store " << binding.state_store().string() << ' '
              << "--root-view " << binding.root_view().string() << ' '
              << "--state-backend " << binding.state_backend().string() << ' '
              << "--publication-domain "
              << binding.publication_domain().string() << '\n';
  } catch (const std::exception& error) {
    std::cerr << "pkgchk-fixture: " << error.what() << '\n';
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
