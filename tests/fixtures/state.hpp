// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <libpkgstate/libpkgstate.h>

namespace audit_state_fixture {

template<typename Identity>
Identity
identity(std::uint8_t seed)
{
  pkgstate::sha256_digest_bytes bytes{};
  for (std::size_t index = 0; index < bytes.size(); ++index)
    bytes[index] = static_cast<std::uint8_t>(seed + index);
  return Identity::from_sha256(bytes);
}

inline pkgstate::state_target_binding
target(std::uint8_t seed = 1)
{
  return pkgstate::state_target_binding::make(
      identity<pkgstate::managed_target_identity>(seed),
      identity<pkgstate::state_store_identity>(seed + 1),
      identity<pkgstate::root_view_identity>(seed + 2),
      identity<pkgstate::state_backend_identity>(seed + 3),
      identity<pkgstate::publication_domain_identity>(seed + 4));
}

inline pkgstate::package_source_record
source(std::string name, std::uint8_t seed)
{
  return pkgstate::package_source_record::make(
      pkgstate::package_release(
          identity<pkgstate::package_release_identity>(seed),
          pkgstate::package_reference(std::move(name)), "1.0", 1),
      pkgstate::package_metadata(
          "Audit fixture", std::nullopt, std::nullopt, {"GPL-3.0-or-later"}),
      {}, {}, {},
      pkgstate::architecture_binding::make(
          {}, {}, pkgstate::architecture_reference("x86_64"),
          pkgstate::architecture_reference("x86_64")),
      {}, identity<pkgstate::source_snapshot_identity>(seed + 1));
}

inline pkgstate::build_provenance
build(const pkgstate::package_source_record& source_record, std::uint8_t seed)
{
  return pkgstate::build_provenance(
      source_record.identity(),
      identity<pkgstate::build_request_identity>(seed + 2),
      identity<pkgstate::build_input_set_identity>(seed + 3),
      identity<pkgstate::environment_policy_identity>(seed + 4),
      identity<pkgstate::build_policy_identity>(seed + 5),
      identity<pkgstate::build_result_identity>(seed + 6),
      identity<pkgstate::payload_manifest_identity>(seed + 7),
      identity<pkgstate::build_artifact_identity>(seed + 8),
      identity<pkgstate::artifact_content_identity>(seed + 9),
      identity<pkgstate::artifact_binding_identity>(seed + 10),
      identity<pkgstate::execution_evidence_identity>(seed + 11),
      identity<pkgstate::build_image_identity>(seed + 12),
      identity<pkgstate::artifact_image_identity>(seed + 13),
      identity<pkgstate::artifact_inspection_identity>(seed + 14));
}

inline pkgstate::installed_object_metadata
regular(std::uint8_t seed)
{
  return pkgstate::installed_object_metadata(
      pkgstate::owned_object_kind::regular, 0644, 0, 0,
      pkgstate::installed_object_timestamp(1700000000, 0), std::uint64_t{1},
      identity<pkgstate::installed_regular_content_identity>(seed));
}

inline pkgstate::installed_object_metadata
directory()
{
  return pkgstate::installed_object_metadata(
      pkgstate::owned_object_kind::directory, 0755, 0, 0,
      pkgstate::installed_object_timestamp(1700000000, 0));
}

inline pkgstate::owned_entry
entry(std::string path, pkgstate::installed_object_metadata metadata)
{
  return pkgstate::owned_entry::make(
      pkgstate::package_path::parse(std::move(path)), std::move(metadata),
      pkgstate::active_object_origin::incoming_payload);
}

inline pkgstate::installed_package
package(std::string name,
        std::uint8_t seed,
        pkgstate::state_target_binding binding,
        std::vector<pkgstate::owned_entry> manifest)
{
  pkgstate::package_source_record source_record = source(std::move(name), seed);
  pkgstate::installed_control control = pkgstate::installed_control::make(
      source_record, pkgstate::installation_reason::explicit_request(),
      build(source_record, seed));
  return pkgstate::installed_package::make(pkgstate::installation_receipt::make(
      std::move(control), std::move(binding), std::move(manifest),
      identity<pkgstate::operation_plan_identity>(seed + 15),
      identity<pkgstate::application_evidence_identity>(seed + 16)));
}

inline pkgstate::installed_package
alpha(pkgstate::state_target_binding binding)
{
  std::vector<pkgstate::owned_entry> manifest;
  manifest.push_back(entry("etc/alpha", regular(41)));
  manifest.push_back(entry("usr/lib", directory()));
  return package("alpha", 20, std::move(binding), std::move(manifest));
}

inline pkgstate::installed_package
beta(pkgstate::state_target_binding binding)
{
  std::vector<pkgstate::owned_entry> manifest;
  manifest.push_back(entry("usr/lib/target", regular(81)));
  return package("beta", 60, std::move(binding), std::move(manifest));
}

inline void
publish(pkgstate::canonical_store& store, pkgstate::installed_package package)
{
  const pkgstate::state_publication_request request =
      pkgstate::state_publication_request::make(
          store.read(),
          {pkgstate::package_state_delta::install(
              package, package.receipt().operation_plan(),
              package.receipt().application_evidence())});
  const pkgstate::state_publication_receipt receipt =
      store.compare_and_publish(request);
  if (receipt.outcome() != pkgstate::state_publication_outcome::published)
    throw pkgstate::state_error("audit fixture publication did not complete");
}

} // namespace audit_state_fixture
