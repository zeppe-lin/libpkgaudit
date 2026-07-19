// SPDX-FileCopyrightText: 2026 Alexandr Savca
// SPDX-License-Identifier: GPL-3.0-or-later

#include <libpkgaudit/filesystem.h>
#include <libpkgaudit/error.h>

#include <cerrno>
#include <cstdint>
#include <deque>
#include <fcntl.h>
#include <optional>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace pkgaudit {
namespace {

class descriptor final
{
public:
  explicit descriptor(int value = -1) noexcept
    : value_(value)
  {
  }

  descriptor(const descriptor&) = delete;
  descriptor& operator=(const descriptor&) = delete;

  descriptor(descriptor&& other) noexcept
    : value_(std::exchange(other.value_, -1))
  {
  }

  descriptor& operator=(descriptor&& other) noexcept
  {
    if (this != &other) {
      reset();
      value_ = std::exchange(other.value_, -1);
    }
    return *this;
  }

  ~descriptor()
  {
    reset();
  }

  [[nodiscard]] int get() const noexcept
  {
    return value_;
  }

private:
  void reset() noexcept
  {
    if (value_ >= 0)
      ::close(value_);
    value_ = -1;
  }

  int value_;
};

probe_error
classify_errno(int value)
{
  if (value == EACCES || value == EPERM)
    return probe_error::permission_denied;
  if (value == ELOOP)
    return probe_error::too_many_symlinks;
  return probe_error::io_error;
}

observed_object_type
classify_mode(mode_t mode)
{
  if (S_ISDIR(mode))
    return observed_object_type::directory;
  if (S_ISREG(mode))
    return observed_object_type::regular;
  if (S_ISLNK(mode))
    return observed_object_type::symlink;
  return observed_object_type::other;
}

bool
same_identity(const struct stat& lhs, const struct stat& rhs) noexcept
{
  return lhs.st_dev == rhs.st_dev &&
         lhs.st_ino == rhs.st_ino &&
         lhs.st_mode == rhs.st_mode &&
         lhs.st_size == rhs.st_size &&
         lhs.st_mtim.tv_sec == rhs.st_mtim.tv_sec &&
         lhs.st_mtim.tv_nsec == rhs.st_mtim.tv_nsec &&
         lhs.st_ctim.tv_sec == rhs.st_ctim.tv_sec &&
         lhs.st_ctim.tv_nsec == rhs.st_ctim.tv_nsec;
}

struct link_read final
{
  std::string target;
  std::optional<probe_failure> failure;
};

link_read
read_link_stable(int root, const std::string& path, const struct stat& before)
{
  std::size_t capacity = before.st_size > 0
                       ? static_cast<std::size_t>(before.st_size) + 1U
                       : 256U;
  std::string target;

  for (;;) {
    target.resize(capacity);
    const ssize_t size = ::readlinkat(root, path.c_str(), target.data(),
                                      target.size());
    if (size < 0) {
      const int error = errno;
      return {{}, probe_failure{probe_operation::read_symlink,
                                classify_errno(error), error}};
    }
    if (static_cast<std::size_t>(size) < target.size()) {
      target.resize(static_cast<std::size_t>(size));
      break;
    }
    capacity *= 2U;
    if (capacity > 1024U * 1024U) {
      return {{}, probe_failure{probe_operation::read_symlink,
                                probe_error::io_error, ENAMETOOLONG}};
    }
  }

  struct stat after {};
  if (::fstatat(root, path.c_str(), &after, AT_SYMLINK_NOFOLLOW) < 0) {
    const int error = errno;
    return {{}, probe_failure{probe_operation::read_symlink,
                              classify_errno(error), error}};
  }
  if (!same_identity(before, after)) {
    return {{}, probe_failure{probe_operation::read_symlink,
                              probe_error::object_changed, 0}};
  }

  return {std::move(target), std::nullopt};
}

std::vector<std::string>
split(std::string_view value)
{
  std::vector<std::string> result;
  std::size_t offset = 0;
  while (offset <= value.size()) {
    const std::size_t slash = value.find('/', offset);
    const std::size_t end = slash == std::string_view::npos
                          ? value.size() : slash;
    result.emplace_back(value.substr(offset, end - offset));
    if (slash == std::string_view::npos)
      break;
    offset = slash + 1;
  }
  return result;
}

std::vector<std::string>
path_components(const object_path& path)
{
  return split(path.string());
}

std::string
join(const std::vector<std::string>& components)
{
  std::string result;
  for (const auto& component : components) {
    if (!result.empty())
      result.push_back('/');
    result += component;
  }
  return result;
}

struct normalized_target final
{
  std::optional<object_path> path;
  bool outside{false};
  bool representable{true};
};

normalized_target
normalize_target(const object_path& source, std::string_view target)
{
  std::vector<std::string> components;
  if (target.empty() || target.front() != '/') {
    if (const auto parent = source.parent())
      components = path_components(*parent);
  }

  for (const auto& component : split(target)) {
    if (component.empty() || component == ".")
      continue;
    if (component == "..") {
      if (components.empty())
        return {std::nullopt, true, true};
      components.pop_back();
      continue;
    }
    if (component.find('\n') != std::string::npos ||
        component.find('\r') != std::string::npos)
      return {std::nullopt, false, false};
    components.push_back(component);
  }

  if (components.empty())
    return {std::nullopt, false, true};
  return {object_path::parse(join(components)), false, true};
}

enum class resolution_status
{
  resolved,
  dangling,
  loop,
  outside,
  failed,
};

struct resolved_link final
{
  resolution_status status;
  std::optional<object_path> path;
  std::optional<probe_failure> failure;
};

resolved_link
resolve_inside_root(int root, const object_path& source,
                    std::string_view target, std::size_t limit)
{
  std::vector<std::string> resolved;
  if (target.empty() || target.front() != '/') {
    if (const auto parent = source.parent())
      resolved = path_components(*parent);
  }

  std::deque<std::string> pending;
  for (auto& component : split(target))
    pending.push_back(std::move(component));

  std::size_t followed = 0;
  while (!pending.empty()) {
    std::string component = std::move(pending.front());
    pending.pop_front();

    if (component.empty() || component == ".")
      continue;
    if (component == "..") {
      if (resolved.empty())
        return {resolution_status::outside, std::nullopt, std::nullopt};
      resolved.pop_back();
      continue;
    }
    if (component.find('\n') != std::string::npos ||
        component.find('\r') != std::string::npos) {
      return {resolution_status::failed, std::nullopt,
              probe_failure{probe_operation::resolve_symlink,
                            probe_error::unrepresentable_path, 0}};
    }

    std::vector<std::string> candidate_components = resolved;
    candidate_components.push_back(component);
    const std::string candidate = join(candidate_components);

    struct stat status {};
    if (::fstatat(root, candidate.c_str(), &status, AT_SYMLINK_NOFOLLOW) < 0) {
      const int error = errno;
      if (error == ENOENT || error == ENOTDIR)
        return {resolution_status::dangling, std::nullopt, std::nullopt};
      return {resolution_status::failed, std::nullopt,
              probe_failure{probe_operation::resolve_symlink,
                            classify_errno(error), error}};
    }

    if (!S_ISLNK(status.st_mode)) {
      resolved.push_back(std::move(component));
      continue;
    }

    if (++followed > limit)
      return {resolution_status::loop, std::nullopt, std::nullopt};

    link_read link = read_link_stable(root, candidate, status);
    if (link.failure)
      return {resolution_status::failed, std::nullopt, link.failure};

    if (!link.target.empty() && link.target.front() == '/')
      resolved.clear();

    auto replacement = split(link.target);
    for (auto it = replacement.rbegin(); it != replacement.rend(); ++it)
      pending.push_front(std::move(*it));
  }

  if (resolved.empty())
    return {resolution_status::resolved, std::nullopt, std::nullopt};
  return {resolution_status::resolved, object_path::parse(join(resolved)),
          std::nullopt};
}

class posix_filesystem_backend final : public filesystem_backend
{
public:
  explicit posix_filesystem_backend(filesystem_options options)
    : options_(std::move(options))
    , root_(::open(options_.root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC))
  {
    if (root_.get() < 0)
      throw audit_error("cannot open audit root: " + options_.root);
    if (options_.symlink_limit == 0)
      throw audit_error("symlink resolution limit is zero");
  }

  std::vector<object_observation>
  observe(const std::vector<observation_request>& requests) override
  {
    std::vector<object_observation> result;
    result.reserve(requests.size());
    for (const auto& request : requests)
      result.push_back(observe_one(request));
    return result;
  }

private:
  object_observation observe_one(const observation_request& request)
  {
    object_observation result{request.id, request.path, std::nullopt,
                              std::nullopt, std::nullopt};
    struct stat status {};
    if (::fstatat(root_.get(), request.path.string().c_str(), &status,
                  AT_SYMLINK_NOFOLLOW) < 0) {
      const int error = errno;
      if (error == ENOENT || error == ENOTDIR) {
        result.type = observed_object_type::missing;
      } else {
        result.failure = probe_failure{probe_operation::inspect_object,
                                       classify_errno(error), error};
      }
      return result;
    }

    result.type = classify_mode(status.st_mode);
    if (*result.type != observed_object_type::symlink ||
        !request.resolve_symlink)
      return result;

    symlink_observation link;
    link_read read = read_link_stable(root_.get(), request.path.string(), status);
    if (read.failure) {
      link.resolution = symlink_resolution::failed;
      link.failure = read.failure;
      result.symlink = std::move(link);
      return result;
    }
    link.target = std::move(read.target);

    const normalized_target immediate = normalize_target(request.path, link.target);
    if (!immediate.representable) {
      link.resolution = symlink_resolution::failed;
      link.failure = probe_failure{probe_operation::resolve_symlink,
                                   probe_error::unrepresentable_path, 0};
      result.symlink = std::move(link);
      return result;
    }
    if (immediate.outside) {
      link.resolution = symlink_resolution::outside_root;
      result.symlink = std::move(link);
      return result;
    }
    link.immediate_path = immediate.path;

    const resolved_link resolved = resolve_inside_root(
        root_.get(), request.path, link.target, options_.symlink_limit);
    link.resolved_path = resolved.path;
    link.failure = resolved.failure;
    switch (resolved.status) {
      case resolution_status::resolved:
        link.resolution = symlink_resolution::resolved;
        break;
      case resolution_status::dangling:
        link.resolution = symlink_resolution::dangling;
        break;
      case resolution_status::loop:
        link.resolution = symlink_resolution::loop;
        break;
      case resolution_status::outside:
        link.resolution = symlink_resolution::outside_root;
        break;
      case resolution_status::failed:
        link.resolution = symlink_resolution::failed;
        break;
    }
    result.symlink = std::move(link);
    return result;
  }

  filesystem_options options_;
  descriptor root_;
};

} // namespace

std::unique_ptr<filesystem_backend>
make_posix_filesystem_backend(filesystem_options options)
{
  return std::make_unique<posix_filesystem_backend>(std::move(options));
}

} // namespace pkgaudit
