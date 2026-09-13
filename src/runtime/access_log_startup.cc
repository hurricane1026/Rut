#include "rut/runtime/access_log_startup.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace rut {

core::Expected<AccessLogStartupResolution, AccessLogStartupResolutionError>
resolve_access_log_startup(const AccessLogStartupInputs& inputs) {
    if (!access_log_sink_spec_valid(inputs.source))
        return core::make_unexpected(AccessLogStartupResolutionError::InvalidSourceSpec);

    AccessLogStartupResolution resolved{};
    if (!inputs.source.present) {
        if (!inputs.cli_path_present) return resolved;
        if (inputs.cli_path == nullptr)
            return core::make_unexpected(AccessLogStartupResolutionError::InvalidCliPath);
        resolved.mode = AccessLogStartupMode::LegacyCli;
        resolved.legacy_path = inputs.cli_path;
        resolved.legacy_compression = inputs.cli_compression;
        resolved.legacy_level = inputs.cli_level;
        return resolved;
    }

    if (inputs.cli_path_present)
        return core::make_unexpected(AccessLogStartupResolutionError::ConflictingCliPath);
    if (inputs.cli_compression_present)
        return core::make_unexpected(AccessLogStartupResolutionError::ConflictingCliCompression);
    if (inputs.cli_level_present)
        return core::make_unexpected(AccessLogStartupResolutionError::ConflictingCliLevel);
    if (inputs.environment_compression_present)
        return core::make_unexpected(
            AccessLogStartupResolutionError::ConflictingEnvironmentCompression);

    resolved.mode = AccessLogStartupMode::SourceLive;
    resolved.source_live = inputs.source;
    return resolved;
}

SourceAccessLogFd::SourceAccessLogFd(SourceAccessLogFd&& other) noexcept : fd_(other.fd_) {
    other.fd_ = -1;
}

SourceAccessLogFd& SourceAccessLogFd::operator=(SourceAccessLogFd&& other) noexcept {
    if (this == &other) return *this;
    reset();
    fd_ = other.fd_;
    other.fd_ = -1;
    return *this;
}

SourceAccessLogFd::~SourceAccessLogFd() {
    reset();
}

void SourceAccessLogFd::reset() {
    if (fd_ < 0) return;
    const i32 fd = fd_;
    fd_ = -1;
    (void)::close(fd);
}

core::Expected<SourceAccessLogFd, SourceAccessLogOpenError> open_source_access_log(
    const AccessLogSinkSpec& spec) {
    if (!spec.present || !access_log_sink_spec_valid(spec))
        return core::make_unexpected(
            SourceAccessLogOpenError{SourceAccessLogOpenErrorKind::InvalidSpec, 0});

    const i32 fd = ::open(
        spec.path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0644);
    if (fd < 0)
        return core::make_unexpected(
            SourceAccessLogOpenError{SourceAccessLogOpenErrorKind::OpenFailed, errno});

    SourceAccessLogFd owned(fd);
    struct stat status{};
    if (::fstat(fd, &status) != 0)
        return core::make_unexpected(
            SourceAccessLogOpenError{SourceAccessLogOpenErrorKind::StatFailed, errno});
    if (!S_ISREG(status.st_mode))
        return core::make_unexpected(
            SourceAccessLogOpenError{SourceAccessLogOpenErrorKind::NotRegularFile, 0});
    return owned;
}

}  // namespace rut
