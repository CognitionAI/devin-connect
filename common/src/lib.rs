//! Plumbing shared by the gateway and edge binaries that is not part of the
//! wire protocol: listener helpers, the minimal admin HTTP surface,
//! Prometheus text rendering, and logging setup.

#![forbid(unsafe_code)]

pub mod http;
pub mod logging;
pub mod net;
pub mod prometheus;
pub mod splice;

use std::path::Path;

/// Directory relative paths in a config file resolve against.
pub fn config_dir(config_path: &Path) -> &Path {
    config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}
