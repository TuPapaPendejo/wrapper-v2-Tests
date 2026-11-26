use std::{env, net::IpAddr, path::PathBuf, time::Duration};

use zeroize::Zeroizing;

use crate::device_info;
use crate::error::ApiError;
use crate::profile::RuntimeProfile;

const DEFAULT_SESSION_DIR: &str = "/data/data/com.apple.android.music/files";

#[derive(Clone)]
pub struct Config {
    pub profile: RuntimeProfile,
    pub host: IpAddr,
    pub port: u16,
    pub launcher: PathBuf,
    pub rootfs: PathBuf,
    pub session_dir: String,
    pub device_info: String,
    pub dns: Vec<String>,
    /// Optional Bearer token for direct HTTP API clients.
    /// Unset preserves 1.0.0 behavior.
    pub api_token: Option<Zeroizing<String>>,
    /// Optional idle deadline for a pending 2FA challenge.
    /// None preserves the indefinite wait.
    pub challenge_timeout: Option<Duration>,
}

impl Config {
    pub fn from_env() -> Result<Self, ApiError> {
        let api_token = read_api_token()?;
        let challenge_timeout = read_challenge_timeout()?;
        let profile = RuntimeProfile::select(
            &env::var("WRAPPER_ARCH").unwrap_or_else(|_| std::env::consts::ARCH.to_string()),
        )?;
        let host = env::var("WRAPPER_HOST")
            .unwrap_or_else(|_| "127.0.0.1".into())
            .parse()
            .map_err(|_| ApiError::bad_config("WRAPPER_HOST"))?;
        let port = env::var("WRAPPER_PORT")
            .unwrap_or_else(|_| "80".into())
            .parse::<u16>()
            .map_err(|_| ApiError::bad_config("WRAPPER_PORT"))?;
        if port == 0 {
            return Err(ApiError::bad_config("WRAPPER_PORT"));
        }
        let launcher = env::var("WRAPPER_LAUNCHER")
            .unwrap_or_else(|_| format!("./build/{}/host/worker-launch", profile.architecture));
        let rootfs = env::var("WRAPPER_ROOTFS")
            .unwrap_or_else(|_| format!("./build/{}/rootfs", profile.architecture));
        let rootfs =
            std::fs::canonicalize(&rootfs).map_err(|_| ApiError::bad_config("WRAPPER_ROOTFS"))?;
        if !rootfs.is_dir() {
            return Err(ApiError::bad_config("WRAPPER_ROOTFS"));
        }
        profile.validate_rootfs(&rootfs)?;
        let launcher = std::fs::canonicalize(&launcher)
            .map_err(|_| ApiError::bad_config("WRAPPER_LAUNCHER"))?;
        let session_dir =
            env::var("WRAPPER_SESSION_DIR").unwrap_or_else(|_| DEFAULT_SESSION_DIR.into());
        if !session_dir.starts_with('/')
            || session_dir.contains("/../")
            || session_dir.ends_with("/..")
            || session_dir == "/"
        {
            return Err(ApiError::bad_config("WRAPPER_SESSION_DIR"));
        }
        let device_info = device_info::resolve(
            &rootfs,
            &session_dir,
            env::var("WRAPPER_DEVICE_INFO").ok().as_deref(),
        )?;
        let dns: Vec<String> = env::var("WRAPPER_DNS")
            .unwrap_or_else(|_| "1.1.1.1,8.8.8.8".into())
            .split(',')
            .map(str::trim)
            .map(str::to_string)
            .collect();
        if dns.is_empty() || dns.len() > 4 || dns.iter().any(|s| s.parse::<IpAddr>().is_err()) {
            return Err(ApiError::bad_config("WRAPPER_DNS"));
        }
        Ok(Self {
            profile,
            host,
            port,
            launcher,
            rootfs,
            session_dir,
            device_info,
            dns,
            api_token,
            challenge_timeout,
        })
    }
}

fn read_api_token() -> Result<Option<Zeroizing<String>>, ApiError> {
    let value = match env::var("WRAPPER_API_TOKEN") {
        Ok(value) => Some(value),
        Err(env::VarError::NotPresent) => None,
        Err(_) => return Err(ApiError::bad_config("WRAPPER_API_TOKEN")),
    };
    parse_api_token(value)
}

fn parse_api_token(value: Option<String>) -> Result<Option<Zeroizing<String>>, ApiError> {
    let Some(value) = value else {
        return Ok(None);
    };
    // Hex/base64url-style tokens only; generate at least 256 bits of entropy.
    if !(43..=256).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
    {
        return Err(ApiError::bad_config("WRAPPER_API_TOKEN"));
    }
    Ok(Some(Zeroizing::new(value)))
}

fn read_challenge_timeout() -> Result<Option<Duration>, ApiError> {
    let value = match env::var("WRAPPER_2FA_TIMEOUT_SECONDS") {
        Ok(value) => Some(value),
        Err(env::VarError::NotPresent) => None,
        Err(_) => return Err(ApiError::bad_config("WRAPPER_2FA_TIMEOUT_SECONDS")),
    };
    parse_challenge_timeout(value.as_deref())
}

fn parse_challenge_timeout(value: Option<&str>) -> Result<Option<Duration>, ApiError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let seconds = value
        .parse::<u64>()
        .map_err(|_| ApiError::bad_config("WRAPPER_2FA_TIMEOUT_SECONDS"))?;
    match seconds {
        0 => Ok(None),
        1..=86_400 => Ok(Some(Duration::from_secs(seconds))),
        _ => Err(ApiError::bad_config("WRAPPER_2FA_TIMEOUT_SECONDS")),
    }
}

#[cfg(test)]
mod environment_tests {
    use super::*;

    #[test]
    fn api_token_is_optional_but_validated_when_configured() {
        assert!(parse_api_token(None).unwrap().is_none());
        assert_eq!(
            parse_api_token(Some("a".repeat(64)))
                .unwrap()
                .unwrap()
                .as_str(),
            "a".repeat(64)
        );
        assert!(parse_api_token(Some(String::new())).is_err());
        assert!(parse_api_token(Some("short".to_string())).is_err());
        assert!(parse_api_token(Some("a".repeat(257))).is_err());
        assert!(parse_api_token(Some(
            "contains spaces ................................".to_string()
        ))
        .is_err());
    }

    #[test]
    fn two_factor_timeout_is_opt_in_and_bounded() {
        assert_eq!(parse_challenge_timeout(None).unwrap(), None);
        assert_eq!(parse_challenge_timeout(Some("0")).unwrap(), None);
        assert_eq!(
            parse_challenge_timeout(Some("900")).unwrap(),
            Some(Duration::from_secs(900))
        );
        assert!(parse_challenge_timeout(Some("-1")).is_err());
        assert!(parse_challenge_timeout(Some("86401")).is_err());
        assert!(parse_challenge_timeout(Some("invalid")).is_err());
    }
}
