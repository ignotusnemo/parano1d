// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero. All rights reserved.

//! Runtime CPU capability detection shared by the proof stack.
//!
//! A process selects the widest safe implementation embedded in its
//! architecture's binary. `NOID_CPU_BACKEND` is a diagnostic/test hook which
//! may restrict that selection to `scalar`, `pclmul`, `avx2`, `avx512`,
//! `neon`, or `neon-pmull`. Official Linux and Windows x86-64 artifacts have
//! an AVX2+VPCLMUL baseline; Intel macOS keeps a PCLMUL baseline and upgrades
//! at runtime when wider kernels are available. The scalar implementation
//! remains a test oracle and a source-build fallback, not a separately
//! distributed binary.

use std::fmt;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuCapabilities {
    pub sse4_1: bool,
    pub pclmulqdq: bool,
    pub avx2: bool,
    pub vpclmulqdq: bool,
    pub gfni: bool,
    pub avx512f: bool,
    pub avx512bw: bool,
    pub neon: bool,
    pub pmull: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpuBackend {
    Scalar,
    Pclmul,
    Avx2,
    Avx512,
    Neon,
    NeonPmull,
}

impl fmt::Display for CpuBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Scalar => "scalar",
            Self::Pclmul => "pclmul",
            Self::Avx2 => "avx2+vpclmul",
            Self::Avx512 => "avx512bw+vpclmul",
            Self::Neon => "neon",
            Self::NeonPmull => "neon+pmull",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BackendRequest {
    Auto,
    Scalar,
    Pclmul,
    Avx2,
    Avx512,
    Neon,
    NeonPmull,
}

pub fn capabilities() -> &'static CpuCapabilities {
    static CAPS: OnceLock<CpuCapabilities> = OnceLock::new();
    CAPS.get_or_init(detect_capabilities)
}

pub fn selected_backend() -> CpuBackend {
    static BACKEND: OnceLock<CpuBackend> = OnceLock::new();
    *BACKEND.get_or_init(|| select_backend(*capabilities(), backend_request()))
}

#[inline]
pub fn pclmul_available() -> bool {
    matches!(
        selected_backend(),
        CpuBackend::Pclmul | CpuBackend::Avx2 | CpuBackend::Avx512
    )
}

#[inline]
pub fn avx2_vpclmul_available() -> bool {
    matches!(selected_backend(), CpuBackend::Avx2 | CpuBackend::Avx512)
}

#[inline]
pub fn avx512_vpclmul_available() -> bool {
    selected_backend() == CpuBackend::Avx512
}

#[inline]
pub fn avx2_available() -> bool {
    matches!(selected_backend(), CpuBackend::Avx2 | CpuBackend::Avx512)
}

#[inline]
pub fn gfni_available() -> bool {
    capabilities().gfni && matches!(selected_backend(), CpuBackend::Avx2 | CpuBackend::Avx512)
}

#[inline]
pub fn neon_available() -> bool {
    matches!(selected_backend(), CpuBackend::Neon | CpuBackend::NeonPmull)
}

#[inline]
pub fn pmull_available() -> bool {
    selected_backend() == CpuBackend::NeonPmull
}

fn backend_request() -> BackendRequest {
    static REQUEST: OnceLock<BackendRequest> = OnceLock::new();
    *REQUEST.get_or_init(|| {
        let Ok(value) = std::env::var("NOID_CPU_BACKEND") else {
            return BackendRequest::Auto;
        };
        parse_backend_request(&value).unwrap_or_else(|| {
            panic!(
                "invalid NOID_CPU_BACKEND={value:?}; expected auto, scalar, pclmul, avx2, \
                 avx512, neon, or neon-pmull"
            )
        })
    })
}

fn parse_backend_request(value: &str) -> Option<BackendRequest> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "auto" => Some(BackendRequest::Auto),
        "scalar" => Some(BackendRequest::Scalar),
        "pclmul" => Some(BackendRequest::Pclmul),
        "avx2" | "avx2+vpclmul" => Some(BackendRequest::Avx2),
        "avx512" | "avx512+vpclmul" => Some(BackendRequest::Avx512),
        "neon" => Some(BackendRequest::Neon),
        "neon-pmull" | "neon+pmull" | "pmull" => Some(BackendRequest::NeonPmull),
        _ => None,
    }
}

fn select_backend(caps: CpuCapabilities, request: BackendRequest) -> CpuBackend {
    #[cfg(target_arch = "x86_64")]
    {
        let available = if caps.avx512f && caps.avx512bw && caps.vpclmulqdq {
            CpuBackend::Avx512
        } else if caps.avx2 && caps.vpclmulqdq {
            CpuBackend::Avx2
        } else if caps.sse4_1 && caps.pclmulqdq {
            CpuBackend::Pclmul
        } else {
            CpuBackend::Scalar
        };
        return match request {
            BackendRequest::Auto => available,
            BackendRequest::Scalar => CpuBackend::Scalar,
            BackendRequest::Pclmul if caps.sse4_1 && caps.pclmulqdq => CpuBackend::Pclmul,
            BackendRequest::Avx2 if caps.avx2 && caps.vpclmulqdq => CpuBackend::Avx2,
            BackendRequest::Avx512 if caps.avx512f && caps.avx512bw && caps.vpclmulqdq => {
                CpuBackend::Avx512
            }
            BackendRequest::Neon | BackendRequest::NeonPmull => {
                panic!("NOID_CPU_BACKEND requests an AArch64 backend on x86_64")
            }
            forced => panic!(
                "NOID_CPU_BACKEND={forced:?} is not supported by this x86_64 CPU; detected \
                 capabilities: {caps:?}"
            ),
        };
    }

    #[cfg(target_arch = "aarch64")]
    {
        let available = if caps.neon && caps.pmull {
            CpuBackend::NeonPmull
        } else if caps.neon {
            CpuBackend::Neon
        } else {
            CpuBackend::Scalar
        };
        return match request {
            BackendRequest::Auto => available,
            BackendRequest::Scalar => CpuBackend::Scalar,
            BackendRequest::Neon if caps.neon => CpuBackend::Neon,
            BackendRequest::NeonPmull if caps.neon && caps.pmull => CpuBackend::NeonPmull,
            BackendRequest::Pclmul | BackendRequest::Avx2 | BackendRequest::Avx512 => {
                panic!("NOID_CPU_BACKEND requests an x86_64 backend on AArch64")
            }
            forced => panic!(
                "NOID_CPU_BACKEND={forced:?} is not supported by this AArch64 CPU; detected \
                 capabilities: {caps:?}"
            ),
        };
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        match request {
            BackendRequest::Auto | BackendRequest::Scalar => CpuBackend::Scalar,
            forced => panic!(
                "NOID_CPU_BACKEND={forced:?} is not supported on architecture {}",
                std::env::consts::ARCH
            ),
        }
    }
}

fn detect_capabilities() -> CpuCapabilities {
    let mut caps = CpuCapabilities::default();

    #[cfg(target_arch = "x86_64")]
    {
        caps.sse4_1 = std::arch::is_x86_feature_detected!("sse4.1");
        caps.pclmulqdq = std::arch::is_x86_feature_detected!("pclmulqdq");
        caps.avx2 = std::arch::is_x86_feature_detected!("avx2");
        caps.vpclmulqdq = std::arch::is_x86_feature_detected!("vpclmulqdq");
        caps.gfni = std::arch::is_x86_feature_detected!("gfni");
        caps.avx512f = std::arch::is_x86_feature_detected!("avx512f");
        caps.avx512bw = std::arch::is_x86_feature_detected!("avx512bw");
    }

    #[cfg(target_arch = "aarch64")]
    {
        caps.neon = std::arch::is_aarch64_feature_detected!("neon");
        caps.pmull = std::arch::is_aarch64_feature_detected!("pmull");
    }

    caps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_request_parser_is_stable() {
        assert_eq!(parse_backend_request("auto"), Some(BackendRequest::Auto));
        assert_eq!(parse_backend_request("AVX2"), Some(BackendRequest::Avx2));
        assert_eq!(
            parse_backend_request("neon+pmull"),
            Some(BackendRequest::NeonPmull)
        );
        assert_eq!(parse_backend_request("unknown"), None);
    }

    #[test]
    fn automatic_backend_never_exceeds_detected_capabilities() {
        let caps = *capabilities();
        let selected = select_backend(caps, BackendRequest::Auto);
        match selected {
            CpuBackend::Scalar => {}
            CpuBackend::Pclmul => assert!(caps.sse4_1 && caps.pclmulqdq),
            CpuBackend::Avx2 => assert!(caps.avx2 && caps.vpclmulqdq),
            CpuBackend::Avx512 => {
                assert!(caps.avx512f && caps.avx512bw && caps.vpclmulqdq)
            }
            CpuBackend::Neon => assert!(caps.neon),
            CpuBackend::NeonPmull => assert!(caps.neon && caps.pmull),
        }
    }
}
