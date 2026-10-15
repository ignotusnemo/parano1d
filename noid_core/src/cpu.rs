// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero. All rights reserved.

//! Runtime CPU capability detection shared by the proof stack.
//!
//! A process selects the widest safe implementation embedded in its
//! architecture's binary. `NOID_CPU_BACKEND` is a diagnostic/test hook which
//! may restrict that selection to `scalar`, `pclmul`, `avx2`, `avx512`,
//! `neon`, or `neon-pmull`. Official artifacts keep their process-wide
//! baseline portable enough to inspect the host before proof code runs, then
//! dispatch the hot kernels at runtime. Production requires SSE4.1 and
//! PCLMULQDQ on x86-64, or NEON and PMULL on AArch64. The scalar
//! implementation remains a test oracle, never a production backend.

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

impl CpuBackend {
    /// Whether this backend has the carry-less multiplication required by a
    /// production node or miner.
    pub const fn production_ready(self) -> bool {
        matches!(
            self,
            Self::Pclmul | Self::Avx2 | Self::Avx512 | Self::NeonPmull
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProductionHardwareReport {
    pub architecture: &'static str,
    pub backend: CpuBackend,
    pub capabilities: CpuCapabilities,
}

impl ProductionHardwareReport {
    pub fn detect() -> Self {
        Self {
            architecture: std::env::consts::ARCH,
            backend: selected_backend(),
            capabilities: *capabilities(),
        }
    }

    pub const fn ready(self) -> bool {
        self.backend.production_ready()
    }

    pub const fn requirement(self) -> &'static str {
        production_hardware_requirement()
    }
}

impl fmt::Display for ProductionHardwareReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "ParanO(1)d hardware check")?;
        writeln!(formatter, "ARCHITECTURE {}", self.architecture)?;
        writeln!(formatter, "BACKEND {}", self.backend)?;
        #[cfg(target_arch = "x86_64")]
        writeln!(
            formatter,
            "FEATURES SSE4.1={} PCLMUL={} AVX2={} VPCLMUL={} AVX512F={} AVX512BW={}",
            yes_no(self.capabilities.sse4_1),
            yes_no(self.capabilities.pclmulqdq),
            yes_no(self.capabilities.avx2),
            yes_no(self.capabilities.vpclmulqdq),
            yes_no(self.capabilities.avx512f),
            yes_no(self.capabilities.avx512bw),
        )?;
        #[cfg(target_arch = "aarch64")]
        writeln!(
            formatter,
            "FEATURES NEON={} PMULL={}",
            yes_no(self.capabilities.neon),
            yes_no(self.capabilities.pmull),
        )?;
        if self.ready() {
            writeln!(formatter, "NODE READY")?;
            writeln!(formatter, "MINING CAPACITY CALIBRATED AT RUNTIME")
        } else {
            write_unsupported_cpu(formatter, self.requirement())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnsupportedProductionCpu {
    report: ProductionHardwareReport,
}

impl UnsupportedProductionCpu {
    pub const fn report(self) -> ProductionHardwareReport {
        self.report
    }
}

impl fmt::Display for UnsupportedProductionCpu {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_unsupported_cpu(formatter, self.report.requirement())
    }
}

impl std::error::Error for UnsupportedProductionCpu {}

/// Detect the selected runtime backend and reject the scalar/reference paths
/// before a production process opens configuration, wallet, or chain state.
pub fn ensure_production_hardware() -> Result<ProductionHardwareReport, UnsupportedProductionCpu> {
    let report = ProductionHardwareReport::detect();
    if report.ready() {
        Ok(report)
    } else {
        Err(UnsupportedProductionCpu { report })
    }
}

pub const fn production_hardware_requirement() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        return "x86-64: SSE4.1 + PCLMULQDQ";
    }
    #[cfg(target_arch = "aarch64")]
    {
        return "AArch64: NEON + PMULL";
    }
    #[allow(unreachable_code)]
    "an accelerated x86-64 or AArch64 proof backend"
}

const fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn write_unsupported_cpu(formatter: &mut fmt::Formatter<'_>, requirement: &str) -> fmt::Result {
    writeln!(formatter, "CPU UNSUPPORTED")?;
    writeln!(
        formatter,
        "This CPU is too old or does not expose the required instruction set."
    )?;
    writeln!(formatter, "MINIMUM {requirement}")?;
    #[cfg(target_arch = "x86_64")]
    {
        return write!(
            formatter,
            "Most Intel and AMD desktop and server CPUs released since 2012 support both."
        );
    }
    #[allow(unreachable_code)]
    Ok(())
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
        let production_floor = caps.sse4_1 && caps.pclmulqdq;
        let available = if production_floor && caps.avx512f && caps.avx512bw && caps.vpclmulqdq {
            CpuBackend::Avx512
        } else if production_floor && caps.avx2 && caps.vpclmulqdq {
            CpuBackend::Avx2
        } else if production_floor {
            CpuBackend::Pclmul
        } else {
            CpuBackend::Scalar
        };
        return match request {
            BackendRequest::Auto => available,
            BackendRequest::Scalar => CpuBackend::Scalar,
            BackendRequest::Pclmul if caps.sse4_1 && caps.pclmulqdq => CpuBackend::Pclmul,
            BackendRequest::Avx2 if production_floor && caps.avx2 && caps.vpclmulqdq => {
                CpuBackend::Avx2
            }
            BackendRequest::Avx512
                if production_floor && caps.avx512f && caps.avx512bw && caps.vpclmulqdq =>
            {
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
        match request {
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
        }
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

    #[test]
    fn production_never_accepts_reference_backends() {
        assert!(!CpuBackend::Scalar.production_ready());
        assert!(!CpuBackend::Neon.production_ready());
        assert!(CpuBackend::Pclmul.production_ready());
        assert!(CpuBackend::Avx2.production_ready());
        assert!(CpuBackend::Avx512.production_ready());
        assert!(CpuBackend::NeonPmull.production_ready());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn wider_x86_features_do_not_bypass_the_production_floor() {
        let caps = CpuCapabilities {
            avx2: true,
            vpclmulqdq: true,
            avx512f: true,
            avx512bw: true,
            ..CpuCapabilities::default()
        };
        assert_eq!(
            select_backend(caps, BackendRequest::Auto),
            CpuBackend::Scalar
        );
    }

    #[test]
    fn hardware_report_matches_the_selected_backend() {
        let report = ProductionHardwareReport::detect();
        assert_eq!(report.backend, selected_backend());
        assert_eq!(report.capabilities, *capabilities());
        assert_eq!(report.ready(), report.backend.production_ready());
        assert!(!report.requirement().is_empty());
        let rendered = report.to_string();
        assert!(rendered.contains("ParanO(1)d hardware check"));
        assert!(rendered.contains("ARCHITECTURE"));
        assert!(rendered.contains("BACKEND"));
    }

    #[test]
    fn unsupported_report_states_the_exact_minimum() {
        let report = ProductionHardwareReport {
            architecture: std::env::consts::ARCH,
            backend: CpuBackend::Scalar,
            capabilities: CpuCapabilities::default(),
        };
        let rendered = report.to_string();
        assert!(rendered.contains("CPU UNSUPPORTED"));
        assert!(rendered
            .contains("This CPU is too old or does not expose the required instruction set."));
        assert!(rendered.contains(&format!("MINIMUM {}", production_hardware_requirement())));
        #[cfg(target_arch = "x86_64")]
        assert!(rendered.contains(
            "Most Intel and AMD desktop and server CPUs released since 2012 support both."
        ));
        #[cfg(target_arch = "aarch64")]
        assert!(!rendered.contains("Intel and AMD"));
    }
}
