use crate::classifier::get_suspicious_count;
use crate::entropy::entropy_to_score;
use crate::role::ProcessRole;
use crate::telemetry::{MemoryRegion, MemoryStats};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringWeights {
    pub rwx_weight: f32,
    pub wx_weight: f32,
    pub shellcode_weight: f32,
    pub deleted_exec_weight: f32,
    pub stack_exec_weight: f32,
    pub heap_exec_weight: f32,
    pub large_anon_weight: f32,
    pub writable_exec_weight: f32,
    pub entropy_weight: f32,
    pub role_multiplier: f32,
}

impl Default for ScoringWeights {
    fn default() -> Self {
        Self {
            rwx_weight: 0.05,
            wx_weight: 0.15,
            shellcode_weight: 0.4,
            deleted_exec_weight: 0.25,
            stack_exec_weight: 0.35,
            heap_exec_weight: 0.35,
            large_anon_weight: 0.2,
            writable_exec_weight: 0.15,
            entropy_weight: 0.2,
            role_multiplier: 1.0,
        }
    }
}

pub struct ScoringEngine {
    weights: ScoringWeights,
    baseline: Option<BaselineProfile>,
}

impl Default for ScoringEngine {
    fn default() -> Self {
        Self {
            weights: ScoringWeights::default(),
            baseline: None,
        }
    }
}

impl ScoringEngine {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(dead_code)]
    pub fn with_baseline(mut self, baseline: BaselineProfile) -> Self {
        self.baseline = Some(baseline);
        self
    }

    pub fn with_role(mut self, role: ProcessRole) -> Self {
        self.weights.role_multiplier = match role {
            ProcessRole::Browser => 0.8,
            ProcessRole::Renderer => 0.85,
            ProcessRole::GpuProcess => 0.9,
            ProcessRole::Utility => 0.95,
            ProcessRole::Extension => 0.95,
            ProcessRole::Zygote => 1.0,
            ProcessRole::Unknown => 1.0,
        };
        self
    }

    pub fn calculate_score(&self, regions: &[MemoryRegion], stats: &MemoryStats) -> f32 {
        let mut score = 0.0f32;

        let rwx_count = regions.iter().filter(|r| r.rwx).count() as f32;
        score += self.weights.rwx_weight * rwx_count.min(10.0) / 10.0;

        let wx_count = regions.iter().filter(|r| r.wx).count() as f32;
        score += self.weights.wx_weight * wx_count.min(5.0) / 5.0;

        let shellcode_count = regions
            .iter()
            .filter(|r| r.classification.iter().any(|c| c == "shellcode_like"))
            .count() as f32;
        score += self.weights.shellcode_weight * shellcode_count;

        let deleted_count = regions
            .iter()
            .filter(|r| r.classification.iter().any(|c| c == "deleted_exec_mapping"))
            .count() as f32;
        score += self.weights.deleted_exec_weight * deleted_count;

        let stack_exec = regions
            .iter()
            .filter(|r| r.classification.iter().any(|c| c == "stack_exec"))
            .count() as f32;
        score += self.weights.stack_exec_weight * stack_exec;

        let heap_exec = regions
            .iter()
            .filter(|r| r.classification.iter().any(|c| c == "heap_exec"))
            .count() as f32;
        score += self.weights.heap_exec_weight * heap_exec;

        let large_anon = regions
            .iter()
            .filter(|r| {
                r.classification
                    .iter()
                    .any(|c| c == "suspicious_large_anonymous")
            })
            .count() as f32;
        score += self.weights.large_anon_weight * large_anon;

        let writable_exec = regions
            .iter()
            .filter(|r| r.classification.iter().any(|c| c == "writable_exec_code"))
            .count() as f32;
        score += self.weights.writable_exec_weight * writable_exec;

        let entropy_score = regions
            .iter()
            .filter_map(|r| r.entropy)
            .map(entropy_to_score)
            .fold(0.0f32, |acc, s| acc + s);
        score += self.weights.entropy_weight * (entropy_score / regions.len().max(1) as f32);

        score *= self.weights.role_multiplier;

        if let Some(ref baseline) = self.baseline {
            score = self.apply_baseline_adjustment(score, stats, baseline);
        }

        score.min(1.0).max(0.0)
    }

    fn apply_baseline_adjustment(
        &self,
        mut score: f32,
        stats: &MemoryStats,
        baseline: &BaselineProfile,
    ) -> f32 {
        let rwx_deviation = (stats.rwx_regions as i32 - baseline.expected_rwx as i32).abs() as f32;
        let anon_deviation =
            (stats.anon_exec_regions as i32 - baseline.expected_anon_exec as i32).abs() as f32;

        if rwx_deviation > baseline.std_rwx * 2.0 || anon_deviation > baseline.std_anon_exec * 2.0 {
            score = (score * 1.5).min(1.0);
        }

        score
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineProfile {
    pub process_name: String,
    pub expected_rwx: usize,
    pub std_rwx: f32,
    pub expected_anon_exec: usize,
    pub std_anon_exec: f32,
    pub expected_entropy_avg: f64,
    pub sample_count: usize,
    pub created_at: String,
}

impl BaselineProfile {
    pub fn from_stats(name: &str, stats: &[MemoryStats]) -> Self {
        if stats.is_empty() {
            return Self {
                process_name: name.to_string(),
                expected_rwx: 0,
                std_rwx: 0.0,
                expected_anon_exec: 0,
                std_anon_exec: 0.0,
                expected_entropy_avg: 0.0,
                sample_count: 0,
                created_at: chrono_lite_now(),
            };
        }

        let rwx_values: Vec<f32> = stats.iter().map(|s| s.rwx_regions as f32).collect();
        let anon_values: Vec<f32> = stats.iter().map(|s| s.anon_exec_regions as f32).collect();

        let rwx_mean = rwx_values.iter().sum::<f32>() / rwx_values.len() as f32;
        let anon_mean = anon_values.iter().sum::<f32>() / anon_values.len() as f32;

        let rwx_variance = rwx_values
            .iter()
            .map(|v| (v - rwx_mean).powi(2))
            .sum::<f32>()
            / rwx_values.len() as f32;
        let anon_variance = anon_values
            .iter()
            .map(|v| (v - anon_mean).powi(2))
            .sum::<f32>()
            / anon_values.len() as f32;

        Self {
            process_name: name.to_string(),
            expected_rwx: rwx_mean as usize,
            std_rwx: rwx_variance.sqrt(),
            expected_anon_exec: anon_mean as usize,
            std_anon_exec: anon_variance.sqrt(),
            expected_entropy_avg: 0.0,
            sample_count: stats.len(),
            created_at: chrono_lite_now(),
        }
    }

    #[allow(dead_code)]
    pub fn deviation_score(&self, stats: &MemoryStats) -> f32 {
        let rwx_dev = (stats.rwx_regions as i32 - self.expected_rwx as i32).abs() as f32
            / self.std_rwx.max(1.0);
        let anon_dev = (stats.anon_exec_regions as i32 - self.expected_anon_exec as i32).abs()
            as f32
            / self.std_anon_exec.max(1.0);

        (rwx_dev + anon_dev) / 2.0
    }
}

fn chrono_lite_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let days = now / 86400;
    let rem = now % 86400;
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;

    let mut year: i64 = 1970;
    let mut day = days as i64;
    loop {
        let leap = if is_leap_year(year) { 366 } else { 365 };
        if day < leap {
            break;
        }
        day -= leap;
        year += 1;
    }

    let mut month = 1u32;
    loop {
        let days_in_month = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 => {
                if is_leap_year(year) {
                    29
                } else {
                    28
                }
            }
            _ => 30,
        };
        if day < days_in_month {
            break;
        }
        day -= days_in_month;
        month += 1;
    }

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        year,
        month,
        day + 1,
        hour,
        min,
        sec
    )
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

pub fn calculate_stats(regions: &[MemoryRegion]) -> MemoryStats {
    MemoryStats {
        total_regions: regions.len(),
        suspicious_regions: get_suspicious_count(regions),
        rwx_regions: regions.iter().filter(|r| r.rwx).count(),
        wx_regions: regions.iter().filter(|r| r.wx).count(),
        anon_exec_regions: regions
            .iter()
            .filter(|r| r.anonymous && r.executable)
            .count(),
        large_anon_regions: regions
            .iter()
            .filter(|r| r.anonymous && r.size >= 1024 * 1024)
            .count(),
        jit_regions: regions
            .iter()
            .filter(|r| r.classification.iter().any(|c| c == "jit_region"))
            .count(),
        wasm_regions: regions
            .iter()
            .filter(|r| r.classification.iter().any(|c| c == "wasm_region"))
            .count(),
        gpu_regions: regions
            .iter()
            .filter(|r| r.classification.iter().any(|c| c == "gpu_region"))
            .count(),
        deleted_exec_mappings: regions
            .iter()
            .filter(|r| r.classification.iter().any(|c| c == "deleted_exec_mapping"))
            .count(),
        stack_exec_regions: regions
            .iter()
            .filter(|r| r.classification.iter().any(|c| c == "stack_exec"))
            .count(),
        heap_exec_regions: regions
            .iter()
            .filter(|r| r.classification.iter().any(|c| c == "heap_exec"))
            .count(),
        high_entropy_regions: regions
            .iter()
            .filter(|r| r.entropy.map(|e| e >= 5.5).unwrap_or(false))
            .count(),
    }
}
