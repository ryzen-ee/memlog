use serde::{Deserialize, Serialize};

/// Represents a single memory region from /proc/<pid>/maps
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
    pub size: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub private_mapping: bool,
    pub shared_mapping: bool,
    pub anonymous: bool,
    pub deleted_file: bool,
    pub rwx: bool,
    pub wx: bool,
    pub pathname: String,
    pub inode: String,
    pub offset: String,
    pub device: String,
    pub first_seen: Option<u64>,
    pub last_seen: Option<u64>,
    pub lifetime_seconds: Option<u64>,
    pub entropy: Option<f64>,
    pub entropy_classification: Option<String>,
    pub classification: Vec<String>, // jit_region, wasm_region, gpu_region, shellcode_like, etc.
}

/// Represents process information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub cmdline: String,
    pub uid: u32,
    pub role: String, // browser, renderer, gpu-process, utility, extension, zygote, unknown
    pub threads: u32,
    pub rss_kb: u64,
    pub vms_kb: u64,
    pub cpu_percent: f32,
}

/// Complete telemetry data for a process snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryData {
    pub timestamp: String, // ISO 8601 UTC
    pub process: ProcessInfo,
    pub stats: MemoryStats,
    pub memory: MemorySummary,
    pub regions: Vec<MemoryRegion>,
    pub flags: Vec<String>,
    pub score: f32, // 0.0 - 1.0
}

/// Memory statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryStats {
    pub total_regions: usize,
    pub suspicious_regions: usize,
    pub rwx_regions: usize,
    pub wx_regions: usize,
    pub anon_exec_regions: usize,
    pub large_anon_regions: usize,
    pub jit_regions: usize,
    pub wasm_regions: usize,
    pub gpu_regions: usize,
    pub deleted_exec_mappings: usize,
    pub stack_exec_regions: usize,
    pub heap_exec_regions: usize,
    pub high_entropy_regions: usize,
}

/// Memory summary (from /proc/<pid>/statm and /proc/<pid>/stat)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySummary {
    pub rss_kb: u64,
    pub vms_kb: u64,
    pub shared_kb: u64,
    pub text_kb: u64,
    pub lib_kb: u64,
    pub data_kb: u64,
    pub dt_kb: u64,
}

/// Baseline data for comparison
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct Baseline {
    pub process_name: String,
    pub expected_rwx_range: (usize, usize),
    pub expected_anon_exec_range: (usize, usize),
    pub expected_entropy_range: (f64, f64),
    pub sample_count: usize,
    pub last_updated: String,
}
