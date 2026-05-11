mod baseline;
mod classifier;
mod entropy;
mod parser;
mod role;
mod scoring;
mod telemetry;

use baseline::BaselineManager;
use classifier::classify_region;
use entropy::calculate_region_entropy;
use parser::{current_timestamp, get_process_info, parse_mappings};
use role::{detect_process_role, ProcessRole};
use scoring::{calculate_stats, ScoringEngine};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use telemetry::{MemoryRegion, MemorySummary, TelemetryData};

#[derive(Debug, Clone)]
pub enum OutputFormat {
    Minimal,
    Verbose,
    Json,
    Csv,
}

struct RegionHistory {
    first_seen: u64,
    last_seen: u64,
}

impl RegionHistory {
    fn new(now: u64) -> Self {
        Self {
            first_seen: now,
            last_seen: now,
        }
    }
    fn update(&mut self, now: u64) {
        self.last_seen = now;
    }
    fn lifetime(&self) -> u64 {
        self.last_seen.saturating_sub(self.first_seen)
    }
}

#[allow(dead_code)]
struct AppState {
    region_history: HashMap<(u32, u64), RegionHistory>,
    baseline_manager: BaselineManager,
    enable_entropy: bool,
    learn_mode: bool,
    output_format: OutputFormat,
    show_scores: bool,
    process_name: String,
}

impl AppState {
    fn new(process_name: &str) -> Self {
        let mut baseline_manager = BaselineManager::new();
        let _ = baseline_manager.load();

        Self {
            region_history: HashMap::new(),
            baseline_manager,
            enable_entropy: false,
            learn_mode: false,
            output_format: OutputFormat::Minimal,
            show_scores: true,
            process_name: process_name.to_string(),
        }
    }
}

fn chrono_lite(secs: u64) -> String {
    let days = secs / 86400;
    let rem = secs % 86400;
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

#[allow(dead_code)]
fn current_timestamp_str() -> String {
    chrono_lite(current_timestamp())
}

fn parse_mappings_with_history(pid: u32, state: &mut AppState, now: u64) -> Vec<MemoryRegion> {
    let mut regions = parse_mappings(pid, now);

    for region in &mut regions {
        let key = (pid, region.start);
        if let Some(history) = state.region_history.get_mut(&key) {
            history.update(now);
            region.first_seen = Some(history.first_seen);
            region.last_seen = Some(history.last_seen);
            region.lifetime_seconds = Some(history.lifetime());
        } else {
            state.region_history.insert(key, RegionHistory::new(now));
        }

        classify_region(region);

        if state.enable_entropy {
            calculate_region_entropy(pid, region);
        }
    }

    regions
}

fn collect_flags(regions: &[MemoryRegion]) -> Vec<String> {
    let mut flags = HashSet::new();
    for region in regions {
        for class in &region.classification {
            if class != "clean" {
                flags.insert(class.clone());
            }
        }
        if region.entropy.map(|e| e >= 5.5).unwrap_or(false) {
            flags.insert("high_entropy".to_string());
        }
    }
    let mut result: Vec<String> = flags.into_iter().collect();
    result.sort();
    if result.is_empty() {
        result.push("clean".to_string());
    }
    result
}

fn build_telemetry_data(
    pid: u32,
    regions: Vec<MemoryRegion>,
    now: u64,
    state: &mut AppState,
) -> TelemetryData {
    let mut info = get_process_info(pid);
    detect_process_role(&mut info);

    let stats = calculate_stats(&regions);
    let flags = collect_flags(&regions);

    let scoring_engine = ScoringEngine::new().with_role(match info.role.as_str() {
        "browser" => ProcessRole::Browser,
        "renderer" => ProcessRole::Renderer,
        "gpu-process" => ProcessRole::GpuProcess,
        "utility" => ProcessRole::Utility,
        "extension" => ProcessRole::Extension,
        "zygote" => ProcessRole::Zygote,
        _ => ProcessRole::Unknown,
    });

    let score = scoring_engine.calculate_score(&regions, &stats);

    let (rss, vms, shared, text, lib, data, dt) = parser::parse_statm(pid);

    if state.learn_mode {
        state.baseline_manager.add_sample(&info.name, stats.clone());
    }

    TelemetryData {
        timestamp: chrono_lite(now),
        process: info,
        stats,
        memory: MemorySummary {
            rss_kb: rss,
            vms_kb: vms,
            shared_kb: shared,
            text_kb: text,
            lib_kb: lib,
            data_kb: data,
            dt_kb: dt,
        },
        regions,
        flags,
        score,
    }
}

fn print_minimal(telemetry: &TelemetryData) {
    println!(
        "[{}] PID {} ({}) | total: {} | suspicious: {} | score: {:.2}",
        telemetry.timestamp,
        telemetry.process.pid,
        telemetry.process.role,
        telemetry.stats.total_regions,
        telemetry.stats.suspicious_regions,
        telemetry.score
    );
}

fn print_verbose(telemetry: &TelemetryData) {
    println!("=== Snapshot {} ===", telemetry.timestamp);
    println!(
        "PID: {} | Process: {} | Role: {}",
        telemetry.process.pid, telemetry.process.name, telemetry.process.role
    );
    println!(
        "Regions: {} | Suspicious: {} | Score: {:.2}",
        telemetry.stats.total_regions, telemetry.stats.suspicious_regions, telemetry.score
    );
    println!(
        "RSS: {} KB | VMS: {} KB",
        telemetry.memory.rss_kb, telemetry.memory.vms_kb
    );
    println!("Flags: {}", telemetry.flags.join(", "));
    println!("--- Classification Stats ---");
    println!(
        "  RWX: {} | WX: {} | AnonExec: {}",
        telemetry.stats.rwx_regions, telemetry.stats.wx_regions, telemetry.stats.anon_exec_regions
    );
    println!(
        "  JIT: {} | WASM: {} | GPU: {}",
        telemetry.stats.jit_regions, telemetry.stats.wasm_regions, telemetry.stats.gpu_regions
    );
    println!(
        "  HighEntropy: {} | DeletedExec: {} | StackExec: {}",
        telemetry.stats.high_entropy_regions,
        telemetry.stats.deleted_exec_mappings,
        telemetry.stats.stack_exec_regions
    );
    println!("--- Regions (first 20) ---");
    for (i, region) in telemetry.regions.iter().take(20).enumerate() {
        let cls = region.classification.join(",");
        let entropy_str = region
            .entropy
            .map(|e| format!("{:.2}", e))
            .unwrap_or_else(|| "N/A".to_string());
        println!(
            "  {:2}. {} | r={} w={} x={} | size={} | {} | ent={} | {}",
            i + 1,
            format!("{:016x}-{:016x}", region.start, region.end),
            if region.readable { "r" } else { "-" },
            if region.writable { "w" } else { "-" },
            if region.executable { "x" } else { "-" },
            region.size,
            region.pathname,
            entropy_str,
            cls
        );
    }
    if telemetry.regions.len() > 20 {
        println!("  ... and {} more regions", telemetry.regions.len() - 20);
    }
    println!();
}

fn print_json(telemetry: &TelemetryData, output_path: &Option<PathBuf>) {
    let json = serde_json::to_string(telemetry).unwrap();
    if let Some(path) = output_path {
        if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = file.write_all(json.as_bytes());
            let _ = file.write_all(b"\n");
        }
    } else {
        println!("{}", json);
    }
}

fn print_csv_header() {
    println!("timestamp,pid,process_name,role,total_regions,suspicious,rwx,wx,anon_exec,jit,wasm,gpu,high_entropy,deleted_exec,stack_exec,heap_exec,score");
}

fn print_csv(telemetry: &TelemetryData) {
    println!(
        "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{:.4}",
        telemetry.timestamp,
        telemetry.process.pid,
        telemetry.process.name,
        telemetry.process.role,
        telemetry.stats.total_regions,
        telemetry.stats.suspicious_regions,
        telemetry.stats.rwx_regions,
        telemetry.stats.wx_regions,
        telemetry.stats.anon_exec_regions,
        telemetry.stats.jit_regions,
        telemetry.stats.wasm_regions,
        telemetry.stats.gpu_regions,
        telemetry.stats.high_entropy_regions,
        telemetry.stats.deleted_exec_mappings,
        telemetry.stats.stack_exec_regions,
        telemetry.stats.heap_exec_regions,
        telemetry.score
    );
}

fn find_pids_by_name(name: &str) -> Vec<u32> {
    let mut pids = Vec::new();
    let proc_path = PathBuf::from("/proc");

    if let Ok(entries) = fs::read_dir(proc_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(pid_str) = path.file_name() {
                if let Ok(pid) = pid_str.to_string_lossy().parse::<u32>() {
                    let cmdline_path = path.join("cmdline");
                    if let Ok(content) = fs::read_to_string(&cmdline_path) {
                        let cmdline = content.replace('\0', " ");
                        if cmdline.contains(name) {
                            pids.push(pid);
                        }
                    }
                }
            }
        }
    }
    pids
}

fn verify_pid(pid: u32) -> bool {
    let path = format!("/proc/{}/maps", pid);
    fs::metadata(&path).is_ok()
}

fn print_usage(program: &str) {
    println!("memlog - Behavioral Memory Telemetry");
    println!();
    println!("Usage: {} [OPTIONS]", program);
    println!("Options:");
    println!("  --pid <PID>           Process ID to monitor");
    println!("  --sourceproc <NAME>   Search and monitor by process name");
    println!("  --interval <SECS>     Sampling interval (default: 1)");
    println!("  --duration <SECS>     Auto-exit after specified seconds");
    println!("  --output <FILE>       Output file (for json/csv)");
    println!("  --format <MODE>       Output format: minimal, verbose, json, csv");
    println!("  --entropy             Enable entropy analysis for shellcode detection");
    println!("  --learn-baseline      Enable baseline learning mode");
    println!("  --baseline <NAME>     Use named baseline for scoring");
    println!("  --verbose, -v         Show full details (alias for --format verbose)");
    println!("  --help, -h            Show this help message");
    println!();
    println!("By Ryzen <3");
}

fn parse_args() -> (
    Vec<u32>,
    std::time::Duration,
    Option<u64>,
    Option<PathBuf>,
    bool,
    OutputFormat,
    bool,
    Option<String>,
    Option<PathBuf>,
) {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_usage(&program);
        std::process::exit(0);
    }

    let mut pids: Vec<u32> = Vec::new();
    let mut source_proc: Option<String> = None;
    let mut interval = std::time::Duration::from_secs(1);
    let mut duration: Option<u64> = None;
    let mut output_path: Option<PathBuf> = None;
    let mut output_format = OutputFormat::Minimal;
    let mut enable_entropy = false;
    let mut learn_baseline = false;
    let mut baseline_file: Option<PathBuf> = None;

    for i in 0..args.len() {
        match args[i].as_str() {
            "--pid" if i + 1 < args.len() => {
                if let Ok(p) = args[i + 1].parse() {
                    pids.push(p);
                }
            }
            s if s.starts_with("--pid=") => {
                if let Ok(p) = s.trim_start_matches("--pid=").parse() {
                    pids.push(p);
                }
            }
            "--sourceproc" | "--searchproc" if i + 1 < args.len() => {
                source_proc = Some(args[i + 1].clone());
            }
            s if s.starts_with("--sourceproc=") || s.starts_with("--searchproc=") => {
                let prefix = if s.starts_with("--sourceproc=") {
                    "--sourceproc="
                } else {
                    "--searchproc="
                };
                source_proc = Some(s.trim_start_matches(prefix).to_string());
            }
            "--interval" if i + 1 < args.len() => {
                if let Ok(sec) = args[i + 1].parse() {
                    interval = std::time::Duration::from_secs(sec);
                }
            }
            s if s.starts_with("--interval=") => {
                if let Ok(sec) = s.trim_start_matches("--interval=").parse() {
                    interval = std::time::Duration::from_secs(sec);
                }
            }
            "--duration" if i + 1 < args.len() => {
                if let Ok(sec) = args[i + 1].parse() {
                    duration = Some(sec);
                }
            }
            s if s.starts_with("--duration=") => {
                if let Ok(sec) = s.trim_start_matches("--duration=").parse() {
                    duration = Some(sec);
                }
            }
            "--output" | "-o" if i + 1 < args.len() => {
                output_path = Some(PathBuf::from(&args[i + 1]));
            }
            s if s.starts_with("--output=") || s.starts_with("-o=") => {
                let prefix = if s.starts_with("--output=") {
                    "--output="
                } else {
                    "-o="
                };
                output_path = Some(PathBuf::from(s.trim_start_matches(prefix)));
            }
            "--format" if i + 1 < args.len() => {
                output_format = match args[i + 1].to_lowercase().as_str() {
                    "verbose" | "detailed" => OutputFormat::Verbose,
                    "json" => OutputFormat::Json,
                    "csv" => OutputFormat::Csv,
                    _ => OutputFormat::Minimal,
                };
            }
            "--entropy" => {
                enable_entropy = true;
            }
            "--learn-baseline" => {
                learn_baseline = true;
            }
            "--baseline" if i + 1 < args.len() => {
                baseline_file = Some(PathBuf::from(&args[i + 1]));
            }
            s if s.starts_with("--baseline=") => {
                baseline_file = Some(PathBuf::from(s.trim_start_matches("--baseline=")));
            }
            "--verbose" | "-v" => {
                output_format = OutputFormat::Verbose;
            }
            _ => {}
        }
    }

    if source_proc.is_some() {
        if let Some(name) = &source_proc {
            println!("Searching for processes matching: {}", name);
            let found_pids = find_pids_by_name(name);
            if found_pids.is_empty() {
                eprintln!("No processes found matching '{}'", name);
                std::process::exit(1);
            }
            println!(
                "Found {} matching process(es): {:?}",
                found_pids.len(),
                found_pids
            );
            pids = found_pids;
        }
    }

    if pids.is_empty() {
        eprintln!("Error: --pid or --sourceproc argument is required");
        eprintln!("Run with --help for usage information");
        std::process::exit(1);
    }

    for pid in &pids {
        if !verify_pid(*pid) {
            eprintln!("Error: Process {} does not exist or is not accessible", pid);
            std::process::exit(1);
        }
    }

    (
        pids,
        interval,
        duration,
        output_path,
        enable_entropy,
        output_format,
        learn_baseline,
        None,
        baseline_file,
    )
}

fn main() {
    let (
        pids,
        interval,
        duration,
        output_path,
        enable_entropy,
        output_format,
        learn_baseline,
        _,
        _baseline_file,
    ) = parse_args();

    println!("memlog - Behavioral Memory Telemetry");
    println!("Monitoring PID(s): {:?}", pids);
    println!("Interval: {} seconds", interval.as_secs());
    if let Some(sec) = duration {
        println!("Duration: {} seconds", sec);
    }
    match &output_format {
        OutputFormat::Minimal => println!("Format: minimal"),
        OutputFormat::Verbose => println!("Format: verbose"),
        OutputFormat::Json => println!("Format: json"),
        OutputFormat::Csv => println!("Format: csv"),
    }
    if enable_entropy {
        println!("Entropy analysis: enabled");
    }
    if learn_baseline {
        println!("Baseline learning: enabled");
    }
    println!();

    let process_name = if let Some(pid) = pids.first() {
        parser::parse_comm(*pid)
    } else {
        "memlog".to_string()
    };

    let mut state = AppState::new(&process_name);
    state.enable_entropy = enable_entropy;
    state.learn_mode = learn_baseline;

    let start_time = std::time::Instant::now();
    let pids_clone = pids.clone();

    let mut csv_header_printed = false;

    loop {
        let now = current_timestamp();

        for pid in &pids_clone {
            let regions = parse_mappings_with_history(*pid, &mut state, now);

            if regions.is_empty() {
                eprintln!(
                    "Warning: No regions read from PID {}. Process may have terminated.",
                    pid
                );
                continue;
            }

            let telemetry = build_telemetry_data(*pid, regions, now, &mut state);

            match &output_format {
                OutputFormat::Minimal => print_minimal(&telemetry),
                OutputFormat::Verbose => print_verbose(&telemetry),
                OutputFormat::Json => print_json(&telemetry, &output_path),
                OutputFormat::Csv => {
                    if !csv_header_printed {
                        print_csv_header();
                        csv_header_printed = true;
                    }
                    print_csv(&telemetry);
                }
            }
        }

        if let Some(sec) = duration {
            if start_time.elapsed().as_secs() >= sec {
                println!("\nDuration limit reached. Exiting.");
                if state.learn_mode && !state.baseline_manager.list_baselines().is_empty() {
                    println!(
                        "Learned baselines: {}",
                        state.baseline_manager.list_baselines().join(", ")
                    );
                }
                std::process::exit(0);
            }
        }

        std::thread::sleep(interval);
    }
}
