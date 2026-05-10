use crate::telemetry::{MemoryRegion, ProcessInfo};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn parse_maps_path(pid: u32) -> PathBuf {
    PathBuf::from(format!("/proc/{}/maps", pid))
}

pub fn parse_statm(pid: u32) -> (u64, u64, u64, u64, u64, u64, u64) {
    let path = format!("/proc/{}/statm", pid);
    let content = fs::read_to_string(&path).unwrap_or_default();
    let parts: Vec<u64> = content
        .split_whitespace()
        .filter_map(|s| s.parse().ok())
        .collect();
    if parts.len() >= 7 {
        let page_size = 4096u64;
        (
            parts[0] * page_size / 1024,
            parts[1] * page_size / 1024,
            parts[2] * page_size / 1024,
            parts[3] * page_size / 1024,
            parts[4] * page_size / 1024,
            parts[5] * page_size / 1024,
            parts[6] * page_size / 1024,
        )
    } else {
        (0, 0, 0, 0, 0, 0, 0)
    }
}

#[allow(dead_code)]
pub fn parse_proc_stat(pid: u32) -> (u64, String) {
    let path = format!("/proc/{}/stat", pid);
    let content = fs::read_to_string(&path).unwrap_or_default();
    let parts: Vec<&str> = content.split_whitespace().collect();
    if parts.len() >= 24 {
        let utime = parts[13].parse().unwrap_or(0);
        let stime = parts[14].parse().unwrap_or(0);
        let name = if content.contains('(') {
            let start = content.find('(').unwrap() + 1;
            let end = content.rfind(')').unwrap();
            content[start..end].to_string()
        } else {
            String::from("unknown")
        };
        (utime + stime, name)
    } else {
        (0, String::from("unknown"))
    }
}

pub fn parse_cmdline(pid: u32) -> String {
    let path = format!("/proc/{}/cmdline", pid);
    fs::read_to_string(&path)
        .unwrap_or_default()
        .trim_end_matches('\0')
        .replace('\0', " ")
}

pub fn parse_comm(pid: u32) -> String {
    let path = format!("/proc/{}/comm", pid);
    fs::read_to_string(&path)
        .unwrap_or_default()
        .trim()
        .to_string()
}

pub fn parse_status(pid: u32) -> (u32, u32) {
    let path = format!("/proc/{}/status", pid);
    let content = fs::read_to_string(&path).unwrap_or_default();
    let mut uid = 0u32;
    let mut ppid = 0u32;
    for line in content.lines() {
        if line.starts_with("Uid:") {
            if let Some(val) = line.split_whitespace().nth(1) {
                uid = val.parse().unwrap_or(0);
            }
        }
        if line.starts_with("PPid:") {
            if let Some(val) = line.split_whitespace().nth(1) {
                ppid = val.parse().unwrap_or(0);
            }
        }
    }
    (uid, ppid)
}

pub fn parse_num_threads(pid: u32) -> u32 {
    let path = format!("/proc/{}/status", pid);
    let content = fs::read_to_string(&path).unwrap_or_default();
    for line in content.lines() {
        if line.starts_with("Threads:") {
            if let Some(val) = line.split_whitespace().nth(1) {
                return val.parse().unwrap_or(1);
            }
        }
    }
    1
}

pub fn parse_mappings(pid: u32, now: u64) -> Vec<MemoryRegion> {
    let path = parse_maps_path(pid);
    let file = match File::open(&path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    let reader = BufReader::new(file);
    let mut regions = Vec::new();

    for line in reader.lines().flatten() {
        if line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }

        let addr_range = parts[0];
        let perms_str = parts[1];
        let offset = parts[2].to_string();
        let dev = parts[3].to_string();
        let inode = parts[4].to_string();
        let pathname = if parts.len() > 5 {
            parts[5..].join(" ")
        } else {
            String::new()
        };

        let (start_str, end_str) = if let Some((s, e)) = addr_range.split_once('-') {
            (s, e)
        } else {
            continue;
        };

        let start = u64::from_str_radix(start_str, 16).unwrap_or(0);
        let end = u64::from_str_radix(end_str, 16).unwrap_or(0);
        let size = end.saturating_sub(start);

        let readable = perms_str.contains('r');
        let writable = perms_str.contains('w');
        let executable = perms_str.contains('x');
        let private_mapping = !perms_str.contains('s');
        let shared_mapping = perms_str.contains('s');

        let anonymous = pathname.is_empty()
            || pathname == "[anon]"
            || pathname == "[heap]"
            || pathname == "[stack]"
            || pathname == "[vdso]"
            || pathname == "[vsyscall]"
            || pathname.starts_with("[");
        let deleted_file = pathname.ends_with(" (deleted)") || pathname.contains("(deleted)");

        let rwx = readable && writable && executable;
        let wx = writable && executable && !readable;

        let is_anon = anonymous;

        regions.push(MemoryRegion {
            start,
            end,
            size,
            readable,
            writable,
            executable,
            private_mapping,
            shared_mapping,
            anonymous: is_anon,
            deleted_file,
            rwx,
            wx,
            pathname,
            inode,
            offset,
            device: dev,
            first_seen: Some(now),
            last_seen: Some(now),
            lifetime_seconds: None,
            entropy: None,
            entropy_classification: None,
            classification: Vec::new(),
        });
    }

    regions
}

pub fn get_process_info(pid: u32) -> ProcessInfo {
    let (uid, ppid) = parse_status(pid);
    let name = parse_comm(pid);
    let cmdline = parse_cmdline(pid);
    let threads = parse_num_threads(pid);
    let (rss_kb, vms_kb, _, _, _, _, _) = parse_statm(pid);

    ProcessInfo {
        pid,
        ppid,
        name,
        cmdline,
        uid,
        role: String::from("unknown"),
        threads,
        rss_kb,
        vms_kb,
        cpu_percent: 0.0,
    }
}

pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
