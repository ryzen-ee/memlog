use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

pub fn calculate_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let len = data.len() as f64;
    let mut freq = [0u64; 256];

    for &byte in data {
        freq[byte as usize] += 1;
    }

    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

pub fn classify_entropy(entropy: f64) -> &'static str {
    if entropy < 2.0 {
        "very_low"
    } else if entropy < 3.5 {
        "low"
    } else if entropy < 5.0 {
        "medium"
    } else if entropy < 6.5 {
        "high"
    } else {
        "very_high"
    }
}

#[allow(dead_code)]
pub fn is_high_entropy(entropy: f64) -> bool {
    entropy >= 5.5
}

pub fn read_memory_region_content(pid: u32, start: u64, _size: u64) -> Vec<u8> {
    const MAX_READ_SIZE: u64 = 1024 * 1024;
    let maps_path = format!("/proc/{}/maps", pid);

    let content = match std::fs::read_to_string(&maps_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }

        let addr_range = parts[0];
        if let Some((start_str, end_str)) = addr_range.split_once('-') {
            let region_start = u64::from_str_radix(start_str, 16).unwrap_or(0);
            if region_start == start {
                if let Ok(end) = u64::from_str_radix(end_str, 16) {
                    let actual_size = end - region_start;
                    if actual_size > 0 && actual_size <= MAX_READ_SIZE {
                        let mem_path = format!("/proc/{}/mem", pid);
                        if let Ok(mut file) = File::open(&mem_path) {
                            if file.seek(SeekFrom::Start(region_start)).is_ok() {
                                let mut buffer = vec![0u8; actual_size as usize];
                                if file.read(&mut buffer).is_ok() {
                                    return buffer;
                                }
                            }
                        }
                    }
                }
                break;
            }
        }
    }

    Vec::new()
}

pub fn calculate_region_entropy(pid: u32, region: &mut crate::telemetry::MemoryRegion) {
    let content = read_memory_region_content(pid, region.start, region.size);

    if !content.is_empty() {
        let entropy = calculate_shannon_entropy(&content);
        region.entropy = Some(entropy);
        region.entropy_classification = Some(classify_entropy(entropy).to_string());
    }
}

#[allow(dead_code)]
pub fn count_high_entropy_regions(regions: &[crate::telemetry::MemoryRegion]) -> usize {
    regions
        .iter()
        .filter(|r| r.entropy.map(|e| is_high_entropy(e)).unwrap_or(false))
        .count()
}

#[allow(dead_code)]
pub const ENTROPY_THRESHOLD_HIGH: f64 = 5.5;
#[allow(dead_code)]
pub const ENTROPY_THRESHOLD_MEDIUM: f64 = 4.0;

pub fn entropy_to_score(entropy: f64) -> f32 {
    if entropy >= 7.5 {
        1.0
    } else if entropy >= 7.0 {
        0.9
    } else if entropy >= 6.5 {
        0.7
    } else if entropy >= 6.0 {
        0.5
    } else if entropy >= 5.5 {
        0.3
    } else {
        0.0
    }
}
