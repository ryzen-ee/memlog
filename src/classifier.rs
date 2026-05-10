use crate::telemetry::MemoryRegion;
use std::collections::HashSet;

pub fn classify_region(region: &mut MemoryRegion) {
    let mut classifications: Vec<String> = Vec::new();

    if is_jit_region(region) {
        classifications.push("jit_region".to_string());
    }
    if is_wasm_region(region) {
        classifications.push("wasm_region".to_string());
    }
    if is_gpu_region(region) {
        classifications.push("gpu_region".to_string());
    }
    if is_shellcode_like(region) {
        classifications.push("shellcode_like".to_string());
    }
    if is_deleted_exec_mapping(region) {
        classifications.push("deleted_exec_mapping".to_string());
    }
    if is_stack_exec(region) {
        classifications.push("stack_exec".to_string());
    }
    if is_heap_exec(region) {
        classifications.push("heap_exec".to_string());
    }
    if is_module_backed_exec(region) {
        classifications.push("module_backed_exec".to_string());
    }
    if is_suspicious_rwx(region) {
        classifications.push("suspicious_rwx".to_string());
    }
    if is_suspicious_wx(region) {
        classifications.push("suspicious_wx".to_string());
    }
    if is_suspicious_large_anon(region) {
        classifications.push("suspicious_large_anonymous".to_string());
    }

    if region.writable && region.executable && !region.pathname.is_empty() {
        if !is_known_safe_path(&region.pathname) {
            classifications.push("writable_exec_code".to_string());
        }
    }

    if classifications.is_empty() {
        classifications.push("clean".to_string());
    }

    region.classification = classifications;
}

fn is_jit_region(region: &MemoryRegion) -> bool {
    let jit_patterns = [
        "jit-compile-cache",
        "jit-code-compilation",
        "V8 JIT",
        "JavaScript JIT",
        "ion",
        "baseline-jit",
        "baseline-code",
        "sparkplug",
        " TurboFan ",
        "/jit/",
        "_jit",
        "-jit-",
        "JITCode",
        "JITData",
    ];
    for pattern in jit_patterns {
        if region.pathname.contains(pattern) {
            return true;
        }
    }
    false
}

fn is_wasm_region(region: &MemoryRegion) -> bool {
    let wasm_patterns = [
        "wasm",
        "WebAssembly",
        "wasm_code",
        "wasm_data",
        "/wasm/",
        "-wasm-",
        ".wasm",
    ];
    for pattern in wasm_patterns {
        if region.pathname.to_lowercase().contains(pattern) {
            return true;
        }
    }
    false
}

fn is_gpu_region(region: &MemoryRegion) -> bool {
    let gpu_patterns = [
        "gpu", "nvidia", "cuda", "opencl", "render", "vulkan", "mesa", "dri", "i915", "amdgpu",
        "/dri/", "surface", "texture", "shader", "blit", "command", "buffer",
    ];
    for pattern in gpu_patterns {
        if region.pathname.to_lowercase().contains(pattern) {
            return true;
        }
    }
    false
}

fn is_shellcode_like(region: &MemoryRegion) -> bool {
    if !region.anonymous {
        return false;
    }

    let min_size = 4096;
    let max_size = 10 * 1024 * 1024;

    if region.size < min_size || region.size > max_size {
        return false;
    }

    if region.writable && region.executable {
        return true;
    }

    false
}

fn is_deleted_exec_mapping(region: &MemoryRegion) -> bool {
    region.deleted_file && region.executable
}

fn is_stack_exec(region: &MemoryRegion) -> bool {
    region.pathname == "[stack]" && region.executable
}

fn is_heap_exec(region: &MemoryRegion) -> bool {
    region.pathname == "[heap]" && region.executable
}

fn is_module_backed_exec(region: &MemoryRegion) -> bool {
    if region.pathname.is_empty() || region.pathname.starts_with('[') {
        return false;
    }

    if !region.executable {
        return false;
    }

    let exec_indicators = [
        ".so", ".bin", ".exe", ".dll", ".dylib", "/lib/", "/usr/", "/bin/",
    ];
    for indicator in exec_indicators {
        if region.pathname.contains(indicator) {
            return true;
        }
    }

    false
}

fn is_suspicious_rwx(region: &MemoryRegion) -> bool {
    region.rwx && !is_known_safe_path(&region.pathname)
}

fn is_suspicious_wx(region: &MemoryRegion) -> bool {
    region.wx && !is_known_safe_path(&region.pathname)
}

fn is_suspicious_large_anon(region: &MemoryRegion) -> bool {
    if !region.anonymous {
        return false;
    }

    const VERY_LARGE: u64 = 10 * 1024 * 1024;
    const SUSPICIOUSLY_LARGE: u64 = 1024 * 1024;

    region.size >= VERY_LARGE || (region.size >= SUSPICIOUSLY_LARGE && region.executable)
}

fn is_known_safe_path(path: &str) -> bool {
    let safe_paths = [
        "/usr/lib/",
        "/lib/",
        "/bin/",
        "/sbin/",
        "/opt/",
        "/usr/bin/",
        "/usr/sbin/",
        "/dev/",
        "/sys/",
        "/proc/",
    ];

    for safe in safe_paths {
        if path.starts_with(safe) {
            return true;
        }
    }
    false
}

#[allow(dead_code)]
pub fn get_flags_from_classification(classifications: &[String]) -> Vec<String> {
    let mut flags = classifications.to_vec();
    if !flags.iter().any(|f| f != "clean") {
        flags.push("clean".to_string());
    }
    flags
}

#[allow(dead_code)]
pub fn count_by_classification(regions: &[MemoryRegion], class: &str) -> usize {
    regions
        .iter()
        .filter(|r| r.classification.iter().any(|c| c == class))
        .count()
}

pub fn get_suspicious_count(regions: &[MemoryRegion]) -> usize {
    let suspicious_classes: HashSet<&str> = [
        "shellcode_like",
        "deleted_exec_mapping",
        "stack_exec",
        "heap_exec",
        "suspicious_rwx",
        "suspicious_wx",
        "suspicious_large_anonymous",
        "writable_exec_code",
    ]
    .iter()
    .cloned()
    .collect();

    regions
        .iter()
        .filter(|r| {
            r.classification
                .iter()
                .any(|c| suspicious_classes.contains(c.as_str()))
        })
        .count()
}
