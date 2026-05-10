use crate::telemetry::ProcessInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessRole {
    Browser,
    Renderer,
    GpuProcess,
    Utility,
    Extension,
    Zygote,
    Unknown,
}

impl ProcessRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProcessRole::Browser => "browser",
            ProcessRole::Renderer => "renderer",
            ProcessRole::GpuProcess => "gpu-process",
            ProcessRole::Utility => "utility",
            ProcessRole::Extension => "extension",
            ProcessRole::Zygote => "zygote",
            ProcessRole::Unknown => "unknown",
        }
    }
}

pub fn detect_process_role(info: &mut ProcessInfo) {
    let role = detect_role(&info.name, &info.cmdline);
    info.role = role.as_str().to_string();
}

fn detect_role(name: &str, cmdline: &str) -> ProcessRole {
    if is_browser_process(name, cmdline) {
        ProcessRole::Browser
    } else if is_renderer_process(name, cmdline) {
        ProcessRole::Renderer
    } else if is_gpu_process(name, cmdline) {
        ProcessRole::GpuProcess
    } else if is_utility_process(name, cmdline) {
        ProcessRole::Utility
    } else if is_extension_process(name, cmdline) {
        ProcessRole::Extension
    } else if is_zygote_process(name, cmdline) {
        ProcessRole::Zygote
    } else {
        ProcessRole::Unknown
    }
}

fn is_browser_process(name: &str, cmdline: &str) -> bool {
    let browser_names = [
        "chrome", "chromium", "firefox", "brave", "vivaldi", "opera", "edge", "browser",
    ];

    for n in browser_names {
        if name.to_lowercase().contains(n) || cmdline.to_lowercase().contains(n) {
            return true;
        }
    }
    false
}

fn is_renderer_process(name: &str, cmdline: &str) -> bool {
    let renderer_indicators = [
        "renderer",
        "render-process",
        "Renderer",
        "tab",
        "content",
        "web-content",
        "Web Content",
    ];

    for indicator in renderer_indicators {
        if name.contains(indicator) || cmdline.contains(indicator) {
            return true;
        }
    }

    if name.contains("chrome") && cmdline.contains("--type=renderer") {
        return true;
    }

    false
}

fn is_gpu_process(name: &str, cmdline: &str) -> bool {
    let gpu_indicators = [
        "gpu",
        "GPU Process",
        "gpu-process",
        "viz",
        "compositor",
        "viz",
        "-gpu",
        "_gpu",
        "dri",
        "gl",
    ];

    for indicator in gpu_indicators {
        if name.contains(indicator) || cmdline.contains(indicator) {
            return true;
        }
    }

    if cmdline.contains("--type=gpu-process")
        || cmdline.contains("type=utility") && cmdline.contains("gpu")
    {
        return true;
    }

    false
}

fn is_utility_process(name: &str, cmdline: &str) -> bool {
    if name.contains("utility") || name.contains("Utility") {
        return true;
    }

    if cmdline.contains("--type=utility") {
        return true;
    }

    let utility_types = [
        "sandbox",
        "network",
        "audio",
        "video",
        "storage",
        "proxy",
        "scheduler",
    ];

    for utype in utility_types {
        if cmdline.contains(&format!("--type={}", utype)) {
            return true;
        }
    }

    false
}

fn is_extension_process(name: &str, cmdline: &str) -> bool {
    let ext_indicators = [
        "extension",
        "Extension",
        "plugin",
        "Plugin",
        "helper",
        "pdf",
        "pdfjs",
    ];

    for indicator in ext_indicators {
        if name.contains(indicator) || cmdline.contains(indicator) {
            return true;
        }
    }

    if cmdline.contains("--type=extension") || cmdline.contains("extension-process") {
        return true;
    }

    false
}

fn is_zygote_process(name: &str, cmdline: &str) -> bool {
    if name == "zygote" || name == "zygote64" || name.contains("zygote") {
        return true;
    }

    if cmdline.contains("zygote") {
        return true;
    }

    false
}

#[allow(dead_code)]
pub fn get_role_threshold(role: ProcessRole) -> RoleThresholds {
    match role {
        ProcessRole::Browser => RoleThresholds {
            max_rwx_regions: 50,
            max_anon_exec_regions: 20,
            max_suspicious_score: 0.7,
            allowed_classes: vec!["jit_region", "wasm_region", "gpu_region"],
        },
        ProcessRole::Renderer => RoleThresholds {
            max_rwx_regions: 40,
            max_anon_exec_regions: 15,
            max_suspicious_score: 0.6,
            allowed_classes: vec!["jit_region", "wasm_region", "module_backed_exec"],
        },
        ProcessRole::GpuProcess => RoleThresholds {
            max_rwx_regions: 30,
            max_anon_exec_regions: 10,
            max_suspicious_score: 0.5,
            allowed_classes: vec!["gpu_region"],
        },
        ProcessRole::Utility => RoleThresholds {
            max_rwx_regions: 20,
            max_anon_exec_regions: 5,
            max_suspicious_score: 0.4,
            allowed_classes: vec![],
        },
        ProcessRole::Extension => RoleThresholds {
            max_rwx_regions: 15,
            max_anon_exec_regions: 5,
            max_suspicious_score: 0.4,
            allowed_classes: vec![],
        },
        ProcessRole::Zygote => RoleThresholds {
            max_rwx_regions: 10,
            max_anon_exec_regions: 3,
            max_suspicious_score: 0.3,
            allowed_classes: vec![],
        },
        ProcessRole::Unknown => RoleThresholds {
            max_rwx_regions: 5,
            max_anon_exec_regions: 2,
            max_suspicious_score: 0.3,
            allowed_classes: vec![],
        },
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RoleThresholds {
    pub max_rwx_regions: usize,
    pub max_anon_exec_regions: usize,
    pub max_suspicious_score: f32,
    pub allowed_classes: Vec<&'static str>,
}

#[allow(dead_code)]
pub fn reduce_false_positives(classifications: &[String], role: &str) -> Vec<String> {
    let thresholds = match role {
        "browser" => get_role_threshold(ProcessRole::Browser),
        "renderer" => get_role_threshold(ProcessRole::Renderer),
        "gpu-process" => get_role_threshold(ProcessRole::GpuProcess),
        "utility" => get_role_threshold(ProcessRole::Utility),
        "extension" => get_role_threshold(ProcessRole::Extension),
        "zygote" => get_role_threshold(ProcessRole::Zygote),
        _ => get_role_threshold(ProcessRole::Unknown),
    };

    let mut result = Vec::new();
    for c in classifications {
        if thresholds.allowed_classes.contains(&c.as_str()) {
            continue;
        }
        result.push(c.clone());
    }

    if result.is_empty() {
        result.push("clean".to_string());
    }

    result
}
