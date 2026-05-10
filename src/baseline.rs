use crate::scoring::BaselineProfile;
use crate::telemetry::MemoryStats;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

pub struct BaselineManager {
    baselines: HashMap<String, BaselineProfile>,
    pending_stats: HashMap<String, Vec<MemoryStats>>,
    baseline_dir: PathBuf,
}

impl BaselineManager {
    pub fn new() -> Self {
        let home_dir = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let baseline_dir = PathBuf::from(format!("{}/.memlog/baselines", home_dir));

        if !baseline_dir.exists() {
            let _ = fs::create_dir_all(&baseline_dir);
        }

        Self {
            baselines: HashMap::new(),
            pending_stats: HashMap::new(),
            baseline_dir,
        }
    }

    pub fn load(&mut self) -> std::io::Result<()> {
        if !self.baseline_dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(&self.baseline_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(baseline) = serde_json::from_str::<BaselineProfile>(&content) {
                        self.baselines
                            .insert(baseline.process_name.clone(), baseline);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn save(&self, name: &str) -> std::io::Result<()> {
        if let Some(baseline) = self.baselines.get(name) {
            let path = self
                .baseline_dir
                .join(format!("{}.json", name.replace('/', "_")));
            let json = serde_json::to_string_pretty(baseline)?;
            let mut file = File::create(&path)?;
            file.write_all(json.as_bytes())?;
        }
        Ok(())
    }

    pub fn add_sample(&mut self, name: &str, stats: MemoryStats) {
        let entry = self
            .pending_stats
            .entry(name.to_string())
            .or_insert_with(Vec::new);
        entry.push(stats);

        if entry.len() >= 10 {
            self.learn_baseline(name);
        }
    }

    pub fn learn_baseline(&mut self, name: &str) {
        if let Some(stats) = self.pending_stats.remove(name) {
            let baseline = BaselineProfile::from_stats(name, &stats);
            self.baselines.insert(name.to_string(), baseline);
            let _ = self.save(name);
        }
    }

    #[allow(dead_code)]
    pub fn get_baseline(&self, name: &str) -> Option<&BaselineProfile> {
        self.baselines.get(name)
    }

    pub fn list_baselines(&self) -> Vec<String> {
        self.baselines.keys().cloned().collect()
    }

    #[allow(dead_code)]
    pub fn delete_baseline(&mut self, name: &str) -> bool {
        if self.baselines.remove(name).is_some() {
            let path = self
                .baseline_dir
                .join(format!("{}.json", name.replace('/', "_")));
            let _ = fs::remove_file(path);
            true
        } else {
            false
        }
    }
}

impl Default for BaselineManager {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
pub fn load_baseline_from_file(path: &PathBuf) -> Option<BaselineProfile> {
    fs::read_to_string(path)
        .ok()
        .and_then(|content| serde_json::from_str(&content).ok())
}

#[allow(dead_code)]
pub fn save_baseline_to_file(baseline: &BaselineProfile, path: &PathBuf) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(baseline)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

#[allow(dead_code)]
pub fn merge_baselines(baselines: &[BaselineProfile]) -> BaselineProfile {
    if baselines.is_empty() {
        return BaselineProfile {
            process_name: "merged".to_string(),
            expected_rwx: 0,
            std_rwx: 0.0,
            expected_anon_exec: 0,
            std_anon_exec: 0.0,
            expected_entropy_avg: 0.0,
            sample_count: 0,
            created_at: "unknown".to_string(),
        };
    }

    let names: Vec<_> = baselines.iter().map(|b| b.process_name.as_str()).collect();
    let combined_name = names.join("+");

    let total_rwx: usize = baselines.iter().map(|b| b.expected_rwx).sum();
    let avg_rwx = total_rwx / baselines.len();
    let avg_std_rwx = baselines.iter().map(|b| b.std_rwx).sum::<f32>() / baselines.len() as f32;

    let total_anon: usize = baselines.iter().map(|b| b.expected_anon_exec).sum();
    let avg_anon = total_anon / baselines.len();
    let avg_std_anon =
        baselines.iter().map(|b| b.std_anon_exec).sum::<f32>() / baselines.len() as f32;

    BaselineProfile {
        process_name: combined_name,
        expected_rwx: avg_rwx,
        std_rwx: avg_std_rwx,
        expected_anon_exec: avg_anon,
        std_anon_exec: avg_std_anon,
        expected_entropy_avg: 0.0,
        sample_count: baselines.iter().map(|b| b.sample_count).sum(),
        created_at: chrono_lite_now(),
    }
}

#[allow(dead_code)]
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

#[allow(dead_code)]
fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}
