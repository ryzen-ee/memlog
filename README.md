# memlog

Behavioral memory telemetry tool for Linux processes.

## Overview

memlog monitors memory regions of running processes through `/proc/<pid>/maps` and provides:

- Structured memory region analysis with classification
- Process role detection (browser, renderer, GPU process, etc.)
- Anomaly scoring (0.0-1.0)
- Entropy analysis for shellcode detection
- Baseline learning for deviation detection
- Multiple output formats

## Installation

```bash
cargo build --release
```

The binary will be at `target/release/memlog`.

## Usage

### Basic Monitoring

```bash
# Monitor by PID
./memlog --pid 1234

# Monitor by process name
./memlog --sourceproc chrome
```

### Options

| Flag | Description |
|------|-------------|
| `--pid <PID>` | Process ID to monitor |
| `--sourceproc <NAME>` | Search and monitor by process name |
| `--interval <SECS>` | Sampling interval (default: 1) |
| `--duration <SECS>` | Auto-exit after specified seconds |
| `--output <FILE>` | Output file for json/csv formats |
| `--format <MODE>` | Output format: minimal, verbose, json, csv |
| `--entropy` | Enable entropy analysis for shellcode detection |
| `--learn-baseline` | Enable baseline learning mode |
| `--baseline <PATH>` | Use named baseline for scoring |
| `--verbose`, `-v` | Show full details |
| `--help`, `-h` | Show help message |

### Output Formats

#### Minimal (default)

```
[2026-05-09 15:01:00] PID 1234 (renderer) | total: 45 | suspicious: 2 | score: 0.35
```

#### Verbose

Full process info, classification stats, and region listing.

#### JSON

Structured output for programmatic analysis:

```json
{
  "timestamp": "2026-05-09 15:01:00",
  "process": { "pid": 1234, "role": "renderer", ... },
  "stats": { "total_regions": 45, "suspicious_regions": 2, ... },
  "memory": { "rss_kb": 102400, "vms_kb": 204800, ... },
  "regions": [...],
  "flags": ["jit_region", "suspicious_rwx"],
  "score": 0.35
}
```

#### CSV

For spreadsheet analysis.

## Region Classification

memlog classifies memory regions into the following categories:

| Classification | Description |
|----------------|-------------|
| `jit_region` | JIT compiler code regions |
| `wasm_region` | WebAssembly regions |
| `gpu_region` | GPU/metal/shared memory regions |
| `shellcode_like` | RWX anonymous regions (potential injection) |
| `deleted_exec_mapping` | Executable mapped files that were deleted |
| `stack_exec` | Executable stack regions |
| `heap_exec` | Executable heap regions |
| `module_backed_exec` | Executable code from loaded modules |
| `suspicious_rwx` | Read-Write-Execute without module backing |
| `suspicious_wx` | Write-Execute regions |
| `writable_exec_code` | Writable executable code |

## Process Roles

memlog detects common process types to adjust scoring thresholds:

- `browser` - Browser main process
- `renderer` - Tab/renderer processes
- `gpu-process` - GPU acceleration process
- `utility` - Utility processes (sandbox, network, etc.)
- `extension` - Browser extension processes
- `zygote` - Process spawner
- `unknown` - Unclassified

## Scoring

The anomaly score ranges from 0.0 to 1.0:

| Score | Meaning |
|-------|---------|
| 0.0 - 0.3 | Normal/expected behavior |
| 0.3 - 0.6 | Elevated activity |
| 0.6 - 0.8 | High concern |
| 0.8 - 1.0 | Critical/anomalous |

### Scoring Factors

- RWX regions count
- WX regions count
- Shellcode-like regions
- Deleted executable mappings
- Stack/heap execution
- High entropy regions

## Baseline Learning

> [!NOTE]
> Use `--learn-baseline` during normal operation to learn expected behavior patterns.

```bash
# Learn baseline for Chrome during normal browsing
./memlog --sourceproc chrome --learn-baseline --duration 60
```

Baselines are stored in `~/.memlog/baselines/` and automatically applied to future scans.

## Requirements

- Linux (uses `/proc/<pid>/maps` and `/proc/<pid>/mem`)
- Rust toolchain (for building)

## Security Notes

> [!WARNING]
> memlog requires read access to `/proc/<pid>/maps` and `/proc/<pid>/mem` for the target process. This typically requires the same user or root privileges.

> [!CAUTION]
> Reading process memory may expose sensitive data. Handle output files with appropriate permissions.

## License

MIT