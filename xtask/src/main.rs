//! xtask — project automation.
//!
//! Run with: `cargo xtask <command>`
//!
//! Commands:
//!   bench      — run criterion benchmarks and open HTML report
//!   flamegraph — profile `cargo bench` and open flamegraph SVG
//!   ffi        — build shared lib + generate cbindgen header
//!   ci         — run everything CI runs (fmt, clippy, test, bench smoke)
//!   loc        — count lines of code by module

use std::{
    env,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");

    let root = project_root();

    match cmd {
        "bench" => bench(&root),
        "flamegraph" => flamegraph(&root),
        "ffi" => ffi(&root),
        "ci" => ci(&root),
        "loc" => loc(&root),
        _ => help(),
    }
}

fn bench(root: &Path) {
    println!("── Benchmarks ──────────────────────────────────────────────");
    run(
        root,
        "cargo",
        &[
            "bench",
            "--features",
            "memory",
            "--",
            "--output-format",
            "bencher",
        ],
    );
    let report = root.join("target/criterion/report/index.html");
    if report.exists() {
        open_browser(&report.to_string_lossy());
    }
}

fn flamegraph(root: &Path) {
    println!("── Flamegraph ──────────────────────────────────────────────");
    // Requires: cargo install flamegraph
    // On Linux: perf, on macOS: dtrace
    run(
        root,
        "cargo",
        &[
            "flamegraph",
            "--features",
            "memory",
            "--bench",
            "throughput",
            "--",
            "--bench", // criterion benchmark mode
            "--sample-size",
            "500",
        ],
    );
    let svg = root.join("flamegraph.svg");
    if svg.exists() {
        println!("Flamegraph written to: {}", svg.display());
        open_browser(&svg.to_string_lossy());
    }
}

fn ffi(root: &Path) {
    println!("── FFI shared library ──────────────────────────────────────");
    run(root, "cargo", &["build", "--release", "--features", "full"]);

    // Generate C header via cbindgen if available
    if which("cbindgen") {
        println!("── Generating C header via cbindgen ────────────────────");
        run(
            root,
            "cbindgen",
            &[
                "--config",
                "cbindgen.toml",
                "--crate",
                "ratekeeper",
                "--output",
                "include/ratekeeper_generated.h",
                "--language",
                "C",
            ],
        );
    } else {
        println!("cbindgen not found — skipping header generation");
        println!("Install: cargo install cbindgen");
    }

    // Print library location
    for name in &["libratekeeper.so", "libratekeeper.dylib", "ratekeeper.dll"] {
        let p = root.join("target/release").join(name);
        if p.exists() {
            println!("Library: {}", p.display());
        }
    }
}

fn ci(root: &Path) {
    println!("── fmt ─────────────────────────────────────────────────────");
    run(root, "cargo", &["fmt", "--check"]);

    println!("── clippy (memory) ─────────────────────────────────────────");
    run(
        root,
        "cargo",
        &["clippy", "--features", "memory", "--", "-D", "warnings"],
    );

    println!("── clippy (full) ───────────────────────────────────────────");
    run(
        root,
        "cargo",
        &["clippy", "--features", "full", "--", "-D", "warnings"],
    );

    println!("── tests (memory) ──────────────────────────────────────────");
    run(root, "cargo", &["test", "--features", "memory"]);

    println!("── bench smoke ─────────────────────────────────────────────");
    run(
        root,
        "cargo",
        &["bench", "--features", "memory", "--", "--sample-size", "10"],
    );

    println!("── All CI checks passed ✓");
}

fn loc(root: &Path) {
    println!("── Lines of code ───────────────────────────────────────────");
    if which("tokei") {
        run(root, "tokei", &["src/", "tests/", "benches/"]);
    } else if which("cloc") {
        run(root, "cloc", &["src/", "tests/", "benches/"]);
    } else {
        // Fallback: wc -l
        let out = Command::new("find")
            .current_dir(root)
            .args(["src", "tests", "benches", "-name", "*.rs"])
            .output()
            .unwrap();
        let files: Vec<&str> = std::str::from_utf8(&out.stdout).unwrap().lines().collect();
        let mut total = 0usize;
        for f in &files {
            if let Ok(content) = std::fs::read_to_string(root.join(f)) {
                total += content.lines().count();
            }
        }
        println!("{total} lines across {} Rust files", files.len());
    }
}

fn help() {
    eprintln!(
        "cargo xtask <command>

Commands:
  bench      Run criterion benchmarks and open HTML report
  flamegraph Profile with flamegraph (requires `cargo flamegraph`)
  ffi        Build shared library and generate C header
  ci         Run fmt + clippy + tests + bench smoke (same as CI)
  loc        Count lines of code (uses tokei, cloc, or wc -l)
"
    );
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn run(cwd: &Path, program: &str, args: &[&str]) {
    let status: ExitStatus = Command::new(program)
        .current_dir(cwd)
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("failed to run `{program}`: {e}"));
    if !status.success() {
        eprintln!("`{program} {}` failed with {status}", args.join(" "));
        std::process::exit(1);
    }
}

fn project_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent() // xtask/
        .expect("xtask must be in a workspace")
        .to_owned()
}

fn which(program: &str) -> bool {
    Command::new("which")
        .arg(program)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn open_browser(path: &str) {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(target_os = "windows") {
        "start"
    } else {
        "xdg-open"
    };
    let _ = Command::new(opener).arg(path).spawn();
}
