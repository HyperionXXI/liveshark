use std::env;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");

    let commit_full = env::var("GITHUB_SHA").ok().filter(|v| !v.is_empty());
    let commit_full = commit_full.or_else(|| run_git(&["rev-parse", "HEAD"]));
    let commit_full = commit_full.unwrap_or_else(|| "unknown".to_string());

    let commit_short = if commit_full != "unknown" {
        shorten_commit(&commit_full)
    } else {
        run_git(&["rev-parse", "--short", "HEAD"]).unwrap_or_else(|| "unknown".to_string())
    };

    let build_date =
        run_git(&["log", "-1", "--format=%cI"]).unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=LIVESHARK_BUILD_COMMIT={}", commit_short);
    println!(
        "cargo:rustc-env=LIVESHARK_BUILD_COMMIT_FULL={}",
        commit_full
    );
    println!("cargo:rustc-env=LIVESHARK_BUILD_DATE={}", build_date);
}

fn run_git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() { None } else { Some(value) }
}

fn shorten_commit(full: &str) -> String {
    let len = full.len().min(7);
    full.chars().take(len).collect()
}
