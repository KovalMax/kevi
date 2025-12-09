use std::env;
use std::process::Command;

fn main() {
    // Git SHA (short)
    let git_sha = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=KEVI_GIT_SHA={}", git_sha);

    // Build time (UTC, RFC3339)
    let build_time = match chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true) {
        s => s,
    };
    println!("cargo:rustc-env=KEVI_BUILD_TIME={}", build_time);

    // Target triple
    let target = env::var("TARGET").unwrap_or_else(|_| "unknown-target".to_string());
    println!("cargo:rustc-env=KEVI_TARGET={}", target);

    // Feature flags summary
    let mut feats: Vec<&'static str> = Vec::new();
    if env::var("CARGO_FEATURE_MEMLOCK").is_ok() {
        feats.push("memlock");
    }
    let features = if feats.is_empty() {
        "default".to_string()
    } else {
        feats.join(",")
    };
    println!("cargo:rustc-env=KEVI_FEATURES={}", features);
}
