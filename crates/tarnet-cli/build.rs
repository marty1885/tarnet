use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let preload_src = PathBuf::from("../tarnet-preload/src/preload.c");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let output = out_dir.join("libtarnet_preload.so");

    println!("cargo:rerun-if-changed={}", preload_src.display());

    let status = Command::new(env::var("CC").unwrap_or_else(|_| "gcc".into()))
        .args([
            "-Wall",
            "-Wextra",
            "-fPIC",
            "-shared",
            "-O2",
            "-D_GNU_SOURCE",
            "-o",
        ])
        .arg(&output)
        .arg(&preload_src)
        .args(["-ldl", "-lpthread"])
        .status()
        .expect("failed to run C compiler");

    assert!(status.success(), "failed to compile libtarnet_preload.so");

    // Make the path available to the binary at compile time.
    println!("cargo:rustc-env=TARNET_PRELOAD_PATH={}", output.display());
}
