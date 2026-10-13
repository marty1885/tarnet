use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let preload_src = PathBuf::from("../tarnet-preload/src/preload.c");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let macos = env::var("CARGO_CFG_TARGET_OS").unwrap() == "macos";
    let name = if macos {
        "libtarnet_preload.dylib"
    } else {
        "libtarnet_preload.so"
    };
    let output = out_dir.join(name);

    println!("cargo:rerun-if-changed={}", preload_src.display());

    println!("cargo:rerun-if-env-changed=CC");
    let mut compiler = Command::new(env::var("CC").unwrap_or_else(|_| "cc".into()));
    compiler.args(["-Wall", "-Wextra", "-fPIC", "-O2"]);
    if macos {
        compiler.arg("-dynamiclib");
    } else {
        compiler.args(["-shared", "-D_GNU_SOURCE"]);
    }
    compiler
        .arg("-o")
        .arg(&output)
        .arg(&preload_src)
        .arg("-lpthread");
    if !macos {
        compiler.arg("-ldl");
    }
    let status = compiler.status()
        .expect("failed to run C compiler");

    assert!(status.success(), "failed to compile {name}");

    // Make the path available to the binary at compile time.
    println!("cargo:rustc-env=TARNET_PRELOAD_PATH={}", output.display());
    println!("cargo:rustc-env=TARNET_PRELOAD_NAME={name}");
}
