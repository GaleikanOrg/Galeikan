fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os == "windows" && target_env == "msvc" {
        // Windows' default 1 MiB main-thread stack is too small for the
        // deliberately bounded 64-module import chain on debug builds.
        println!("cargo:rustc-link-arg-bin=galeikan=/STACK:8388608");
    }
}
