//! The wasm module's stack. wasm-ld's default is 1 MiB, which the scanner's recursive parser and rules outgrow on
//! code nested a few hundred levels deep (a trap, where the command line, with its 8 MiB stack, succeeds). This
//! gives the module the same 8 MiB. Only the wasm build gets the flag: it is a wasm-ld option.

fn main() {
    if std::env::var("CARGO_CFG_TARGET_ARCH").is_ok_and(|arch| arch == "wasm32") {
        println!("cargo::rustc-link-arg-cdylib=-zstack-size=8388608");
    }
    println!("cargo::rerun-if-changed=build.rs");
}
