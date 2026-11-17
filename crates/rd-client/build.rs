// Windows: embed an application manifest. Without one, Windows guesses that a program
// named like "...Setup.exe" is an installer and asks for administrator rights before it
// starts; the installer asks only for the step that needs them.
fn main() {
    println!("cargo:rerun-if-changed=rd-client.manifest");
    let windows = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows");
    let msvc = std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");
    if windows && msvc {
        let manifest = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("rd-client.manifest");
        println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
        // Our manifest has the trustInfo; the linker would add a second one.
        println!("cargo:rustc-link-arg-bins=/MANIFESTUAC:NO");
        println!("cargo:rustc-link-arg-bins=/MANIFESTINPUT:{}", manifest.display());
    }
}
