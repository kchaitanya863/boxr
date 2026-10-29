fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        match pkg_config::Config::new().probe("libsystemd") {
            Ok(_) => {
                println!("cargo:rustc-cfg=boxr_has_systemd");
            }
            Err(e) => {
                println!(
                    "cargo:warning=libsystemd not found ({e}); journald native send disabled, using /dev/log fallback"
                );
            }
        }
    }
}
