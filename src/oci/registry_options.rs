use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Default, Clone)]
pub struct RegistryOptions {
    pub cert_dir: Option<PathBuf>,
    pub inline_creds: Option<(String, String)>,
}

static REGISTRY_OPTIONS: Mutex<RegistryOptions> = Mutex::new(RegistryOptions {
    cert_dir: None,
    inline_creds: None,
});

pub fn registry_options_snapshot() -> RegistryOptions {
    REGISTRY_OPTIONS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

pub fn set_registry_options(opts: RegistryOptions) {
    *REGISTRY_OPTIONS.lock().unwrap_or_else(|e| e.into_inner()) = opts;
}

pub fn clear_registry_options() {
    set_registry_options(RegistryOptions::default());
}

pub struct RegistryOptionsGuard {
    prev: RegistryOptions,
}

impl RegistryOptionsGuard {
    pub fn install(opts: RegistryOptions) -> Self {
        let prev = registry_options_snapshot();
        set_registry_options(opts);
        Self { prev }
    }
}

impl Drop for RegistryOptionsGuard {
    fn drop(&mut self) {
        set_registry_options(self.prev.clone());
    }
}

pub fn registry_options_from_cli(cert_dir: Option<&str>, creds: Option<&str>) -> RegistryOptions {
    let inline_creds = creds.and_then(parse_creds);
    RegistryOptions {
        cert_dir: cert_dir.map(PathBuf::from),
        inline_creds,
    }
}

fn parse_creds(raw: &str) -> Option<(String, String)> {
    let (user, pass) = raw.split_once(':')?;
    if user.is_empty() {
        return None;
    }
    Some((user.to_string(), pass.to_string()))
}

pub fn load_extra_root_certs(cert_dir: &Path) -> anyhow::Result<Vec<reqwest::Certificate>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(cert_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let load = name.ends_with(".crt")
            || name.ends_with(".cert")
            || name.ends_with(".pem")
            || name == "ca.crt";
        if !load {
            continue;
        }
        let pem = std::fs::read(&path)?;
        out.push(reqwest::Certificate::from_pem(&pem)?);
    }
    Ok(out)
}
