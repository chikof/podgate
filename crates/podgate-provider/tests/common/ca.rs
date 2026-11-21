//! A CA made by `ca init` into a scratch directory, and the small builders the internal-CA tests
//! share between `internal_ca.rs` and `internal_ca_logs.rs`.

use std::path::{Path, PathBuf};

use podgate_model::TlsMode;
use podgate_provider::Config;
use podgate_provider::ca::init::{InitOptions, Initialized, init};
use podgate_provider::ca::{Ca, Want, Wants};
use podgate_provider::source::SourceApp;
use podgate_provider::trust::HostPattern;

pub fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgp-ca-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// A CA made by `ca init` into a scratch directory, with the root key kept beside it.
pub struct Pki {
    pub work: PathBuf,
    pub dir: PathBuf,
    pub root_key: PathBuf,
    pub made: Initialized,
    pub suffixes: Vec<String>,
}

pub fn pki(name: &str, suffixes: &[&str]) -> Pki {
    let work = scratch(name);
    let dir = work.join("ca");
    let root_key = work.join("offline").join("root.key");
    std::fs::create_dir_all(root_key.parent().expect("parent")).expect("offline dir");
    let suffixes: Vec<String> = suffixes.iter().map(|s| (*s).to_owned()).collect();
    let made = init(&InitOptions::new(
        dir.clone(),
        root_key.clone(),
        suffixes.clone(),
    ))
    .expect("ca init");
    Pki {
        work,
        dir,
        root_key,
        made,
        suffixes,
    }
}

pub const TENANTS: &str = r#"
[[tenant]]
id = "acme"
hosts = ["acme.internal", "*.acme.internal"]

[[tenant]]
id = "globex"
hosts = ["globex.internal", "*.globex.internal"]
"#;

impl Pki {
    /// The provider configuration after the `admin_socket` line: quick debounce, the tenants,
    /// the `[ca]` section, one fake source `local`.
    pub fn toml_full(&self, ca_extra: &str) -> String {
        format!(
            "{}\n[[source]]\nkind = \"fake\"\nname = \"local\"\n",
            self.toml(ca_extra)
        )
    }

    pub fn toml(&self, ca_extra: &str) -> String {
        let suffixes: Vec<String> = self.suffixes.iter().map(|s| format!("{s:?}")).collect();
        format!(
            "debounce_ms = 20\nmax_delay_ms = 100\nresync_secs = 1\n{TENANTS}\n[ca]\nenabled = true\ndir = {:?}\nallowed_suffixes = [{}]\n{ca_extra}\n",
            self.dir.display().to_string(),
            suffixes.join(", ")
        )
    }

    pub fn config(&self, ca_extra: &str) -> Config {
        super::config(
            Path::new("/nonexistent/admin.sock"),
            &self.toml_full(ca_extra),
        )
    }

    pub fn ca(&self, ca_extra: &str) -> Ca {
        let config = self.config(ca_extra);
        let settings = config.ca.clone().expect("an enabled [ca] section");
        Ca::open(&settings, &config).expect("the CA opens")
    }

    pub fn root_file(&self) -> PathBuf {
        let path = self.work.join("root.pem");
        std::fs::write(&path, &self.made.root_cert).expect("root file");
        path
    }
}

pub fn internal(mut app: SourceApp) -> SourceApp {
    app.app.tls.mode = TlsMode::Internal;
    app
}

pub fn key_lines(key: &str) -> Vec<String> {
    key.lines()
        .filter(|line| !line.starts_with("-----"))
        .map(str::to_owned)
        .collect()
}

pub fn want(app: &str, tenant: &str, hosts: &[&str]) -> Want {
    let mut hosts: Vec<HostPattern> = hosts
        .iter()
        .map(|host| HostPattern::parse(host).expect("host"))
        .collect();
    hosts.sort();
    Want {
        app: app.into(),
        tenant: tenant.into(),
        hosts,
    }
}

pub fn wants(list: Vec<Want>) -> Wants {
    Wants { apps: list }
}
