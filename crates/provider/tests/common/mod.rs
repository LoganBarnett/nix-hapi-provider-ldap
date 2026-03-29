#![allow(dead_code)]

use std::collections::HashSet;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::thread;
use std::time::Duration;

/// Monotonically increasing port counter so parallel tests don't collide.
static PORT_COUNTER: AtomicU16 = AtomicU16::new(10389);

/// A self-contained OpenLDAP server process used exclusively in tests.
pub struct TestLdapServer {
  process: Option<Child>,
  pub url: String,
  pub base_dn: String,
  pub bind_dn: String,
  pub bind_password: String,
  // Must stay alive for the lifetime of the server; dropped last.
  _data_dir: tempfile::TempDir,
}

impl TestLdapServer {
  /// Spawns a slapd instance and waits until it accepts connections.
  pub fn start() -> Result<Self, Box<dyn std::error::Error>> {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let url = format!("ldap://localhost:{}", port);
    let base_dn = "dc=test,dc=local".to_string();
    let bind_dn = format!("cn=admin,{}", base_dn);
    let bind_password = "admin".to_string();

    let data_dir = tempfile::TempDir::new()?;
    let slapd_conf =
      Self::create_slapd_config(&base_dn, &bind_dn, &bind_password, &data_dir)?;

    let process = Command::new("slapd")
      .arg("-h")
      .arg(&url)
      .arg("-f")
      .arg(&slapd_conf)
      .arg("-d")
      .arg("0") // daemon mode, no debug output
      .stdout(Stdio::null())
      .stderr(Stdio::null())
      .spawn()?;

    let mut server = Self {
      process: Some(process),
      url,
      base_dn,
      bind_dn,
      bind_password,
      _data_dir: data_dir,
    };

    server.wait_for_ready()?;
    Ok(server)
  }

  /// Locates the OpenLDAP schema directory by inspecting the slapd binary
  /// path.  Works correctly in a Nix store where slapd lives under
  /// `<store>/libexec/` and schemas live under `<store>/etc/schema/`.
  fn find_schema_dir() -> Result<String, Box<dyn std::error::Error>> {
    if let Ok(output) = Command::new("which").arg("slapd").output() {
      if output.status.success() {
        let slapd_path =
          String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !slapd_path.is_empty() {
          let schema_dir = std::path::Path::new(&slapd_path)
            .parent() // strip 'slapd'
            .and_then(|p| p.parent()) // strip 'libexec'
            .ok_or("Cannot derive OpenLDAP root from slapd path")?
            .join("etc")
            .join("schema");
          if schema_dir.exists() {
            return Ok(schema_dir.to_string_lossy().to_string());
          }
        }
      }
    }

    for path in &["/etc/openldap/schema", "/etc/ldap/schema"] {
      if std::path::Path::new(path).exists() {
        return Ok(path.to_string());
      }
    }

    Err(
      "Cannot find OpenLDAP schema directory; ensure slapd is on PATH.".into(),
    )
  }

  fn create_slapd_config(
    base_dn: &str,
    bind_dn: &str,
    bind_password: &str,
    data_dir: &tempfile::TempDir,
  ) -> Result<String, Box<dyn std::error::Error>> {
    let conf_path = data_dir.path().join("slapd.conf");
    let db_path = data_dir.path().join("db");
    std::fs::create_dir_all(&db_path)?;

    let schema_dir = Self::find_schema_dir()?;
    let conf = format!(
      "\
include {s}/core.schema
include {s}/cosine.schema
include {s}/inetorgperson.schema

pidfile {d}/slapd.pid
argsfile {d}/slapd.args

database mdb
suffix \"{base_dn}\"
rootdn \"{bind_dn}\"
rootpw {bind_password}
directory {db}
maxsize 1073741824
",
      s = schema_dir,
      d = data_dir.path().display(),
      base_dn = base_dn,
      bind_dn = bind_dn,
      bind_password = bind_password,
      db = db_path.display(),
    );

    std::fs::write(&conf_path, conf)?;
    Ok(conf_path.to_string_lossy().to_string())
  }

  fn wait_for_ready(&mut self) -> Result<(), Box<dyn std::error::Error>> {
    let delay = Duration::from_millis(100);
    for attempt in 0_u32..50 {
      if let Some(ref mut proc) = self.process {
        if let Ok(Some(status)) = proc.try_wait() {
          return Err(
            format!("slapd exited before becoming ready ({})", status).into(),
          );
        }
      }
      match ldap3::LdapConn::new(&self.url) {
        Ok(_) => return Ok(()),
        Err(_) if attempt < 49 => thread::sleep(delay),
        Err(e) => {
          return Err(
            format!("slapd not ready after 50 attempts: {}", e).into(),
          )
        }
      }
    }
    Ok(())
  }

  /// Creates the base DN plus `ou=users` and `ou=groups` OUs, then returns
  /// the bound connection so callers can perform additional setup.
  pub fn initialize(
    &self,
  ) -> Result<ldap3::LdapConn, Box<dyn std::error::Error>> {
    let mut ldap = ldap3::LdapConn::new(&self.url)?;
    ldap
      .simple_bind(&self.bind_dn, &self.bind_password)?
      .success()?;

    ldap
      .add(
        &self.base_dn,
        vec![
          ("objectClass", HashSet::from(["dcObject", "organization", "top"])),
          ("dc", HashSet::from(["test"])),
          ("o", HashSet::from(["Test Organization"])),
        ],
      )?
      .success()?;

    let users_dn = format!("ou=users,{}", self.base_dn);
    ldap
      .add(
        &users_dn,
        vec![
          ("objectClass", HashSet::from(["organizationalUnit", "top"])),
          ("ou", HashSet::from(["users"])),
        ],
      )?
      .success()?;

    let groups_dn = format!("ou=groups,{}", self.base_dn);
    ldap
      .add(
        &groups_dn,
        vec![
          ("objectClass", HashSet::from(["organizationalUnit", "top"])),
          ("ou", HashSet::from(["groups"])),
        ],
      )?
      .success()?;

    Ok(ldap)
  }
}

impl Drop for TestLdapServer {
  fn drop(&mut self) {
    if let Some(mut proc) = self.process.take() {
      let _ = proc.kill();
      let _ = proc.wait();
    }
  }
}
