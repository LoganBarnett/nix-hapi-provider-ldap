#![allow(dead_code)]

use std::collections::HashSet;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
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
  /// Async because the readiness probe uses async ldap3 — we are
  /// already inside a tokio runtime when called from a `#[tokio::test]`,
  /// so the sync `LdapConn::new` wrapper would error with
  /// "cannot start a runtime within a runtime".
  pub async fn start() -> Result<Self, Box<dyn std::error::Error>> {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let url = format!("ldap://localhost:{}", port);
    let base_dn = "dc=test,dc=local".to_string();
    let bind_dn = format!("cn=admin,{}", base_dn);
    let bind_password = "admin".to_string();

    let data_dir = tempfile::TempDir::new()?;
    let slapd_conf =
      Self::create_slapd_config(&base_dn, &bind_dn, &bind_password, &data_dir)?;

    // macOS's default RLIMIT_NOFILE is "unlimited", which slapd 2.6.9
    // reads as dtblsize=-1 and then aborts trying to calloc a 2^64-1
    // byte fd table.  Wrap the spawn in `sh -c "ulimit -n 1024; exec slapd..."`
    // so the child gets a sane descriptor cap before slapd runs.
    let shell_cmd = format!(
      "ulimit -n 1024; exec slapd -h {url} -f {conf} -d 0",
      url = shell_escape(&url),
      conf = shell_escape(&slapd_conf),
    );
    let process = Command::new("sh")
      .arg("-c")
      .arg(&shell_cmd)
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

    server.wait_for_ready().await?;
    Ok(server)
  }

  fn find_schema_dir() -> Result<String, Box<dyn std::error::Error>> {
    if let Ok(output) = Command::new("which").arg("slapd").output() {
      if output.status.success() {
        let slapd_path =
          String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !slapd_path.is_empty() {
          let schema_dir = std::path::Path::new(&slapd_path)
            .parent()
            .and_then(|p| p.parent())
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

  async fn wait_for_ready(&mut self) -> Result<(), Box<dyn std::error::Error>> {
    let delay = Duration::from_millis(100);
    for attempt in 0_u32..50 {
      if let Some(ref mut proc) = self.process {
        if let Ok(Some(status)) = proc.try_wait() {
          return Err(
            format!("slapd exited before becoming ready ({})", status).into(),
          );
        }
      }
      match ldap3::LdapConnAsync::new(&self.url).await {
        Ok((conn, _)) => {
          tokio::spawn(async move {
            let _ = conn.drive().await;
          });
          return Ok(());
        }
        Err(_) if attempt < 49 => tokio::time::sleep(delay).await,
        Err(e) => {
          return Err(
            format!("slapd not ready after 50 attempts: {}", e).into(),
          )
        }
      }
    }
    Ok(())
  }

  /// Creates the base DN plus `ou=users` and `ou=groups` OUs, then
  /// returns a bound async LDAP handle so callers can perform any
  /// additional setup their test needs.  The connection driver is
  /// spawned on the current tokio runtime.
  pub async fn initialize(
    &self,
  ) -> Result<ldap3::Ldap, Box<dyn std::error::Error>> {
    let (conn, mut ldap) = ldap3::LdapConnAsync::new(&self.url).await?;
    tokio::spawn(async move {
      let _ = conn.drive().await;
    });
    ldap
      .simple_bind(&self.bind_dn, &self.bind_password)
      .await?
      .success()?;

    ldap
      .add(
        &self.base_dn,
        vec![
          ("objectClass", HashSet::from(["dcObject", "organization", "top"])),
          ("dc", HashSet::from(["test"])),
          ("o", HashSet::from(["Test Organization"])),
        ],
      )
      .await?
      .success()?;

    let users_dn = format!("ou=users,{}", self.base_dn);
    ldap
      .add(
        &users_dn,
        vec![
          ("objectClass", HashSet::from(["organizationalUnit", "top"])),
          ("ou", HashSet::from(["users"])),
        ],
      )
      .await?
      .success()?;

    let groups_dn = format!("ou=groups,{}", self.base_dn);
    ldap
      .add(
        &groups_dn,
        vec![
          ("objectClass", HashSet::from(["organizationalUnit", "top"])),
          ("ou", HashSet::from(["groups"])),
        ],
      )
      .await?
      .success()?;

    Ok(ldap)
  }
}

/// Single-quote-escapes for /bin/sh.  Used to splice paths and URLs
/// into the slapd launch command without worrying about spaces or
/// metacharacters in tempdir names.
fn shell_escape(s: &str) -> String {
  let escaped = s.replace('\'', "'\\''");
  format!("'{}'", escaped)
}

impl Drop for TestLdapServer {
  fn drop(&mut self) {
    if let Some(mut proc) = self.process.take() {
      let _ = proc.kill();
      let _ = proc.wait();
    }
  }
}
