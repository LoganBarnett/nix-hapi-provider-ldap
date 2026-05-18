mod common;
use common::TestLdapServer;

use nix_hapi_lib::diff::compute_provider_changes;
use nix_hapi_lib::field_value::ResolvedFieldValue;
use nix_hapi_lib::meta::NixHapiMeta;
use nix_hapi_lib::plan::{
  DiffNode, FieldTarget, ProviderPlanWave, RunbookStep, Status,
};
use nix_hapi_lib::provider::{Provider, ResolvedConfig};
use nix_hapi_lib::subprocess::SubprocessProvider;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::Path;

// ── Helpers ──────────────────────────────────────────────────────────────────

const INSTANCE: &str = "test";
const INSTANCE_PREFIX: &str = ".[\"test\"]";

fn make_provider() -> SubprocessProvider {
  let binary = env!("CARGO_BIN_EXE_nix-hapi-provider-ldap");
  SubprocessProvider::spawn("ldap".to_string(), Path::new(binary))
    .expect("failed to spawn nix-hapi-provider-ldap")
}

fn make_config(server: &TestLdapServer) -> ResolvedConfig {
  let mut cfg: ResolvedConfig = HashMap::new();
  cfg.insert(
    "url".to_string(),
    ResolvedFieldValue::Managed(Value::String(server.url.clone())),
  );
  cfg.insert(
    "baseDn".to_string(),
    ResolvedFieldValue::Managed(Value::String(server.base_dn.clone())),
  );
  cfg.insert(
    "bindDn".to_string(),
    ResolvedFieldValue::Managed(Value::String(server.bind_dn.clone())),
  );
  cfg.insert(
    "bindPassword".to_string(),
    ResolvedFieldValue::Managed(Value::String(server.bind_password.clone())),
  );
  cfg
}

fn managed(value: &str) -> Value {
  json!({"__nixhapi": "managed", "value": value})
}

fn initial(value: &str) -> Value {
  json!({"__nixhapi": "initial", "value": value})
}

fn user_key(uid: &str, base_dn: &str) -> Value {
  json!({"providerKey": [format!("uid={},ou=users,{}", uid, base_dn)]})
}

fn group_key(cn: &str, base_dn: &str) -> Value {
  json!({"providerKey": [format!("cn={},ou=groups,{}", cn, base_dn)]})
}

/// Minimal alice user node carrying the providerKey the engine matches
/// against.  `password_field` lets callers pick managed vs. initial.
fn alice(cn: &str, password_field: Value, base_dn: &str) -> Value {
  json!({
    "__nixhapi": user_key("alice", base_dn),
    "cn": managed(cn),
    "sn": managed("Smith"),
    "mail": managed("alice@example.org"),
    "userPassword": password_field,
  })
}

fn bob(base_dn: &str) -> Value {
  json!({
    "__nixhapi": user_key("bob", base_dn),
    "cn": managed("Bob Jones"),
    "sn": managed("Jones"),
    "mail": managed("bob@example.org"),
    "userPassword": managed("secret"),
  })
}

fn group(
  cn: &str,
  description: &str,
  member_uids: &[&str],
  base_dn: &str,
) -> Value {
  let members: Vec<String> = {
    let mut v: Vec<String> = member_uids
      .iter()
      .map(|uid| format!("uid={},ou=users,{}", uid, base_dn))
      .collect();
    v.sort();
    v
  };
  json!({
    "__nixhapi": group_key(cn, base_dn),
    "description": managed(description),
    "member": members,
  })
}

fn desired_only_users(users: Value) -> Value {
  json!({ "users": users, "groups": {} })
}

fn desired_with(users: Value, groups: Value) -> Value {
  json!({ "users": users, "groups": groups })
}

/// Runs the engine's diff to produce the wave's changes for the
/// instance under test.
fn compute_changes(
  desired: &Value,
  live: &Value,
  meta: &NixHapiMeta,
) -> Vec<DiffNode> {
  compute_provider_changes(desired, live, meta, INSTANCE_PREFIX)
    .expect("compute diff")
}

fn make_wave(
  changes: Vec<DiffNode>,
  runbook: Vec<RunbookStep>,
) -> ProviderPlanWave {
  ProviderPlanWave {
    instance_name: INSTANCE.to_string(),
    provider_type: "ldap".to_string(),
    wave_index: 0,
    changes,
    runbook,
  }
}

/// Drives the full plan-then-apply lifecycle once.  Used by tests that
/// only care about whether a change was successfully applied.
async fn plan_and_apply(
  provider: &SubprocessProvider,
  config: &ResolvedConfig,
  desired: &Value,
  meta: &NixHapiMeta,
) {
  let live = provider.list_live(config, &[]).await.expect("list_live");
  let changes = compute_changes(desired, &live, meta);
  let wave = make_wave(changes, Vec::new());
  let runbook = provider
    .build_runbook(&wave, desired, &live, meta, config)
    .await
    .expect("build_runbook");
  let wave_with_runbook = make_wave(wave.changes.clone(), runbook);
  provider
    .apply(&wave_with_runbook, config)
    .await
    .expect("apply");
}

fn statuses(changes: &[DiffNode]) -> Vec<(&Value, &Status)> {
  fn walk<'a>(node: &'a DiffNode, out: &mut Vec<(&'a Value, &'a Status)>) {
    if let Some(head) = node.provider_key.first() {
      out.push((head, &node.status));
    }
    for child in &node.children {
      walk(child, out);
    }
  }
  let mut out = Vec::new();
  for n in changes {
    walk(n, &mut out);
  }
  out
}

fn dn_has_status(
  changes: &[DiffNode],
  dn: &str,
  predicate: impl Fn(&Status) -> bool,
) -> bool {
  statuses(changes)
    .iter()
    .any(|(key, status)| key.as_str() == Some(dn) && predicate(status))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn canary_list_live_empty() {
  let server = TestLdapServer::start().await.expect("start slapd");
  server
    .initialize()
    .await
    .expect("initialize base structure");

  let provider = make_provider();
  let live = provider
    .list_live(&make_config(&server), &[])
    .await
    .expect("list_live");

  assert_eq!(live["users"], json!({}));
  assert_eq!(live["groups"], json!({}));
}

#[tokio::test]
async fn engine_diff_produces_add_for_new_user() {
  let server = TestLdapServer::start().await.expect("start slapd");
  server
    .initialize()
    .await
    .expect("initialize base structure");

  let provider = make_provider();
  let config = make_config(&server);
  let live = provider.list_live(&config, &[]).await.expect("list_live");

  let desired = desired_only_users(
    json!({ "alice": alice("Alice Smith", initial("secret"), &server.base_dn) }),
  );
  let changes = compute_changes(&desired, &live, &NixHapiMeta::default());

  let alice_dn = format!("uid=alice,ou=users,{}", server.base_dn);
  assert!(
    dn_has_status(&changes, &alice_dn, |s| matches!(s, Status::Add)),
    "expected Add for alice; got: {:?}",
    changes
  );
}

#[tokio::test]
async fn apply_creates_user() {
  let server = TestLdapServer::start().await.expect("start slapd");
  server
    .initialize()
    .await
    .expect("initialize base structure");

  let provider = make_provider();
  let config = make_config(&server);

  let desired = desired_only_users(
    json!({ "alice": alice("Alice Smith", initial("secret"), &server.base_dn) }),
  );
  plan_and_apply(&provider, &config, &desired, &NixHapiMeta::default()).await;

  let live_after = provider
    .list_live(&config, &[])
    .await
    .expect("list_live after");
  assert!(
    live_after["users"]["alice"].is_object(),
    "expected alice in live state after apply; got: {:?}",
    live_after
  );
  assert_eq!(
    live_after["users"]["alice"]["cn"],
    json!("Alice Smith"),
    "cn should match desired value (normalised to scalar)",
  );
}

#[tokio::test]
async fn apply_is_idempotent() {
  let server = TestLdapServer::start().await.expect("start slapd");
  server
    .initialize()
    .await
    .expect("initialize base structure");

  let provider = make_provider();
  let config = make_config(&server);

  let desired = desired_only_users(
    json!({ "alice": alice("Alice Smith", initial("secret"), &server.base_dn) }),
  );
  plan_and_apply(&provider, &config, &desired, &NixHapiMeta::default()).await;

  let live2 = provider.list_live(&config, &[]).await.expect("list_live 2");
  let changes2 = compute_changes(&desired, &live2, &NixHapiMeta::default());
  assert!(
    changes2.is_empty(),
    "expected no changes on second plan; got: {:?}",
    changes2,
  );
}

#[tokio::test]
async fn managed_field_is_enforced_on_change() {
  let server = TestLdapServer::start().await.expect("start slapd");
  server
    .initialize()
    .await
    .expect("initialize base structure");

  let provider = make_provider();
  let config = make_config(&server);

  let desired1 = desired_only_users(
    json!({ "alice": alice("Alice Smith", initial("secret"), &server.base_dn) }),
  );
  plan_and_apply(&provider, &config, &desired1, &NixHapiMeta::default()).await;

  // Drift: change the managed cn.
  let live2 = provider.list_live(&config, &[]).await.expect("list_live 2");
  let desired2 = desired_only_users(
    json!({ "alice": alice("Alice Updated", initial("secret"), &server.base_dn) }),
  );
  let changes = compute_changes(&desired2, &live2, &NixHapiMeta::default());

  let alice_dn = format!("uid=alice,ou=users,{}", server.base_dn);
  assert!(
    dn_has_status(&changes, &alice_dn, |s| matches!(s, Status::Modify)),
    "expected Modify for alice after cn change; got: {:?}",
    changes
  );
}

#[tokio::test]
async fn initial_field_not_updated_when_present() {
  let server = TestLdapServer::start().await.expect("start slapd");
  server
    .initialize()
    .await
    .expect("initialize base structure");

  let provider = make_provider();
  let config = make_config(&server);

  let desired1 = desired_only_users(
    json!({ "alice": alice("Alice Smith", initial("first"), &server.base_dn) }),
  );
  plan_and_apply(&provider, &config, &desired1, &NixHapiMeta::default()).await;

  // Declared Initial value differs but live already has it set — must produce
  // no change.
  let live2 = provider.list_live(&config, &[]).await.expect("list_live 2");
  let desired2 = desired_only_users(
    json!({ "alice": alice("Alice Smith", initial("second"), &server.base_dn) }),
  );
  let changes = compute_changes(&desired2, &live2, &NixHapiMeta::default());

  assert!(
    changes.is_empty(),
    "initial field must not be modified when already present; got: {:?}",
    changes,
  );
}

#[tokio::test]
async fn user_absent_from_desired_is_deleted() {
  let server = TestLdapServer::start().await.expect("start slapd");
  server
    .initialize()
    .await
    .expect("initialize base structure");

  let provider = make_provider();
  let config = make_config(&server);

  let with_alice = desired_only_users(
    json!({ "alice": alice("Alice Smith", managed("secret"), &server.base_dn) }),
  );
  plan_and_apply(&provider, &config, &with_alice, &NixHapiMeta::default())
    .await;

  let live2 = provider.list_live(&config, &[]).await.expect("list_live 2");
  let empty = desired_only_users(json!({}));
  let changes = compute_changes(&empty, &live2, &NixHapiMeta::default());

  let alice_dn = format!("uid=alice,ou=users,{}", server.base_dn);
  assert!(
    dn_has_status(&changes, &alice_dn, |s| matches!(s, Status::Delete)),
    "expected Delete for alice; got: {:?}",
    changes
  );
}

#[tokio::test]
async fn ignore_predicate_prevents_deletion() {
  let server = TestLdapServer::start().await.expect("start slapd");
  server
    .initialize()
    .await
    .expect("initialize base structure");

  let provider = make_provider();
  let config = make_config(&server);

  let with_alice = desired_only_users(
    json!({ "alice": alice("Alice Smith", managed("secret"), &server.base_dn) }),
  );
  plan_and_apply(&provider, &config, &with_alice, &NixHapiMeta::default())
    .await;

  // Match alice's live node by providerKey-head DN.
  let alice_dn = format!("uid=alice,ou=users,{}", server.base_dn);
  let predicate = format!(".__nixhapi.providerKey[0] == \"{}\"", alice_dn);
  let meta = NixHapiMeta {
    ignore: vec![nix_hapi_lib::jq_expr::JqExpr::Inline(predicate)],
    ..NixHapiMeta::default()
  };

  let live2 = provider.list_live(&config, &[]).await.expect("list_live 2");
  let empty = desired_only_users(json!({}));
  let changes = compute_changes(&empty, &live2, &meta);

  assert!(
    changes.is_empty(),
    "expected no changes; alice should be protected by ignore predicate; \
     got: {:?}",
    changes,
  );
}

#[tokio::test]
async fn runbook_scrubs_bind_password() {
  let server = TestLdapServer::start().await.expect("start slapd");
  server
    .initialize()
    .await
    .expect("initialize base structure");

  let provider = make_provider();
  let config = make_config(&server);
  let live = provider.list_live(&config, &[]).await.expect("list_live");
  let desired = desired_only_users(
    json!({ "alice": alice("Alice Smith", managed("secret"), &server.base_dn) }),
  );

  let changes = compute_changes(&desired, &live, &NixHapiMeta::default());
  let wave = make_wave(changes, Vec::new());
  let runbook = provider
    .build_runbook(&wave, &desired, &live, &NixHapiMeta::default(), &config)
    .await
    .expect("build_runbook");

  assert!(!runbook.is_empty(), "expected at least one runbook step");
  let raw_password_arg = format!("-w {}", server.bind_password);
  for step in &runbook {
    assert!(
      !step.command.contains(&raw_password_arg),
      "bind password must not appear as -w argument: {}",
      step.command,
    );
    assert!(
      step.command.contains("-w ***"),
      "runbook command must show -w *** in place of password: {}",
      step.command,
    );
  }
}

#[tokio::test]
async fn add_corrects_existing_entry_with_wrong_attributes() {
  let server = TestLdapServer::start().await.expect("start slapd");
  let mut ldap = server
    .initialize()
    .await
    .expect("initialize base structure");

  // Pre-create alice with wrong cn directly via LDAP.
  let alice_dn = format!("uid=alice,ou=users,{}", server.base_dn);
  ldap
    .add(
      &alice_dn,
      vec![
        (
          "objectClass",
          HashSet::from(["inetOrgPerson", "organizationalPerson", "person"]),
        ),
        ("uid", HashSet::from(["alice"])),
        ("cn", HashSet::from(["WRONG"])),
        ("sn", HashSet::from(["WRONG"])),
        ("mail", HashSet::from(["wrong@example.org"])),
        ("userPassword", HashSet::from(["oldpw"])),
      ],
    )
    .await
    .expect("pre-create alice")
    .success()
    .expect("pre-create success");

  let provider = make_provider();
  let config = make_config(&server);

  // Force an Add by diffing against an empty live tree — the apply must
  // still succeed because the underlying entry_add falls back to a
  // Modify on rc=68.
  let empty_live = json!({ "users": {}, "groups": {} });
  let desired = desired_only_users(
    json!({ "alice": alice("Alice Smith", managed("secret"), &server.base_dn) }),
  );

  let changes = compute_changes(&desired, &empty_live, &NixHapiMeta::default());
  assert!(
    dn_has_status(&changes, &alice_dn, |s| matches!(s, Status::Add)),
    "expected Add for pre-existing alice; got: {:?}",
    changes,
  );

  let wave = make_wave(changes, Vec::new());
  let runbook = provider
    .build_runbook(
      &wave,
      &desired,
      &empty_live,
      &NixHapiMeta::default(),
      &config,
    )
    .await
    .expect("build_runbook");
  let wave = make_wave(wave.changes.clone(), runbook);
  provider.apply(&wave, &config).await.expect("apply");

  let live_after = provider
    .list_live(&config, &[])
    .await
    .expect("list_live after");
  assert_eq!(
    live_after["users"]["alice"]["cn"],
    json!("Alice Smith"),
    "cn should be corrected after Add fallback to Modify",
  );
}

#[tokio::test]
async fn nested_ou_entries_excluded_from_list_live() {
  let server = TestLdapServer::start().await.expect("start slapd");
  let mut ldap = server
    .initialize()
    .await
    .expect("initialize base structure");

  // Create a sub-OU and a user inside it directly via LDAP.
  let sub_ou_dn = format!("ou=admins,ou=users,{}", server.base_dn);
  ldap
    .add(
      &sub_ou_dn,
      vec![
        ("objectClass", HashSet::from(["organizationalUnit", "top"])),
        ("ou", HashSet::from(["admins"])),
      ],
    )
    .await
    .expect("add sub-OU")
    .success()
    .expect("sub-OU success");

  let deep_dn = format!("uid=deep,ou=admins,ou=users,{}", server.base_dn);
  ldap
    .add(
      &deep_dn,
      vec![
        (
          "objectClass",
          HashSet::from(["inetOrgPerson", "organizationalPerson", "person"]),
        ),
        ("uid", HashSet::from(["deep"])),
        ("cn", HashSet::from(["Deep User"])),
        ("sn", HashSet::from(["User"])),
      ],
    )
    .await
    .expect("add deep user")
    .success()
    .expect("deep user success");

  let alice_dn = format!("uid=alice,ou=users,{}", server.base_dn);
  ldap
    .add(
      &alice_dn,
      vec![
        (
          "objectClass",
          HashSet::from(["inetOrgPerson", "organizationalPerson", "person"]),
        ),
        ("uid", HashSet::from(["alice"])),
        ("cn", HashSet::from(["Alice Smith"])),
        ("sn", HashSet::from(["Smith"])),
      ],
    )
    .await
    .expect("add alice")
    .success()
    .expect("alice success");

  let provider = make_provider();
  let live = provider
    .list_live(&make_config(&server), &[])
    .await
    .expect("list_live");

  assert!(
    live["users"]["alice"].is_object(),
    "alice should appear in list_live",
  );
  assert!(
    live["users"]["deep"].is_null(),
    "deep user in sub-OU must not appear in list_live",
  );
}

#[tokio::test]
async fn group_with_multiple_members_is_idempotent() {
  let server = TestLdapServer::start().await.expect("start slapd");
  server
    .initialize()
    .await
    .expect("initialize base structure");

  let provider = make_provider();
  let config = make_config(&server);

  let desired = desired_with(
    json!({
      "alice": alice("Alice Smith", managed("secret"), &server.base_dn),
      "bob": bob(&server.base_dn),
    }),
    json!({
      "staff": group("staff", "Staff group", &["alice", "bob"], &server.base_dn),
    }),
  );

  // First plan + apply.
  plan_and_apply(&provider, &config, &desired, &NixHapiMeta::default()).await;

  // Second plan should be empty — no spurious diffs from multi-valued attrs.
  let live2 = provider.list_live(&config, &[]).await.expect("list_live 2");
  let changes2 = compute_changes(&desired, &live2, &NixHapiMeta::default());
  assert!(
    changes2.is_empty(),
    "expected no changes on second plan for group with multiple members; \
     got: {:?}",
    changes2,
  );
}

#[tokio::test]
async fn field_target_value_is_used_on_modify() {
  let server = TestLdapServer::start().await.expect("start slapd");
  server
    .initialize()
    .await
    .expect("initialize base structure");

  let provider = make_provider();
  let config = make_config(&server);

  // Apply original.
  let desired1 = desired_only_users(
    json!({ "alice": alice("Alice Smith", managed("secret"), &server.base_dn) }),
  );
  plan_and_apply(&provider, &config, &desired1, &NixHapiMeta::default()).await;

  // Drift cn and confirm the engine emits FieldTarget::Value with the new
  // value (and no DerivedPlaceholder leakage on this code path).
  let live2 = provider.list_live(&config, &[]).await.expect("list_live 2");
  let desired2 = desired_only_users(
    json!({ "alice": alice("Alice Updated", managed("secret"), &server.base_dn) }),
  );
  let changes = compute_changes(&desired2, &live2, &NixHapiMeta::default());

  let cn_target = changes
    .iter()
    .flat_map(|n| n.field_changes.iter())
    .find(|f| f.field == "cn")
    .map(|f| &f.to)
    .expect("expected cn field change");
  match cn_target {
    FieldTarget::Value { value } => {
      assert_eq!(value, &json!("Alice Updated"));
    }
    other => panic!("expected FieldTarget::Value, got {:?}", other),
  }
}
