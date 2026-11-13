mod common;
use common::TestLdapServer;

use nix_hapi_lib::diff::compute_provider_changes;
use nix_hapi_lib::field_value::ResolvedFieldValue;
use nix_hapi_lib::meta::NixHapiMeta;
use nix_hapi_lib::plan::{
  DiffNode, FieldTarget, ProviderPlanWave, RunbookStep, Status,
};
use nix_hapi_lib::provider::{Provider, ProviderError, ResolvedConfig};
use nix_hapi_lib::subprocess::SubprocessProvider;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::path::Path;

// -- Helpers ------------------------------------------------------------------

const INSTANCE: &str = "test";
const INSTANCE_PREFIX: &str = ".[\"test\"]";
const PERSON_CLASSES: &[&str] =
  &["inetOrgPerson", "organizationalPerson", "person"];

fn make_provider() -> SubprocessProvider {
  let binary = env!("CARGO_BIN_EXE_nix-hapi-provider-ldap");
  SubprocessProvider::spawn("ldap".to_string(), Path::new(binary))
    .expect("failed to spawn nix-hapi-provider-ldap")
}

/// An RFC 4516 search base URL, spelled the way the Nix module renders them.
fn search_base(dn: &str, scope: &str, filter: Option<&str>) -> String {
  format!("ldap:///{}??{}?{}", dn, scope, filter.unwrap_or(""))
}

/// Connection fields only; ownership is added by the two helpers below.
/// `baseDn` is deliberately absent: the provider must not need it.
fn connection(server: &TestLdapServer) -> ResolvedConfig {
  HashMap::from([
    ("url".to_string(), ResolvedFieldValue::Managed(json!(server.url))),
    ("bindDn".to_string(), ResolvedFieldValue::Managed(json!(server.bind_dn))),
    (
      "bindPassword".to_string(),
      ResolvedFieldValue::Managed(json!(server.bind_password)),
    ),
  ])
}

/// A config owning exactly `bases`.
fn config_with_bases(
  server: &TestLdapServer,
  bases: &[String],
) -> ResolvedConfig {
  let mut config = connection(server);
  config.insert(
    "searchBases".to_string(),
    ResolvedFieldValue::Managed(json!(bases)),
  );
  config
}

/// A config owning every naming context the server publishes except
/// `unmanaged`, which is what the Nix module emits.
fn config_discovering(
  server: &TestLdapServer,
  unmanaged: &[&str],
) -> ResolvedConfig {
  let mut config = connection(server);
  config.insert(
    "unmanagedNamingContexts".to_string(),
    ResolvedFieldValue::Managed(json!(unmanaged)),
  );
  config
}

/// The conventional layout: `ou=users` and `ou=groups`, one level each.
fn make_config(server: &TestLdapServer) -> ResolvedConfig {
  config_with_bases(
    server,
    &[
      search_base(&users_ou(server), "one", None),
      search_base(&groups_ou(server), "one", None),
    ],
  )
}

fn users_ou(server: &TestLdapServer) -> String {
  format!("ou=users,{}", server.base_dn)
}

fn groups_ou(server: &TestLdapServer) -> String {
  format!("ou=groups,{}", server.base_dn)
}

fn user_dn(uid: &str, server: &TestLdapServer) -> String {
  format!("uid={},{}", uid, users_ou(server))
}

fn group_dn(cn: &str, server: &TestLdapServer) -> String {
  format!("cn={},{}", cn, groups_ou(server))
}

fn managed(value: &str) -> Value {
  json!({"__nixhapi": "managed", "value": value})
}

fn initial(value: &str) -> Value {
  json!({"__nixhapi": "initial", "value": value})
}

fn entry_key(dn: &str) -> Value {
  json!({"providerKey": [dn]})
}

/// Multi-valued attribute values as live state spells them: a single value
/// is a bare string, several are a sorted array.
fn wire(values: &[&str]) -> Value {
  match values {
    [single] => json!(single),
    many => {
      let mut sorted = many.to_vec();
      sorted.sort();
      json!(sorted)
    }
  }
}

/// An entry node: providerKey, objectClass, and the given attributes.
fn entry(dn: &str, object_class: &[&str], attrs: Value) -> Value {
  let mut node = attrs.as_object().cloned().unwrap_or_default();
  node.insert("__nixhapi".to_string(), entry_key(dn));
  node.insert("objectClass".to_string(), wire(object_class));
  Value::Object(node)
}

/// Minimal alice user node.  `password_field` lets callers pick managed vs.
/// initial.
fn alice(cn: &str, password_field: Value, server: &TestLdapServer) -> Value {
  entry(
    &user_dn("alice", server),
    PERSON_CLASSES,
    json!({
      "cn": managed(cn),
      "sn": managed("Smith"),
      "mail": managed("alice@example.org"),
      "userPassword": password_field,
    }),
  )
}

fn bob(server: &TestLdapServer) -> Value {
  entry(
    &user_dn("bob", server),
    PERSON_CLASSES,
    json!({
      "cn": managed("Bob Jones"),
      "sn": managed("Jones"),
      "mail": managed("bob@example.org"),
      "userPassword": managed("secret"),
    }),
  )
}

fn group(
  cn: &str,
  description: &str,
  member_uids: &[&str],
  server: &TestLdapServer,
) -> Value {
  let member_dns: Vec<String> =
    member_uids.iter().map(|uid| user_dn(uid, server)).collect();
  let members: Vec<&str> = member_dns.iter().map(String::as_str).collect();
  entry(
    &group_dn(cn, server),
    &["groupOfNames"],
    json!({
      "description": managed(description),
      "member": wire(&members),
    }),
  )
}

/// Desired state keyed by each node's providerKey head, the way the Nix
/// module emits it.
fn desired(nodes: &[Value]) -> Value {
  json!({
    "entries": nodes
      .iter()
      .map(|node| {
        let dn = node["__nixhapi"]["providerKey"][0]
          .as_str()
          .expect("providerKey head")
          .to_string();
        (dn, node.clone())
      })
      .collect::<Map<String, Value>>(),
  })
}

/// Attributes for a raw organizationalUnit added straight through ldap3.
fn organizational_unit(name: &str) -> Vec<(&str, HashSet<&str>)> {
  vec![
    ("objectClass", HashSet::from(["organizationalUnit", "top"])),
    ("ou", HashSet::from([name])),
  ]
}

/// Attributes for a raw inetOrgPerson added straight through ldap3.
fn person<'a>(
  uid: &'a str,
  cn: &'a str,
  sn: &'a str,
) -> Vec<(&'a str, HashSet<&'a str>)> {
  vec![
    ("objectClass", PERSON_CLASSES.iter().copied().collect()),
    ("uid", HashSet::from([uid])),
    ("cn", HashSet::from([cn])),
    ("sn", HashSet::from([sn])),
  ]
}

async fn add_raw(
  ldap: &mut ldap3::Ldap,
  dn: &str,
  attrs: Vec<(&str, HashSet<&str>)>,
) {
  ldap
    .add(dn, attrs)
    .await
    .unwrap_or_else(|e| panic!("add {dn}: {e}"))
    .success()
    .unwrap_or_else(|e| panic!("add {dn}: {e}"));
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

/// Plans up to the runbook and hands back its result without applying, for
/// tests that expect the runbook to refuse.
async fn build_runbook_for(
  provider: &SubprocessProvider,
  config: &ResolvedConfig,
  desired: &Value,
) -> Result<Vec<RunbookStep>, ProviderError> {
  let live = provider.list_live(config, &[]).await.expect("list_live");
  let changes = compute_changes(desired, &live, &NixHapiMeta::default());
  let wave = make_wave(changes, Vec::new());
  provider
    .build_runbook(&wave, desired, &live, &NixHapiMeta::default(), config)
    .await
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

fn entry_dns(live: &Value) -> Vec<String> {
  live["entries"]
    .as_object()
    .map(|entries| entries.keys().cloned().collect())
    .unwrap_or_default()
}

// -- Tests ---------------------------------------------------------------------

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

  assert_eq!(live["entries"], json!({}));
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

  let desired = desired(&[alice("Alice Smith", initial("secret"), &server)]);
  let changes = compute_changes(&desired, &live, &NixHapiMeta::default());

  let alice_dn = user_dn("alice", &server);
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

  let desired = desired(&[alice("Alice Smith", initial("secret"), &server)]);
  plan_and_apply(&provider, &config, &desired, &NixHapiMeta::default()).await;

  let alice_dn = user_dn("alice", &server);
  let live_after = provider
    .list_live(&config, &[])
    .await
    .expect("list_live after");
  assert!(
    live_after["entries"][&alice_dn].is_object(),
    "expected alice in live state after apply; got: {:?}",
    live_after
  );
  assert_eq!(
    live_after["entries"][&alice_dn]["cn"],
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

  let desired = desired(&[alice("Alice Smith", initial("secret"), &server)]);
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

  let desired1 = desired(&[alice("Alice Smith", initial("secret"), &server)]);
  plan_and_apply(&provider, &config, &desired1, &NixHapiMeta::default()).await;

  // Drift: change the managed cn.
  let live2 = provider.list_live(&config, &[]).await.expect("list_live 2");
  let desired2 = desired(&[alice("Alice Updated", initial("secret"), &server)]);
  let changes = compute_changes(&desired2, &live2, &NixHapiMeta::default());

  let alice_dn = user_dn("alice", &server);
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

  let desired1 = desired(&[alice("Alice Smith", initial("first"), &server)]);
  plan_and_apply(&provider, &config, &desired1, &NixHapiMeta::default()).await;

  // Declared Initial value differs but live already has it set; must produce
  // no change.
  let live2 = provider.list_live(&config, &[]).await.expect("list_live 2");
  let desired2 = desired(&[alice("Alice Smith", initial("second"), &server)]);
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

  let with_alice = desired(&[alice("Alice Smith", managed("secret"), &server)]);
  plan_and_apply(&provider, &config, &with_alice, &NixHapiMeta::default())
    .await;

  let live2 = provider.list_live(&config, &[]).await.expect("list_live 2");
  let empty = desired(&[]);
  let changes = compute_changes(&empty, &live2, &NixHapiMeta::default());

  let alice_dn = user_dn("alice", &server);
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

  let with_alice = desired(&[alice("Alice Smith", managed("secret"), &server)]);
  plan_and_apply(&provider, &config, &with_alice, &NixHapiMeta::default())
    .await;

  // Match alice's live node by providerKey-head DN.
  let alice_dn = user_dn("alice", &server);
  let predicate = format!(".__nixhapi.providerKey[0] == \"{}\"", alice_dn);
  let meta = NixHapiMeta {
    ignore: vec![nix_hapi_lib::jq_expr::JqExpr::Inline(predicate)],
    ..NixHapiMeta::default()
  };

  let live2 = provider.list_live(&config, &[]).await.expect("list_live 2");
  let empty = desired(&[]);
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
  let desired = desired(&[alice("Alice Smith", managed("secret"), &server)]);

  let runbook = build_runbook_for(&provider, &config, &desired)
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

  // Pre-create alice with wrong attributes directly via LDAP.  The object
  // classes match the desired set, so the rc=68 fallback's Replace of
  // objectClass is a no-op the server accepts.
  let alice_dn = user_dn("alice", &server);
  add_raw(
    &mut ldap,
    &alice_dn,
    vec![
      ("objectClass", PERSON_CLASSES.iter().copied().collect()),
      ("uid", HashSet::from(["alice"])),
      ("cn", HashSet::from(["WRONG"])),
      ("sn", HashSet::from(["WRONG"])),
      ("mail", HashSet::from(["wrong@example.org"])),
      ("userPassword", HashSet::from(["oldpw"])),
    ],
  )
  .await;

  let provider = make_provider();
  let config = make_config(&server);

  // Force an Add by diffing against an empty live tree; the apply must
  // still succeed because the underlying entry_add falls back to a
  // Modify on rc=68.
  let empty_live = json!({ "entries": {} });
  let desired = desired(&[alice("Alice Smith", managed("secret"), &server)]);

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
    live_after["entries"][&alice_dn]["cn"],
    json!("Alice Smith"),
    "cn should be corrected after Add fallback to Modify",
  );
}

/// A `one` base owns exactly the direct children of its base, whatever they
/// are.  A sub-OU is a direct child and therefore owned (the old uid-keyed
/// model hid it); an entry inside that sub-OU is not.
#[tokio::test]
async fn one_level_scope_owns_direct_children_only() {
  let server = TestLdapServer::start().await.expect("start slapd");
  let mut ldap = server
    .initialize()
    .await
    .expect("initialize base structure");

  let admins_dn = format!("ou=admins,{}", users_ou(&server));
  let deep_dn = format!("uid=deep,{}", admins_dn);
  let alice_dn = user_dn("alice", &server);
  add_raw(&mut ldap, &admins_dn, organizational_unit("admins")).await;
  add_raw(&mut ldap, &deep_dn, person("deep", "Deep User", "User")).await;
  add_raw(&mut ldap, &alice_dn, person("alice", "Alice Smith", "Smith")).await;

  let provider = make_provider();
  let live = provider
    .list_live(&make_config(&server), &[])
    .await
    .expect("list_live");

  assert!(
    live["entries"][&alice_dn].is_object(),
    "alice should appear in list_live; got {:?}",
    entry_dns(&live),
  );
  assert!(
    live["entries"][&admins_dn].is_object(),
    "the sub-OU is a direct child and is owned; got {:?}",
    entry_dns(&live),
  );
  assert!(
    live["entries"][&deep_dn].is_null(),
    "an entry inside the sub-OU is not a direct child; got {:?}",
    entry_dns(&live),
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

  let desired = desired(&[
    alice("Alice Smith", managed("secret"), &server),
    bob(&server),
    group("staff", "Staff group", &["alice", "bob"], &server),
  ]);

  // First plan + apply.
  plan_and_apply(&provider, &config, &desired, &NixHapiMeta::default()).await;

  // Second plan should be empty: no spurious diffs from multi-valued attrs.
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
  let desired1 = desired(&[alice("Alice Smith", managed("secret"), &server)]);
  plan_and_apply(&provider, &config, &desired1, &NixHapiMeta::default()).await;

  // Drift cn and confirm the engine emits FieldTarget::Value with the new
  // value (and no DerivedPlaceholder leakage on this code path).
  let live2 = provider.list_live(&config, &[]).await.expect("list_live 2");
  let desired2 = desired(&[alice("Alice Updated", managed("secret"), &server)]);
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

/// Renaming a user via providerKey history (head + prior DN) must produce
/// a Status::Rename and result in a modrdn on the wire, *not* a delete +
/// re-add.  The probe: declare the renamed user's userPassword as Initial
/// with a different value than what was originally written.  modrdn
/// preserves the entry's attributes, so the live password stays at the
/// original value; a delete-then-add would write the new value.  The test
/// asserts the original value survives.
#[tokio::test]
async fn rename_via_provider_key_history_uses_modrdn() {
  let server = TestLdapServer::start().await.expect("start slapd");
  server
    .initialize()
    .await
    .expect("initialize base structure");

  let provider = make_provider();
  let config = make_config(&server);

  // Step 1: create alice with userPassword = initial("first").
  let desired1 = desired(&[alice("Alice Smith", initial("first"), &server)]);
  plan_and_apply(&provider, &config, &desired1, &NixHapiMeta::default()).await;

  // Step 2: declare the renamed-to entry, `alicia`, whose providerKey
  // lists the new DN first and the prior DN second.  Pair it with an
  // Initial password of a *different* value; modrdn preserves the
  // entry body so the live password should still be "first" after this
  // apply, not "second".
  let alice_dn = user_dn("alice", &server);
  let alicia_dn = user_dn("alicia", &server);
  let desired2 = json!({
    "entries": {
      alicia_dn.clone(): {
        "__nixhapi": {
          "providerKey": [alicia_dn.clone(), alice_dn.clone()],
        },
        "objectClass": wire(PERSON_CLASSES),
        "cn": managed("Alice Smith"),
        "sn": managed("Smith"),
        "mail": managed("alice@example.org"),
        "userPassword": initial("second"),
      },
    },
  });

  let live2 = provider.list_live(&config, &[]).await.expect("list_live 2");
  let changes = compute_changes(&desired2, &live2, &NixHapiMeta::default());

  // The engine should emit a Rename: head match failed (no live
  // "uid=alicia"); history match succeeded against "uid=alice".
  let renamed = changes.iter().any(|n| {
    matches!(&n.status, Status::Rename { chain }
      if chain.first().and_then(|v| v.as_str()) == Some(alice_dn.as_str())
        && chain.last().and_then(|v| v.as_str()) == Some(alicia_dn.as_str()))
  });
  assert!(
    renamed,
    "expected Rename(alice -> alicia) in changes; got: {:?}",
    changes,
  );

  let wave = make_wave(changes, Vec::new());
  let runbook = provider
    .build_runbook(&wave, &desired2, &live2, &NixHapiMeta::default(), &config)
    .await
    .expect("build_runbook");
  let wave = make_wave(wave.changes.clone(), runbook);
  provider.apply(&wave, &config).await.expect("apply rename");

  let live3 = provider.list_live(&config, &[]).await.expect("list_live 3");
  assert!(
    live3["entries"][&alicia_dn].is_object(),
    "alicia should exist after rename; live3 = {:?}",
    live3,
  );
  assert!(
    live3["entries"][&alice_dn].is_null(),
    "alice should be gone after rename; live3 = {:?}",
    live3,
  );
  assert_eq!(
    live3["entries"][&alicia_dn]["userPassword"],
    json!("first"),
    "userPassword must be preserved through modrdn; \"second\" leaking \
     here would indicate the entry was deleted and re-added instead",
  );
}

/// Extra values of the RDN attribute are login aliases: a user declared
/// with `uid` beyond the RDN value must be added with the union, read back
/// as exactly the extras (the RDN value stays implicit in the providerKey),
/// plan clean on the next run, and take a changed alias set as a Replace
/// that still carries the RDN value.  slapd refuses an entry without its
/// naming value, so every apply here failing would mean the RDN value was
/// dropped from the wire.
#[tokio::test]
async fn rdn_attribute_extras_are_login_aliases() {
  let server = TestLdapServer::start().await.expect("start slapd");
  server
    .initialize()
    .await
    .expect("initialize base structure");

  let provider = make_provider();
  let config = make_config(&server);
  let alice_dn = user_dn("alice", &server);

  // One alias arrives as a scalar, the way the Nix module normalises a
  // single value.
  let mut alice1 = alice("Alice Smith", managed("secret"), &server);
  alice1["uid"] = json!("alice.alt");
  let desired1 = desired(&[alice1]);
  plan_and_apply(&provider, &config, &desired1, &NixHapiMeta::default()).await;

  let live1 = provider.list_live(&config, &[]).await.expect("list_live 1");
  assert_eq!(
    live1["entries"][&alice_dn]["uid"],
    json!("alice.alt"),
    "live uid should be the extras only; got: {:?}",
    live1["entries"][&alice_dn],
  );
  let changes1 = compute_changes(&desired1, &live1, &NixHapiMeta::default());
  assert!(
    changes1.is_empty(),
    "expected no changes after adding an alias; got: {:?}",
    changes1,
  );

  // A changed alias set is a Replace of uid; the RDN value must ride
  // along or slapd rejects it.
  let mut alice2 = alice("Alice Smith", managed("secret"), &server);
  alice2["uid"] = json!(["alice.alt", "alice.other"]);
  let desired2 = desired(std::slice::from_ref(&alice2));
  let changes2 = compute_changes(&desired2, &live1, &NixHapiMeta::default());
  assert!(
    changes2.iter().any(|n| matches!(n.status, Status::Modify)
      && n.field_changes.iter().any(|f| f.field == "uid")),
    "expected a Modify of uid; got: {:?}",
    changes2,
  );
  plan_and_apply(&provider, &config, &desired2, &NixHapiMeta::default()).await;

  let live2 = provider.list_live(&config, &[]).await.expect("list_live 2");
  assert_eq!(
    live2["entries"][&alice_dn]["uid"],
    json!(["alice.alt", "alice.other"]),
    "live uid should be both extras, sorted; got: {:?}",
    live2["entries"][&alice_dn],
  );
  let changes3 = compute_changes(&desired2, &live2, &NixHapiMeta::default());
  assert!(
    changes3.is_empty(),
    "expected no changes after changing the aliases; got: {:?}",
    changes3,
  );

  // A user without aliases is untouched by all this: no uid in desired,
  // none in live, nothing to do.
  let bob_dn = user_dn("bob", &server);
  let with_bob = desired(&[alice2, bob(&server)]);
  plan_and_apply(&provider, &config, &with_bob, &NixHapiMeta::default()).await;
  let live3 = provider.list_live(&config, &[]).await.expect("list_live 3");
  assert!(
    live3["entries"][&bob_dn]["uid"].is_null(),
    "a user with only its RDN value shows no uid; got: {:?}",
    live3["entries"][&bob_dn],
  );
}

/// `objectClass` is an ordinary declared attribute: it reads back sorted,
/// plans clean, and an auxiliary class added together with its required
/// attributes lands in one Modify.
#[tokio::test]
async fn object_class_round_trips_and_extends() {
  let server = TestLdapServer::start().await.expect("start slapd");
  server
    .initialize()
    .await
    .expect("initialize base structure");

  let provider = make_provider();
  let config = make_config(&server);
  let alice_dn = user_dn("alice", &server);

  let alice1 = alice("Alice Smith", managed("secret"), &server);
  let desired1 = desired(std::slice::from_ref(&alice1));
  plan_and_apply(&provider, &config, &desired1, &NixHapiMeta::default()).await;

  let live1 = provider.list_live(&config, &[]).await.expect("list_live 1");
  assert_eq!(
    live1["entries"][&alice_dn]["objectClass"],
    json!(["inetOrgPerson", "organizationalPerson", "person"]),
  );
  let changes1 = compute_changes(&desired1, &live1, &NixHapiMeta::default());
  assert!(changes1.is_empty(), "expected a clean plan; got {:?}", changes1);

  let mut alice2 = alice1.clone();
  alice2["objectClass"] = wire(&[
    "inetOrgPerson",
    "organizationalPerson",
    "person",
    "posixAccount",
  ]);
  alice2["uidNumber"] = managed("10001");
  alice2["gidNumber"] = managed("10001");
  alice2["homeDirectory"] = managed("/home/alice");
  let desired2 = desired(&[alice2]);

  let changes2 = compute_changes(&desired2, &live1, &NixHapiMeta::default());
  assert_eq!(changes2.len(), 1, "expected one node; got {:?}", changes2);
  assert!(matches!(changes2[0].status, Status::Modify));
  let changed: HashSet<&str> = changes2[0]
    .field_changes
    .iter()
    .map(|f| f.field.as_str())
    .collect();
  assert_eq!(
    changed,
    HashSet::from(["objectClass", "uidNumber", "gidNumber", "homeDirectory"]),
  );

  plan_and_apply(&provider, &config, &desired2, &NixHapiMeta::default()).await;
  let live2 = provider.list_live(&config, &[]).await.expect("list_live 2");
  assert_eq!(
    live2["entries"][&alice_dn]["objectClass"],
    json!([
      "inetOrgPerson",
      "organizationalPerson",
      "person",
      "posixAccount"
    ]),
  );
  assert_eq!(live2["entries"][&alice_dn]["uidNumber"], json!("10001"));
  let changes3 = compute_changes(&desired2, &live2, &NixHapiMeta::default());
  assert!(changes3.is_empty(), "expected a clean plan; got {:?}", changes3);
}

/// Nothing is synthesised for a group: a posixGroup carries exactly what
/// was declared and no groupOfNames `member`.
#[tokio::test]
async fn posix_group_is_added_without_member_placeholder() {
  let server = TestLdapServer::start().await.expect("start slapd");
  server
    .initialize()
    .await
    .expect("initialize base structure");

  let provider = make_provider();
  let config = make_config(&server);
  let devs_dn = group_dn("devs", &server);

  let devs = entry(
    &devs_dn,
    &["posixGroup"],
    json!({
      "gidNumber": managed("5000"),
      "memberUid": wire(&["alice", "bob"]),
    }),
  );
  let desired = desired(&[devs]);
  plan_and_apply(&provider, &config, &desired, &NixHapiMeta::default()).await;

  let live = provider.list_live(&config, &[]).await.expect("list_live");
  assert_eq!(live["entries"][&devs_dn]["memberUid"], json!(["alice", "bob"]),);
  assert!(
    live["entries"][&devs_dn]["member"].is_null(),
    "no placeholder member may be injected; got {:?}",
    live["entries"][&devs_dn],
  );
  let changes = compute_changes(&desired, &live, &NixHapiMeta::default());
  assert!(changes.is_empty(), "expected a clean plan; got {:?}", changes);
}

/// A `sub` base with a filter owns matching entries at any depth and nothing
/// else, and an entry two overlapping bases both return appears once.
#[tokio::test]
async fn sub_scope_owns_nested_entries_once() {
  let server = TestLdapServer::start().await.expect("start slapd");
  let mut ldap = server
    .initialize()
    .await
    .expect("initialize base structure");

  let admins_dn = format!("ou=admins,{}", users_ou(&server));
  let svc_dn = format!("ou=svc,{}", admins_dn);
  let deep_dn = format!("uid=deep,{}", svc_dn);
  add_raw(&mut ldap, &admins_dn, organizational_unit("admins")).await;
  add_raw(&mut ldap, &svc_dn, organizational_unit("svc")).await;
  add_raw(&mut ldap, &deep_dn, person("deep", "Deep User", "User")).await;

  let provider = make_provider();
  let people = Some("(objectClass=inetOrgPerson)");
  let config = config_with_bases(
    &server,
    &[
      search_base(&users_ou(&server), "sub", people),
      search_base(&admins_dn, "sub", people),
    ],
  );

  let live = provider.list_live(&config, &[]).await.expect("list_live");
  assert_eq!(
    entry_dns(&live),
    vec![deep_dn.clone()],
    "only the filtered entry is owned, and only once",
  );

  let changes = compute_changes(&desired(&[]), &live, &NixHapiMeta::default());
  assert_eq!(changes.len(), 1, "expected one Delete; got {:?}", changes);
  assert!(dn_has_status(&changes, &deep_dn, |s| matches!(s, Status::Delete)));

  let deeper_dn = format!("uid=deeper,{}", svc_dn);
  let deeper = entry(
    &deeper_dn,
    PERSON_CLASSES,
    json!({ "cn": managed("Deeper User"), "sn": managed("User") }),
  );
  plan_and_apply(
    &provider,
    &config,
    &desired(&[deeper]),
    &NixHapiMeta::default(),
  )
  .await;
  let live2 = provider.list_live(&config, &[]).await.expect("list_live 2");
  assert_eq!(entry_dns(&live2), vec![deeper_dn]);
}

/// A subtree base owns its own entry too, as LDAP defines the scope.
#[tokio::test]
async fn sub_scope_includes_the_base_entry() {
  let server = TestLdapServer::start().await.expect("start slapd");
  let mut ldap = server
    .initialize()
    .await
    .expect("initialize base structure");

  let admins_dn = format!("ou=admins,{}", users_ou(&server));
  let svc_dn = format!("ou=svc,{}", admins_dn);
  let deep_dn = format!("uid=deep,{}", svc_dn);
  add_raw(&mut ldap, &admins_dn, organizational_unit("admins")).await;
  add_raw(&mut ldap, &svc_dn, organizational_unit("svc")).await;
  add_raw(&mut ldap, &deep_dn, person("deep", "Deep User", "User")).await;

  let provider = make_provider();
  let config =
    config_with_bases(&server, &[search_base(&admins_dn, "sub", None)]);

  let live = provider.list_live(&config, &[]).await.expect("list_live");
  let mut owned = entry_dns(&live);
  owned.sort();
  let mut expected = vec![admins_dn, svc_dn, deep_dn];
  expected.sort();
  assert_eq!(owned, expected);
}

/// An entry no search base reaches would be written and never read back, so
/// the runbook refuses it and names the DN.
#[tokio::test]
async fn entry_outside_search_bases_fails_build_runbook() {
  let server = TestLdapServer::start().await.expect("start slapd");
  server
    .initialize()
    .await
    .expect("initialize base structure");

  let provider = make_provider();
  let config = make_config(&server);
  let stray_dn = format!("uid=stray,ou=elsewhere,{}", server.base_dn);
  let stray = entry(
    &stray_dn,
    PERSON_CLASSES,
    json!({ "cn": managed("Stray"), "sn": managed("Stray") }),
  );

  let err = build_runbook_for(&provider, &config, &desired(&[stray]))
    .await
    .expect_err("runbook must refuse an uncovered entry")
    .to_string();
  assert!(err.contains(&stray_dn), "{err}");
  assert!(err.contains("search base"), "{err}");
}

#[tokio::test]
async fn add_without_object_class_fails_build_runbook() {
  let server = TestLdapServer::start().await.expect("start slapd");
  server
    .initialize()
    .await
    .expect("initialize base structure");

  let provider = make_provider();
  let config = make_config(&server);
  let alice_dn = user_dn("alice", &server);
  let mut classless = alice("Alice Smith", managed("secret"), &server);
  classless
    .as_object_mut()
    .expect("object")
    .remove("objectClass");

  let err = build_runbook_for(&provider, &config, &desired(&[classless]))
    .await
    .expect_err("runbook must refuse an Add without objectClass")
    .to_string();
  assert!(err.contains(&alice_dn), "{err}");
  assert!(err.contains("objectClass"), "{err}");
}

/// The alias logic keys off whatever attribute the DN names, under whatever
/// container the base points at.
#[tokio::test]
async fn cn_rdn_extras_are_aliases_under_custom_container() {
  let server = TestLdapServer::start().await.expect("start slapd");
  let mut ldap = server
    .initialize()
    .await
    .expect("initialize base structure");

  let services_dn = format!("ou=services,{}", server.base_dn);
  add_raw(&mut ldap, &services_dn, organizational_unit("services")).await;

  let provider = make_provider();
  let config = config_with_bases(
    &server,
    &[
      search_base(&users_ou(&server), "one", None),
      search_base(&services_dn, "one", None),
    ],
  );
  let svc_dn = format!("cn=svc-backup,{}", services_dn);

  let svc1 = entry(
    &svc_dn,
    &["applicationProcess"],
    json!({
      "cn": wire(&["backup", "backup-svc"]),
      "description": managed("Backup job"),
    }),
  );
  let desired1 = desired(&[svc1]);
  plan_and_apply(&provider, &config, &desired1, &NixHapiMeta::default()).await;
  let live1 = provider.list_live(&config, &[]).await.expect("list_live 1");
  assert_eq!(live1["entries"][&svc_dn]["cn"], json!(["backup", "backup-svc"]),);
  let changes1 = compute_changes(&desired1, &live1, &NixHapiMeta::default());
  assert!(changes1.is_empty(), "expected a clean plan; got {:?}", changes1);

  let svc2 = entry(
    &svc_dn,
    &["applicationProcess"],
    json!({
      "cn": wire(&["backup"]),
      "description": managed("Backup job"),
    }),
  );
  let desired2 = desired(&[svc2]);
  let changes2 = compute_changes(&desired2, &live1, &NixHapiMeta::default());
  assert!(
    changes2.iter().any(|n| matches!(n.status, Status::Modify)
      && n.field_changes.iter().any(|f| f.field == "cn")),
    "expected a Modify of cn; got {:?}",
    changes2,
  );
  plan_and_apply(&provider, &config, &desired2, &NixHapiMeta::default()).await;
  let live2 = provider.list_live(&config, &[]).await.expect("list_live 2");
  assert_eq!(live2["entries"][&svc_dn]["cn"], json!("backup"));
  let changes3 = compute_changes(&desired2, &live2, &NixHapiMeta::default());
  assert!(changes3.is_empty(), "expected a clean plan; got {:?}", changes3);
}

#[tokio::test]
async fn malformed_search_base_url_is_a_config_error() {
  let server = TestLdapServer::start().await.expect("start slapd");
  server
    .initialize()
    .await
    .expect("initialize base structure");

  let provider = make_provider();
  for url in [
    format!("ldap:///{}??bogus", users_ou(&server)),
    "http://example.org/".to_string(),
    format!("ldaps:///{}??one", users_ou(&server)),
  ] {
    let config = config_with_bases(&server, std::slice::from_ref(&url));
    let err = provider
      .list_live(&config, &[])
      .await
      .err()
      .unwrap_or_else(|| panic!("{url} must be rejected"))
      .to_string();
    assert!(err.contains(&url), "{err}");
  }
}

/// The suffix entry the fixture creates.  Discovery owns the whole naming
/// context, so the record has to name it like everything beneath it.
fn suffix_entry(server: &TestLdapServer) -> Value {
  entry(&server.base_dn, &["dcObject", "organization", "top"], json!({}))
}

fn organizational_unit_entry(dn: &str) -> Value {
  entry(dn, &["organizationalUnit", "top"], json!({}))
}

/// What the fixture leaves on the server, declared: the suffix and its two
/// OUs.
fn fixture_entries(server: &TestLdapServer) -> Vec<Value> {
  vec![
    suffix_entry(server),
    organizational_unit_entry(&users_ou(server)),
    organizational_unit_entry(&groups_ou(server)),
  ]
}

fn sorted(mut dns: Vec<String>) -> Vec<String> {
  dns.sort();
  dns
}

/// Discovery owns every naming context the server publishes, root entry
/// included.
#[tokio::test]
async fn discovery_owns_every_naming_context() {
  let server = TestLdapServer::start().await.expect("start slapd");
  server
    .initialize()
    .await
    .expect("initialize base structure");

  let provider = make_provider();
  let config = config_discovering(&server, &[]);
  let live = provider.list_live(&config, &[]).await.expect("list_live");
  assert_eq!(
    sorted(entry_dns(&live)),
    sorted(vec![
      server.base_dn.clone(),
      users_ou(&server),
      groups_ou(&server)
    ]),
  );
  let changes = compute_changes(
    &desired(&fixture_entries(&server)),
    &live,
    &NixHapiMeta::default(),
  );
  assert!(changes.is_empty(), "expected a clean plan; got {:?}", changes);
}

/// An unmanaged naming context is neither read nor written: it is absent
/// from live state, and an entry declared inside it is refused at plan time.
#[tokio::test]
async fn unmanaged_naming_contexts_are_neither_read_nor_written() {
  let server = TestLdapServer::start().await.expect("start slapd");
  server
    .initialize()
    .await
    .expect("initialize base structure");

  let provider = make_provider();
  let config = config_discovering(&server, &[&server.base_dn]);
  let live = provider.list_live(&config, &[]).await.expect("list_live");
  assert_eq!(live["entries"], json!({}));

  let alice_dn = user_dn("alice", &server);
  let err = build_runbook_for(
    &provider,
    &config,
    &desired(&[alice("Alice Smith", managed("secret"), &server)]),
  )
  .await
  .expect_err("an entry in an unmanaged context must be refused")
  .to_string();
  assert!(err.contains(&alice_dn), "{err}");
}

/// Removing a node from the declaration removes everything beneath it, with
/// the runbook deleting deepest-first so the server never sees a non-leaf
/// delete.
#[tokio::test]
async fn removing_an_entry_deletes_its_subtree_deepest_first() {
  let server = TestLdapServer::start().await.expect("start slapd");
  server
    .initialize()
    .await
    .expect("initialize base structure");

  let provider = make_provider();
  let config = config_discovering(&server, &[]);
  let services_dn = format!("ou=services,{}", server.base_dn);
  let web_dn = format!("ou=web,{}", services_dn);
  let gitea_dn = format!("cn=gitea,{}", web_dn);
  let kept = fixture_entries(&server);

  let mut with_services = kept.clone();
  with_services.extend([
    organizational_unit_entry(&services_dn),
    organizational_unit_entry(&web_dn),
    entry(&gitea_dn, &["applicationProcess"], json!({})),
  ]);
  let with_services = desired(&with_services);
  plan_and_apply(&provider, &config, &with_services, &NixHapiMeta::default())
    .await;

  let without_services = desired(&kept);
  let runbook = build_runbook_for(&provider, &config, &without_services)
    .await
    .expect("build_runbook");
  let deletes: Vec<&str> = runbook
    .iter()
    .filter_map(|step| step.description.strip_prefix("delete "))
    .collect();
  assert_eq!(
    deletes,
    vec![gitea_dn.as_str(), web_dn.as_str(), services_dn.as_str()]
  );

  plan_and_apply(
    &provider,
    &config,
    &without_services,
    &NixHapiMeta::default(),
  )
  .await;
  let live = provider.list_live(&config, &[]).await.expect("list_live");
  assert_eq!(
    sorted(entry_dns(&live)),
    sorted(vec![
      server.base_dn.clone(),
      users_ou(&server),
      groups_ou(&server)
    ]),
  );
}

/// Renames are leaf operations.  Renaming a parent recreates it; a child that
/// carries the rename is moved with its attributes intact, and a child that
/// does not is recreated under the new parent.
#[tokio::test]
async fn renaming_a_parent_moves_children_that_carry_history() {
  let server = TestLdapServer::start().await.expect("start slapd");
  server
    .initialize()
    .await
    .expect("initialize base structure");

  let provider = make_provider();
  let config = config_discovering(&server, &[]);
  let suffix = suffix_entry(&server);
  let groups = organizational_unit_entry(&groups_ou(&server));
  let staff_dn = format!("ou=staff,{}", server.base_dn);

  let before = desired(&[
    suffix.clone(),
    organizational_unit_entry(&users_ou(&server)),
    groups.clone(),
    alice("Alice Smith", initial("first"), &server),
    bob(&server),
  ]);
  plan_and_apply(&provider, &config, &before, &NixHapiMeta::default()).await;

  // Alice carries the move; bob does not.  Both declare a different Initial
  // password, which only the recreated entry will take.
  let alice_new = format!("uid=alice,{}", staff_dn);
  let bob_new = format!("uid=bob,{}", staff_dn);
  let mut alice_moved = entry(
    &alice_new,
    PERSON_CLASSES,
    json!({
      "cn": managed("Alice Smith"),
      "sn": managed("Smith"),
      "mail": managed("alice@example.org"),
      "userPassword": initial("second"),
    }),
  );
  alice_moved["__nixhapi"]["providerKey"] =
    json!([alice_new, user_dn("alice", &server)]);
  let bob_recreated = entry(
    &bob_new,
    PERSON_CLASSES,
    json!({
      "cn": managed("Bob Jones"),
      "sn": managed("Jones"),
      "mail": managed("bob@example.org"),
      "userPassword": initial("second"),
    }),
  );
  let after = desired(&[
    suffix,
    organizational_unit_entry(&staff_dn),
    groups,
    alice_moved,
    bob_recreated,
  ]);

  let live1 = provider.list_live(&config, &[]).await.expect("list_live 1");
  let changes = compute_changes(&after, &live1, &NixHapiMeta::default());
  assert!(dn_has_status(&changes, &staff_dn, |s| matches!(s, Status::Add)));
  assert!(dn_has_status(&changes, &alice_new, |s| matches!(
    s,
    Status::Rename { .. }
  )));
  assert!(dn_has_status(&changes, &bob_new, |s| matches!(s, Status::Add)));
  assert!(dn_has_status(&changes, &user_dn("bob", &server), |s| matches!(
    s,
    Status::Delete
  )));
  assert!(dn_has_status(&changes, &users_ou(&server), |s| matches!(
    s,
    Status::Delete
  )));

  plan_and_apply(&provider, &config, &after, &NixHapiMeta::default()).await;
  let live2 = provider.list_live(&config, &[]).await.expect("list_live 2");
  assert_eq!(
    live2["entries"][&alice_new]["userPassword"],
    json!("first"),
    "a moved entry keeps its attributes",
  );
  assert_eq!(
    live2["entries"][&bob_new]["userPassword"],
    json!("second"),
    "a recreated entry takes the declared values",
  );
  assert!(live2["entries"][&users_ou(&server)].is_null());
  let changes2 = compute_changes(&after, &live2, &NixHapiMeta::default());
  assert!(changes2.is_empty(), "expected a clean plan; got {:?}", changes2);
}
