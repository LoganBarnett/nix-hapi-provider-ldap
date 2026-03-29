mod common;
use common::TestLdapServer;

use nix_hapi_lib::{
  field_value::ResolvedFieldValue,
  meta::NixHapiMeta,
  plan::ResourceChange,
  provider::{Provider, ResolvedConfig},
  subprocess::SubprocessProvider,
};
use std::collections::HashMap;
use std::path::Path;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn make_provider() -> SubprocessProvider {
  let binary = env!("CARGO_BIN_EXE_nix-hapi-provider-ldap");
  SubprocessProvider::spawn("ldap".to_string(), Path::new(binary))
    .expect("failed to spawn nix-hapi-provider-ldap")
}

fn make_config(server: &TestLdapServer) -> ResolvedConfig {
  let mut cfg = HashMap::new();
  cfg
    .insert("url".to_string(), ResolvedFieldValue::Managed(server.url.clone()));
  cfg.insert(
    "baseDn".to_string(),
    ResolvedFieldValue::Managed(server.base_dn.clone()),
  );
  cfg.insert(
    "bindDn".to_string(),
    ResolvedFieldValue::Managed(server.bind_dn.clone()),
  );
  cfg.insert(
    "bindPassword".to_string(),
    ResolvedFieldValue::Managed(server.bind_password.clone()),
  );
  cfg
}

fn managed(value: &str) -> serde_json::Value {
  serde_json::json!({"__nixhapi": "managed", "value": value})
}

fn initial(value: &str) -> serde_json::Value {
  serde_json::json!({"__nixhapi": "initial", "value": value})
}

/// Wraps a users map in the top-level desired-state shape, with no groups.
fn desired(users: serde_json::Value) -> serde_json::Value {
  serde_json::json!({"users": users, "groups": {}})
}

/// A minimal alice entry including `sn`, which is required by inetOrgPerson.
/// The `password_field` argument lets callers choose managed vs. initial.
fn alice(cn: &str, password_field: serde_json::Value) -> serde_json::Value {
  serde_json::json!({
    "cn": managed(cn),
    "sn": managed("Smith"),
    "mail": managed("alice@example.org"),
    "userPassword": password_field,
  })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Verifies that the test infrastructure starts cleanly and list_live returns
/// empty collections once the base structure is in place but no users/groups
/// have been added yet.
#[test]
fn canary_list_live_empty() {
  let server = TestLdapServer::start().expect("start slapd");
  server.initialize().expect("initialize base structure");

  let provider = make_provider();
  let live = provider
    .list_live(&make_config(&server), &[])
    .expect("list_live");

  assert_eq!(live["users"], serde_json::json!({}));
  assert_eq!(live["groups"], serde_json::json!({}));
}

/// A user in the desired state that is absent from live should produce an Add
/// change in the plan.
#[test]
fn plan_produces_add_for_new_user() {
  let server = TestLdapServer::start().expect("start slapd");
  server.initialize().expect("initialize base structure");

  let provider = make_provider();
  let config = make_config(&server);
  let live = provider.list_live(&config, &[]).expect("list_live");
  let desired_state = desired(
    serde_json::json!({"alice": alice("Alice Smith", initial("secret"))}),
  );

  let plan = provider
    .plan(&desired_state, &live, &NixHapiMeta::default(), &config)
    .expect("plan");

  let alice_dn = format!("uid=alice,ou=users,{}", server.base_dn);
  let has_add = plan.changes.iter().any(|c| {
    matches!(c, ResourceChange::Add { resource_id, .. } if resource_id == &alice_dn)
  });
  assert!(has_add, "Expected Add change for alice; got: {:?}", plan.changes);
}

/// Applying a plan that adds a user should result in that user appearing in the
/// live state on the next list_live call.
#[test]
fn apply_creates_user() {
  let server = TestLdapServer::start().expect("start slapd");
  server.initialize().expect("initialize base structure");

  let provider = make_provider();
  let config = make_config(&server);
  let live = provider.list_live(&config, &[]).expect("list_live");
  let desired_state = desired(
    serde_json::json!({"alice": alice("Alice Smith", initial("secret"))}),
  );

  let mut plan = provider
    .plan(&desired_state, &live, &NixHapiMeta::default(), &config)
    .expect("plan");
  plan.instance_name = "test".to_string();
  provider.apply(&plan, &config).expect("apply");

  let live_after = provider.list_live(&config, &[]).expect("list_live after");
  assert!(
    live_after["users"]["alice"].is_object(),
    "Expected alice in live state after apply"
  );
  assert_eq!(
    live_after["users"]["alice"]["cn"],
    serde_json::json!(["Alice Smith"]),
    "cn should match desired value"
  );
}

/// Running plan → apply → plan should produce an empty plan on the second run
/// for all Managed and Initial fields.
#[test]
fn apply_is_idempotent() {
  let server = TestLdapServer::start().expect("start slapd");
  server.initialize().expect("initialize base structure");

  let provider = make_provider();
  let config = make_config(&server);
  let desired_state = desired(
    serde_json::json!({"alice": alice("Alice Smith", initial("secret"))}),
  );

  // First apply.
  let live1 = provider.list_live(&config, &[]).expect("list_live 1");
  let mut plan1 = provider
    .plan(&desired_state, &live1, &NixHapiMeta::default(), &config)
    .expect("plan 1");
  plan1.instance_name = "test".to_string();
  provider.apply(&plan1, &config).expect("apply 1");

  // Second plan should be empty.
  let live2 = provider.list_live(&config, &[]).expect("list_live 2");
  let plan2 = provider
    .plan(&desired_state, &live2, &NixHapiMeta::default(), &config)
    .expect("plan 2");

  assert!(
    plan2.changes.is_empty(),
    "Expected no changes on second plan; got: {:?}",
    plan2.changes
  );
}

/// A Managed field whose desired value changes should produce a Modify change
/// in the next plan.
#[test]
fn managed_field_is_enforced_on_change() {
  let server = TestLdapServer::start().expect("start slapd");
  server.initialize().expect("initialize base structure");

  let provider = make_provider();
  let config = make_config(&server);

  // Apply original value.
  let live1 = provider.list_live(&config, &[]).expect("list_live 1");
  let desired1 = desired(
    serde_json::json!({"alice": alice("Alice Smith", initial("secret"))}),
  );
  let mut plan1 = provider
    .plan(&desired1, &live1, &NixHapiMeta::default(), &config)
    .expect("plan 1");
  plan1.instance_name = "test".to_string();
  provider.apply(&plan1, &config).expect("apply 1");

  // Plan with updated cn — should detect drift.
  let live2 = provider.list_live(&config, &[]).expect("list_live 2");
  let desired2 = desired(
    serde_json::json!({"alice": alice("Alice Updated", initial("secret"))}),
  );
  let plan2 = provider
    .plan(&desired2, &live2, &NixHapiMeta::default(), &config)
    .expect("plan 2");

  let alice_dn = format!("uid=alice,ou=users,{}", server.base_dn);
  let has_modify = plan2.changes.iter().any(|c| {
    matches!(c, ResourceChange::Modify { resource_id, .. } if resource_id == &alice_dn)
  });
  assert!(
    has_modify,
    "Expected Modify for alice after cn change; got: {:?}",
    plan2.changes
  );
}

/// An Initial field must not generate a Modify once the attribute is present in
/// the live entry, regardless of what new value the desired state declares.
#[test]
fn initial_field_not_updated_when_present() {
  let server = TestLdapServer::start().expect("start slapd");
  server.initialize().expect("initialize base structure");

  let provider = make_provider();
  let config = make_config(&server);

  // Apply with userPassword = initial("first").
  let live1 = provider.list_live(&config, &[]).expect("list_live 1");
  let desired1 = desired(
    serde_json::json!({"alice": alice("Alice Smith", initial("first"))}),
  );
  let mut plan1 = provider
    .plan(&desired1, &live1, &NixHapiMeta::default(), &config)
    .expect("plan 1");
  plan1.instance_name = "test".to_string();
  provider.apply(&plan1, &config).expect("apply 1");

  // Change the declared initial value to "second" — must still produce no
  // changes because userPassword is already present in the live entry.
  let live2 = provider.list_live(&config, &[]).expect("list_live 2");
  let desired2 = desired(
    serde_json::json!({"alice": alice("Alice Smith", initial("second"))}),
  );
  let plan2 = provider
    .plan(&desired2, &live2, &NixHapiMeta::default(), &config)
    .expect("plan 2");

  assert!(
    plan2.changes.is_empty(),
    "Initial field must not be modified when already present; got: {:?}",
    plan2.changes
  );
}

/// A user present in live but absent from the desired state should appear as a
/// Delete change in the plan.
#[test]
fn user_absent_from_desired_is_deleted() {
  let server = TestLdapServer::start().expect("start slapd");
  server.initialize().expect("initialize base structure");

  let provider = make_provider();
  let config = make_config(&server);

  // Apply alice.
  let live1 = provider.list_live(&config, &[]).expect("list_live 1");
  let with_alice = desired(
    serde_json::json!({"alice": alice("Alice Smith", managed("secret"))}),
  );
  let mut plan1 = provider
    .plan(&with_alice, &live1, &NixHapiMeta::default(), &config)
    .expect("plan 1");
  plan1.instance_name = "test".to_string();
  provider.apply(&plan1, &config).expect("apply 1");

  // Plan with no users — alice should be marked for deletion.
  let live2 = provider.list_live(&config, &[]).expect("list_live 2");
  let plan2 = provider
    .plan(
      &desired(serde_json::json!({})),
      &live2,
      &NixHapiMeta::default(),
      &config,
    )
    .expect("plan 2");

  let alice_dn = format!("uid=alice,ou=users,{}", server.base_dn);
  let has_delete = plan2.changes.iter().any(|c| {
    matches!(c, ResourceChange::Delete { resource_id } if resource_id == &alice_dn)
  });
  assert!(
    has_delete,
    "Expected Delete change for alice; got: {:?}",
    plan2.changes
  );
}

/// Resources whose DNs match an ignore pattern must not appear as deletions
/// even when absent from the desired state.
#[test]
fn ignore_pattern_prevents_deletion() {
  let server = TestLdapServer::start().expect("start slapd");
  server.initialize().expect("initialize base structure");

  let provider = make_provider();
  let config = make_config(&server);

  // Apply alice.
  let live1 = provider.list_live(&config, &[]).expect("list_live 1");
  let with_alice = desired(
    serde_json::json!({"alice": alice("Alice Smith", managed("secret"))}),
  );
  let mut plan1 = provider
    .plan(&with_alice, &live1, &NixHapiMeta::default(), &config)
    .expect("plan 1");
  plan1.instance_name = "test".to_string();
  provider.apply(&plan1, &config).expect("apply 1");

  // Plan with no users but an ignore pattern matching alice's DN.
  let live2 = provider.list_live(&config, &[]).expect("list_live 2");
  let meta = NixHapiMeta {
    ignore: vec!["uid=alice,.*".to_string()],
    ..NixHapiMeta::default()
  };
  let plan2 = provider
    .plan(&desired(serde_json::json!({})), &live2, &meta, &config)
    .expect("plan 2");

  assert!(
    plan2.changes.is_empty(),
    "Expected no changes; alice should be protected by ignore pattern; got: {:?}",
    plan2.changes
  );
}

/// Every runbook command must redact the bind password.  The check targets the
/// `-w <password>` argument specifically, since the bind DN may legitimately
/// contain a substring of the password.
#[test]
fn runbook_scrubs_bind_password() {
  let server = TestLdapServer::start().expect("start slapd");
  server.initialize().expect("initialize base structure");

  let provider = make_provider();
  let config = make_config(&server);
  let live = provider.list_live(&config, &[]).expect("list_live");
  let desired_state = desired(
    serde_json::json!({"alice": alice("Alice Smith", managed("secret"))}),
  );

  let plan = provider
    .plan(&desired_state, &live, &NixHapiMeta::default(), &config)
    .expect("plan");

  assert!(!plan.runbook.is_empty(), "Expected at least one runbook step");
  for step in &plan.runbook {
    let raw_password_arg = format!("-w {}", server.bind_password);
    assert!(
      !step.command.contains(&raw_password_arg),
      "Bind password must not appear as -w argument: {}",
      step.command
    );
    assert!(
      step.command.contains("-w ***"),
      "Runbook command must show -w *** in place of password: {}",
      step.command
    );
  }
}
