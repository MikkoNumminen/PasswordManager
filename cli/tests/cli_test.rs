//! End to end CLI tests. Stdin is piped, so the binary reads the master
//! password and every prompt answer from consecutive stdin lines. The
//! password never appears as an argument.
//!
//! These tests run `init` with the real default KDF parameters, so each
//! unlock performs a full Argon2id derivation. That is deliberate: the
//! production parameters get exercised on every test run.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::Path;

const MASTER: &str = "test master password";

fn pm(vault: &Path) -> Command {
    let mut cmd = Command::cargo_bin("password-manager").expect("binary builds");
    cmd.env("PASSWORD_MANAGER_VAULT", vault);
    cmd
}

fn init_vault(vault: &Path) {
    pm(vault)
        .arg("init")
        .write_stdin(format!("{MASTER}\n{MASTER}\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains("Vault created"));
}

#[test]
fn full_entry_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
    init_vault(&vault);

    // add: master password, username, entry password, url, notes
    pm(&vault)
        .args(["add", "example.com"])
        .write_stdin(format!(
            "{MASTER}\nmikko\nhunter2 entry pw\nhttps://example.com/login\nsome notes\n"
        ))
        .assert()
        .success()
        .stdout(predicate::str::contains("Added 'example.com'"));

    // get without --reveal masks the password
    pm(&vault)
        .args(["get", "example"])
        .write_stdin(format!("{MASTER}\n"))
        .assert()
        .success()
        .stdout(
            predicate::str::contains("mikko")
                .and(predicate::str::contains("https://example.com/login"))
                .and(predicate::str::contains("hunter2").not()),
        );

    // get --reveal prints it
    pm(&vault)
        .args(["get", "example.com", "--reveal"])
        .write_stdin(format!("{MASTER}\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains("hunter2 entry pw"));

    // list shows the entry
    pm(&vault)
        .arg("list")
        .write_stdin(format!("{MASTER}\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains("example.com").and(predicate::str::contains("mikko")));

    // edit: keep title, change username, keep password, keep url, clear notes
    pm(&vault)
        .args(["edit", "example.com"])
        .write_stdin(format!("{MASTER}\n\nuusi-mikko\n\n\n-\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains("Updated 'example.com'"));

    pm(&vault)
        .args(["get", "example.com", "--reveal"])
        .write_stdin(format!("{MASTER}\n"))
        .assert()
        .success()
        .stdout(
            predicate::str::contains("uusi-mikko")
                .and(predicate::str::contains("hunter2 entry pw")),
        );

    // rm with confirmation
    pm(&vault)
        .args(["rm", "example.com"])
        .write_stdin(format!("{MASTER}\ny\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains("Deleted 'example.com'"));

    pm(&vault)
        .args(["get", "example.com"])
        .write_stdin(format!("{MASTER}\n"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("no entry matches"));
}

#[test]
fn wrong_password_is_rejected_with_clear_message() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
    init_vault(&vault);

    pm(&vault)
        .arg("list")
        .write_stdin("not the password\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("wrong master password"));
}

#[test]
fn init_refuses_to_overwrite_existing_vault() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
    init_vault(&vault);

    pm(&vault)
        .arg("init")
        .write_stdin(format!("{MASTER}\n{MASTER}\n"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn init_rejects_mismatched_passwords() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
    pm(&vault)
        .arg("init")
        .write_stdin("one password\nanother password\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("do not match"));
    assert!(
        !vault.exists() || {
            // The database file may exist with schema but must hold no vault.
            pm(&vault)
                .arg("list")
                .write_stdin("x\n")
                .assert()
                .failure()
                .stderr(predicate::str::contains("run `password-manager init`"));
            true
        }
    );
}

#[test]
fn generated_password_never_prints_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
    init_vault(&vault);

    // add with -g: master password, username, url, notes (no password prompt)
    let assert = pm(&vault)
        .args(["add", "generated.example", "-g", "32"])
        .write_stdin(format!("{MASTER}\nuser\n\n\n"))
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();

    // Fetch the generated password, then check it never appeared in add's output.
    let reveal = pm(&vault)
        .args(["get", "generated.example", "--reveal"])
        .write_stdin(format!("{MASTER}\n"))
        .assert()
        .success();
    let reveal_out = String::from_utf8(reveal.get_output().stdout.clone()).unwrap();
    let password_line = reveal_out
        .lines()
        .find(|l| l.starts_with("Password:"))
        .expect("password line");
    let password = password_line.trim_start_matches("Password:").trim();
    assert_eq!(password.len(), 32);
    assert!(!stdout.contains(password));
}

#[test]
fn ambiguous_query_lists_candidates() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
    init_vault(&vault);

    for title in ["site-alpha", "site-beta"] {
        pm(&vault)
            .args(["add", title])
            .write_stdin(format!("{MASTER}\nuser\npw\n\n\n"))
            .assert()
            .success();
    }
    pm(&vault)
        .args(["get", "site"])
        .write_stdin(format!("{MASTER}\n"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("site-alpha").and(predicate::str::contains("site-beta")));
}
