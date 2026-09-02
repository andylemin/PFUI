//! Live PF ioctl tests. These talk to the real kernel through /dev/pf, so they
//! only build on OpenBSD and only run when asked for:
//!
//!     doas cargo test --test pf_ioctl_live -- --ignored --test-threads=1
//!
//! They need root, or a group with write on /dev/pf. --test-threads=1 because
//! they share the tables they work on.
//!
//! By default they use their own scratch tables, so running them on a firewall
//! cannot disturb a live whitelist. Point them at real tables — which is the
//! more faithful test, since those are declared in pf.conf — only when the
//! ruleset is known not to be relying on their contents:
//!
//!     PFUI_TEST_TABLE4=pfui_ipv4_domains PFUI_TEST_TABLE6=pfui_ipv6_domains ...

#![cfg(target_os = "openbsd")]

use std::net::IpAddr;
use std::path::Path;

use pfui_firewall::pf::ioctl::{table_add, table_del, table_get, DevPf};

const DEVPF: &str = "/dev/pf";

fn table4() -> String {
    std::env::var("PFUI_TEST_TABLE4").unwrap_or_else(|_| "pfui_selftest_v4".into())
}

fn table6() -> String {
    std::env::var("PFUI_TEST_TABLE6").unwrap_or_else(|_| "pfui_selftest_v6".into())
}

fn dev() -> DevPf<'static> {
    DevPf(Path::new(DEVPF))
}

fn ips(list: &[&str]) -> Vec<IpAddr> {
    list.iter().map(|s| s.parse().unwrap()).collect()
}

/// The table ioctls do not create tables — an absent one is ESRCH — so a table
/// that is not already in the ruleset is created the way an operator would,
/// with pfctl. A table created that way is anonymous, and a ruleset reload
/// clears it away again.
fn ensure_table(table: &str, v6: bool) {
    if table_get(&mut dev(), table).is_ok() {
        drain(table);
        return;
    }
    let seed = if v6 { "2001:db8::1" } else { "192.0.2.1" };
    let created = std::process::Command::new("/sbin/pfctl")
        .args(["-t", table, "-T", "add", seed])
        .output()
        .expect("run pfctl");
    assert!(
        created.status.success(),
        "pfctl could not create {table}: {}",
        String::from_utf8_lossy(&created.stderr)
    );
    drain(table);
}

/// Leave the table as it was found: empty.
fn drain(table: &str) {
    if let Ok(existing) = table_get(&mut dev(), table) {
        if !existing.is_empty() {
            let _ = table_del(&mut dev(), table, &existing);
        }
    }
}

#[test]
#[ignore = "talks to the real kernel; needs root and /dev/pf"]
fn ipv4_add_get_del_against_the_real_kernel() {
    let table = table4();
    ensure_table(&table, false);
    // Documentation range: harmless even if a rule did match it
    let addrs = ips(&["192.0.2.10", "192.0.2.11"]);

    let added = table_add(&mut dev(), &table, &addrs).expect("DIOCRADDADDRS");
    assert_eq!(added, 2, "the kernel counted the additions");

    // Re-adding is not an effective addition, which is what makes the sync
    // loop's "add what Redis has that the table lacks" idempotent
    let again = table_add(&mut dev(), &table, &addrs).expect("DIOCRADDADDRS again");
    assert_eq!(again, 0, "re-adding an existing entry adds nothing");

    let read = table_get(&mut dev(), &table).expect("DIOCRGETADDRS");
    let mut sorted = read.clone();
    sorted.sort();
    assert_eq!(sorted, addrs, "the kernel returned what was installed");

    let deleted = table_del(&mut dev(), &table, &addrs).expect("DIOCRDELADDRS");
    assert_eq!(deleted, 2, "ndel, not nadd, counts deletions");
    assert!(
        table_get(&mut dev(), &table)
            .expect("read after delete")
            .is_empty(),
        "the table is empty again"
    );
}

#[test]
#[ignore = "talks to the real kernel; needs root and /dev/pf"]
fn ipv6_round_trips_and_stays_canonical() {
    let table = table6();
    ensure_table(&table, true);
    let addrs = ips(&["2001:db8::10", "2001:db8::20"]);

    assert_eq!(table_add(&mut dev(), &table, &addrs).expect("add v6"), 2);
    let read = table_get(&mut dev(), &table).expect("get v6");
    let mut sorted = read.clone();
    sorted.sort();
    assert_eq!(sorted, addrs);
    // Spelling must survive the kernel round trip, or the sync loop would
    // delete and re-add the same address forever
    assert!(
        read.iter().all(|ip| ip.to_string().contains("2001:db8::")),
        "addresses come back canonical: {read:?}"
    );

    assert_eq!(table_del(&mut dev(), &table, &addrs).expect("del v6"), 2);
    assert!(table_get(&mut dev(), &table).unwrap().is_empty());
}

#[test]
#[ignore = "talks to the real kernel; needs root and /dev/pf"]
fn a_larger_batch_round_trips() {
    // Exercises the two-call GETADDRS sizing on a buffer worth allocating
    let table = table4();
    ensure_table(&table, false);
    let addrs: Vec<IpAddr> = (1..=200)
        .map(|n: u32| format!("198.51.100.{}", n % 256).parse().unwrap())
        .collect::<std::collections::BTreeSet<IpAddr>>()
        .into_iter()
        .collect();
    let installed = table_add(&mut dev(), &table, &addrs).expect("bulk add");
    assert_eq!(installed, addrs.len());

    let mut read = table_get(&mut dev(), &table).expect("bulk get");
    read.sort();
    assert_eq!(read, addrs, "every address of a bulk install reads back");

    assert_eq!(
        table_del(&mut dev(), &table, &addrs).expect("bulk del"),
        addrs.len()
    );
    drain(&table);
}

#[test]
#[ignore = "talks to the real kernel; needs root and /dev/pf"]
fn deleting_an_absent_address_reports_zero() {
    let table = table4();
    ensure_table(&table, false);
    let absent = ips(&["192.0.2.99"]);
    assert_eq!(
        table_del(&mut dev(), &table, &absent).expect("delete absent"),
        0,
        "the kernel reports nothing was deleted"
    );
}

#[test]
#[ignore = "talks to the real kernel; needs root and /dev/pf"]
fn a_table_absent_from_the_ruleset_is_a_named_error() {
    // ESRCH is how the kernel says "no such table". The ioctls never create
    // one, unlike pfctl -T add, so this is the failure an operator sees when
    // the table is missing from pf.conf
    let err = table_add(&mut dev(), "pfui_no_such_table_xyz", &ips(&["192.0.2.1"]))
        .expect_err("a missing table must fail");
    let text = err.to_string();
    assert!(
        text.contains("not in the active ruleset"),
        "the error should name the cause: {text}"
    );
}
