//! A pool-loaded register keeps its value until it is written, wherever the
//! instruction that uses it sits.
use crate::common;

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

fn fixture() -> PathBuf {
    let path = common::scratch_file("arm-regvalue", "elf");
    assert!(Command::new("python3")
        .arg(common::fixture("arm_regvalue_le32.py"))
        .arg(&path)
        .status()
        .expect("run authored fixture generator")
        .success());
    path
}

fn rows(path: &PathBuf, target: u64) -> Vec<(u64, String)> {
    let (stdout, stderr, code) =
        common::run_kuna(&["xrefs", path.to_str().unwrap(), "--to", &format!("{target:#x}"), "--json"]);
    assert_eq!(code, 0, "{stderr}");
    let doc: Value = serde_json::from_str(&stdout).expect("xref JSON");
    let mut rows: Vec<(u64, String)> = doc["xrefs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r["from_address"].as_u64().unwrap(), r["kind"].as_str().unwrap().to_string()))
        .collect();
    rows.sort();
    rows
}

fn row(from: u64, kind: &str) -> (u64, String) {
    (from, kind.to_string())
}

#[test]
fn a_pool_word_far_from_or_branched_to_its_use_still_forms_the_address() {
    let path = fixture();
    let base = rows(&path, 0x11000);
    assert!(base.contains(&row(0x10130, "data")), "pair 11 apart makes the base: {base:?}");
    assert!(base.contains(&row(0x10138, "read")), "slot read through it: {base:?}");
    assert_eq!(rows(&path, 0x10800), vec![row(0x10138, "data")], "the slot's word");
    assert_eq!(rows(&path, 0x11004), vec![row(0x10264, "read")], "offset loaded 25 before");
    assert_eq!(rows(&path, 0x10820), vec![row(0x10324, "data")], "word carried across a branch");
    std::fs::remove_file(path).unwrap();
}
