//! A query about an address inside a function only the gap walk finds answers
//! with that function walked, not with the address walked as a function first.
use crate::common;

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

fn fixture() -> PathBuf {
    let path = common::scratch_file("arm-gapfocus", "elf");
    assert!(Command::new("python3")
        .arg(common::fixture("arm_gapfocus_le32.py"))
        .arg(&path)
        .status()
        .expect("run authored fixture generator")
        .success());
    path
}

fn rows(path: &PathBuf, direction: &str, target: &str) -> Vec<(u64, u64, String, Option<u64>)> {
    let (stdout, stderr, code) =
        common::run_kuna(&["xrefs", path.to_str().unwrap(), direction, target, "--json"]);
    assert_eq!(code, 0, "{stderr}");
    let doc: Value = serde_json::from_str(&stdout).expect("xref JSON");
    doc["xrefs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["from_address"].as_u64().unwrap(),
                r["to_address"].as_u64().unwrap(),
                r["kind"].as_str().unwrap().to_string(),
                r["from_function"]["address"].as_u64(),
            )
        })
        .collect()
}

#[test]
fn a_query_inside_a_gap_walk_function_keeps_its_branches() {
    let path = fixture();
    assert_eq!(
        rows(&path, "--to", "0x1450"),
        vec![(0x1410, 0x1450, "jump".to_string(), Some(0x1400))],
    );
    assert_eq!(
        rows(&path, "--from", "0x1454"),
        vec![(0x1454, 0x1414, "jump".to_string(), Some(0x1400))],
    );
    assert!(rows(&path, "--to", "0x1420")
        .contains(&(0x1418, 0x1420, "jump".to_string(), Some(0x1400))));
    std::fs::remove_file(path).unwrap();
}
