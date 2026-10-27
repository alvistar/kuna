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
    rows_with(path, target, &[])
}

fn rows_with(path: &PathBuf, target: u64, extra: &[&str]) -> Vec<(u64, String)> {
    let target = format!("{target:#x}");
    let mut args = vec!["xrefs", path.to_str().unwrap(), "--to", &target, "--json"];
    args.extend_from_slice(extra);
    let (stdout, stderr, code) = common::run_kuna(&args);
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

#[test]
fn a_got_base_reloaded_from_the_stack_reads_its_slots() {
    let path = fixture();
    assert_eq!(rows(&path, 0x11008), vec![row(0x10420, "read")], "spilled, sp moved, reloaded");
    assert_eq!(rows(&path, 0x10830), vec![row(0x10420, "data")], "the slot's word");
    assert_eq!(rows(&path, 0x1100c), vec![row(0x1051c, "read")], "pushed and popped");
    assert!(rows(&path, 0x11010).is_empty(), "slot overwritten before the reload");
    assert!(rows(&path, 0x10850).is_empty());
    std::fs::remove_file(path).unwrap();
}

/// `picpoolreach off` restores the eight-instruction, fall-through-only window
/// and follows no stack slot: none of the rows above is filed.
#[test]
fn picpoolreach_off_files_none_of_them() {
    let path = fixture();
    let off = ["--option", "picpoolreach", "off"];
    let base = rows_with(&path, 0x11000, &off);
    assert!(!base.contains(&row(0x10138, "read")), "{base:?}");
    for target in [0x11004, 0x10820, 0x11008, 0x1100c] {
        assert!(rows_with(&path, target, &off).is_empty(), "{target:#x}");
    }
    std::fs::remove_file(path).unwrap();
}
