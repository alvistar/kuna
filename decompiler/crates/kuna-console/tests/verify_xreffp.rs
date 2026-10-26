//! End-to-end gate for two ARM false positives of the reference walk: the
//! partial sums a PLT stub builds its slot's address from.
//!
//! Fixture: `xreffp_arm_le32` (built from `xreffp_arm_le32.c`), a dynamic A32
//! executable whose imports are called through GNU ld PLT stubs
//! (`add ip,pc,#0,12; add ip,ip,#0x12000; ldr pc,[ip,#M]!`), with `table`
//! between the stubs and the GOT so that `0x12000` is a mapped address.

use std::path::PathBuf;
use std::sync::OnceLock;

use kuna_analysis::listing::xrefs::{self, XrefIndex, XrefKind};
use kuna_console::engine::bootstrap_from_object;

/// The PLT stubs (entry, slot) of `printf`, `puts` and `strlen`.
const STUBS: [(u64, u64); 3] = [(0x10310, 0x2300c), (0x1031c, 0x23010), (0x1034c, 0x23020)];
/// The immediate every stub adds to `ip`, which lands in `table`.
const STUB_ADD: u64 = 0x12000;
/// `main`'s calls to the stubs of `printf`, `puts` and `strlen`.
const STUB_CALLS: [(u64, u64); 3] = [(0x103c8, 0x10310), (0x10394, 0x1031c), (0x103b4, 0x1034c)];
/// `main`'s two PC-relative strings: the `add rN,pc,rN` and the string.
const STRINGS: [(u64, u64); 2] = [(0x10390, 0x10648), (0x103c4, 0x10650)];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap()
}

fn fixture() -> PathBuf {
    repo_root().join("decompiler/crates/kuna-analysis/tests/fixtures/xreffp_arm_le32")
}

/// The fixture's reference index under the default options, built once.
fn index() -> &'static XrefIndex {
    static INDEX: OnceLock<XrefIndex> = OnceLock::new();
    INDEX.get_or_init(|| {
        let bin = fixture();
        let spec_roots = vec![repo_root().join("specs").to_str().unwrap().to_string()];
        let mut prog = bootstrap_from_object(bin.to_str().unwrap(), "", &spec_roots)
            .expect("bootstrap fixture with built processor specs");
        prog.commit_pending_analysis().expect("analysis commit succeeds");
        let bytes = std::fs::read(&bin).expect("fixture readable");
        let file = object::File::parse(&*bytes).expect("fixture parses");
        let seeds: Vec<u64> =
            prog.function_entries_canonical().iter().map(|e| e.addr.get_offset()).collect();
        xrefs::build(&file, prog.arch(), prog.arch().translate(), &seeds)
    })
}

fn from(idx: &XrefIndex, at: u64) -> Vec<(u64, XrefKind)> {
    idx.refs_from_instruction(at).iter().map(|r| (r.to, r.kind)).collect()
}

/// A PLT stub files the slot it jumps through, from its `ldr pc`, and nothing
/// for the PC value or the immediate it adds on the way.
#[test]
fn a_plt_stub_files_its_slot_and_no_partial_address() {
    let idx = index();
    for (stub, slot) in STUBS {
        let rows: Vec<_> = (0..3).flat_map(|i| from(idx, stub + 4 * i)).collect();
        assert_eq!(rows, vec![(slot, XrefKind::Read)], "{stub:#x}");
        assert_eq!(from(idx, stub + 8), vec![(slot, XrefKind::Read)], "{stub:#x}");
    }
    assert!(idx.refs_to(STUB_ADD).is_empty(), "{:?}", idx.refs_to(STUB_ADD));
}

/// The calls into the stubs and the PC-relative strings of the caller keep
/// their rows.
#[test]
fn calls_to_plt_stubs_and_pc_relative_strings_keep_their_rows() {
    let idx = index();
    for (call, stub) in STUB_CALLS {
        assert!(from(idx, call).contains(&(stub, XrefKind::Call)), "{call:#x}: {:?}", from(idx, call));
    }
    for (add, string) in STRINGS {
        assert!(from(idx, add).contains(&(string, XrefKind::Data)), "{add:#x}: {:?}", from(idx, add));
    }
}
