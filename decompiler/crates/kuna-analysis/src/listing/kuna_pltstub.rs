//! (kuna) `pltstub` — a PLT stub that builds its slot's address in a register
//! references the slot, not the partial sums on the way to it.
//!
//! GNU ld's A32 PLT entry adds the PC and two (three with `--long-plt`) rotated
//! immediates into `ip`, then jumps through the slot that sum names:
//!
//! ```text
//! 0x10310  add ip,pc,#0,12      ; ip = 0x10318          (adr r12,0x10318)
//! 0x10314  add ip,ip,#18,20     ; ip += 0x12000
//! 0x10318  ldr pc,[ip,#0xcf4]!  ; jump through the slot 0x2300c
//! ```
//!
//! Each step lifts to a constant the generic operand rule files when it lands in
//! a mapped section: the PC value (`0x10318`) and, once the GOT is far enough
//! from the stub, the immediate itself (`0x12000`). Neither is a reference; the
//! one address the stub uses is the slot.
//!
//! # The rule
//!
//! A chain is a straight run that starts with an instruction setting one
//! register to a constant, adds constants to that register in one or more
//! further instructions, and ends in an instruction that loads through the
//! register plus a constant and jumps to what it loaded (`BRANCHIND`). Its
//! instructions file no constant [`XrefKind::Data`] row; the last one files the
//! slot as a [`XrefKind::Read`]. The values are only `COPY`/`INT_ADD`/`INT_SUB`
//! of constants, so no other instruction shape matches, and a run that leaves
//! the shape at any step keeps the rows the generic rule gives it.

use std::collections::HashMap;
use std::rc::Rc;

use kuna_base::space::{spacetype, AddrSpace};
use kuna_num::opcodes::OpCode;
use kuna_num::pcoderaw::VarnodeData;
use kuna_sleigh::translate::Translate;

use super::xrefs::{decode, FullCapture, FullOp, XrefKind};

/// The most constant adds a chain may take before its load: one in the
/// standard entry, two with `--long-plt`.
const MAX_ADDS: usize = 2;

/// What one instruction of a recognised chain contributes.
#[derive(Clone, Copy)]
enum Role {
    /// Builds a partial address: files no constant row.
    Partial,
    /// Loads the slot and jumps through it: files the slot.
    Load(u64),
}

/// The chains recognised so far, keyed by the VMA of each instruction in them.
#[derive(Default)]
pub(super) struct PltStubs {
    roles: HashMap<u64, Role>,
}

impl PltStubs {
    /// Recognise a chain starting at `vma` (of byte length `len`, lifted to
    /// `ops`) when it has not been seen, then rewrite `drefs` for the
    /// instruction's role in any chain.
    pub(super) fn rewrite(
        &mut self,
        translate: &dyn Translate,
        code_space: &Rc<AddrSpace>,
        data_space: Option<&Rc<AddrSpace>>,
        vma: u64,
        len: u32,
        ops: &[FullOp],
        drefs: &mut Vec<(u64, XrefKind)>,
    ) {
        if !self.roles.contains_key(&vma) && drefs.iter().any(|&(_, kind)| kind == XrefKind::Data) {
            if let Some(chain) = chain_at(translate, code_space, data_space, vma, len, ops) {
                self.roles.extend(chain);
            }
        }
        match self.roles.get(&vma) {
            Some(Role::Partial) => drefs.retain(|&(_, kind)| kind != XrefKind::Data),
            Some(&Role::Load(slot)) => {
                drefs.retain(|&(_, kind)| kind != XrefKind::Data);
                if !drefs.contains(&(slot, XrefKind::Read)) {
                    drefs.push((slot, XrefKind::Read));
                }
            }
            None => {}
        }
    }
}

/// The chain whose first instruction is the one at `vma`, as the role of each
/// of its instructions.
fn chain_at(
    translate: &dyn Translate,
    code_space: &Rc<AddrSpace>,
    data_space: Option<&Rc<AddrSpace>>,
    vma: u64,
    len: u32,
    ops: &[FullOp],
) -> Option<Vec<(u64, Role)>> {
    let mut values = Values::new(data_space);
    let (reg, _) = values.single_write(ops)?;
    let mut roles = vec![(vma, Role::Partial)];
    let mut cap = FullCapture::default();
    let mut at = vma.wrapping_add(u64::from(len));
    for adds in 0..=MAX_ADDS {
        let len = decode(translate, at, code_space, &mut cap)?;
        values.keep_only(&reg);
        if adds > 0 {
            if let Some(slot) = values.load_jump(cap.ops()) {
                roles.push((at, Role::Load(slot)));
                return Some(roles);
            }
        }
        values.add_to(cap.ops(), &reg)?;
        roles.push((at, Role::Partial));
        at = at.wrapping_add(u64::from(len));
    }
    None
}

/// Constant values of registers and temporaries along a chain.
struct Values<'a> {
    data_space: Option<&'a Rc<AddrSpace>>,
    known: HashMap<(usize, u64, u32), u64>,
}

impl<'a> Values<'a> {
    fn new(data_space: Option<&'a Rc<AddrSpace>>) -> Self {
        Values { data_space, known: HashMap::new() }
    }

    /// Forget every value but `reg`'s: temporaries do not outlive their
    /// instruction.
    fn keep_only(&mut self, reg: &VarnodeData) {
        let key = Self::key(reg);
        self.known.retain(|k, _| Some(*k) == key);
    }

    fn key(vn: &VarnodeData) -> Option<(usize, u64, u32)> {
        let space = vn.space.as_ref()?;
        Some((Rc::as_ptr(space) as usize, vn.offset, vn.size))
    }

    fn is_register(&self, vn: &VarnodeData) -> bool {
        let Some(space) = &vn.space else { return false };
        space.get_type() == spacetype::IPTR_PROCESSOR
            && !self.data_space.is_some_and(|data| Rc::ptr_eq(space, data))
    }

    fn value(&self, vn: &VarnodeData) -> Option<u64> {
        let space = vn.space.as_ref()?;
        if space.get_type() == spacetype::IPTR_CONSTANT {
            return Some(vn.offset);
        }
        self.known.get(&Self::key(vn)?).copied()
    }

    /// Evaluate one arithmetic op, recording its output.
    fn eval(&mut self, op: &FullOp) -> Option<()> {
        let out = op.out.as_ref()?;
        let mask = if out.size >= 8 { u64::MAX } else { (1u64 << (out.size * 8)) - 1 };
        let value = match (op.opcode, op.ins.as_slice()) {
            (OpCode::CPUI_COPY, [a]) => self.value(a)?,
            (OpCode::CPUI_INT_ADD, [a, b]) => self.value(a)?.wrapping_add(self.value(b)?),
            (OpCode::CPUI_INT_SUB, [a, b]) => self.value(a)?.wrapping_sub(self.value(b)?),
            _ => return None,
        };
        let key = Self::key(out)?;
        self.known.insert(key, value & mask);
        Some(())
    }

    /// The one register an instruction of only constant arithmetic writes, and
    /// its value, or `None` for any other instruction.
    fn single_write(&mut self, ops: &[FullOp]) -> Option<(VarnodeData, u64)> {
        let mut written = None;
        for op in ops {
            self.eval(op)?;
            let out = op.out.as_ref()?;
            if self.is_register(out) {
                if written.as_ref().is_some_and(|w: &VarnodeData| w != out) {
                    return None;
                }
                written = Some(out.clone());
            }
        }
        let reg = written?;
        let value = self.value(&reg)?;
        Some((reg, value))
    }

    /// Evaluate an instruction that neither touches memory nor branches and
    /// leaves `reg` holding a known value: `add ip,ip,#N` also computes flag
    /// temporaries, which are not followed.
    fn add_to(&mut self, ops: &[FullOp], reg: &VarnodeData) -> Option<()> {
        let mut wrote = false;
        for op in ops {
            if is_memory_or_flow(op.opcode) {
                return None;
            }
            let evaluated = self.eval(op).is_some();
            if op.out.as_ref() == Some(reg) {
                if !evaluated {
                    return None;
                }
                wrote = true;
            }
        }
        wrote.then_some(())
    }

    /// The slot an instruction loads from a known address and then jumps
    /// through, or `None`.
    fn load_jump(&mut self, ops: &[FullOp]) -> Option<u64> {
        if ops.last()?.opcode != OpCode::CPUI_BRANCHIND {
            return None;
        }
        let mut slot = None;
        for op in ops {
            match op.opcode {
                OpCode::CPUI_LOAD => slot = slot.or(self.value(op.ins.get(1)?)),
                OpCode::CPUI_BRANCHIND => {}
                _ => {
                    let _ = self.eval(op);
                }
            }
        }
        slot
    }
}

fn is_memory_or_flow(opcode: OpCode) -> bool {
    matches!(
        opcode,
        OpCode::CPUI_LOAD
            | OpCode::CPUI_STORE
            | OpCode::CPUI_BRANCH
            | OpCode::CPUI_CBRANCH
            | OpCode::CPUI_BRANCHIND
            | OpCode::CPUI_CALL
            | OpCode::CPUI_CALLIND
            | OpCode::CPUI_CALLOTHER
            | OpCode::CPUI_RETURN
    )
}
