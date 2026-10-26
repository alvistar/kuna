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
//!
//! The chain is followed in the walk's own order: each instruction is the one
//! the walk decoded, in the mode it chose, and a chain waits for the walk to
//! decode the instruction at its fall-through. The constant rows of a chain
//! still open are held back, and filed as they were when it breaks or when the
//! body drains with it open.

use std::collections::HashMap;
use std::rc::Rc;

use kuna_base::space::{spacetype, AddrSpace};
use kuna_num::opcodes::OpCode;
use kuna_num::pcoderaw::VarnodeData;

use super::xrefs::{FullOp, XrefKind};

/// The most constant adds a chain may take before its load: one in the
/// standard entry, two with `--long-plt`.
const MAX_ADDS: usize = 2;

/// A constant row held back: `(from, to, instruction text)`.
pub(super) type Held = (u64, u64, String);

/// A chain the walk is following.
struct Chain {
    /// The register the chain builds the address in, and its value.
    reg: VarnodeData,
    value: u64,
    /// The constant adds taken so far.
    adds: usize,
    held: Vec<Held>,
}

/// The chains one body's walk has open, keyed by the VMA of the instruction
/// each expects next.
pub(super) struct PltStubs<'a> {
    data_space: Option<&'a Rc<AddrSpace>>,
    open: HashMap<u64, Chain>,
}

impl<'a> PltStubs<'a> {
    pub(super) fn new(data_space: Option<&'a Rc<AddrSpace>>) -> Self {
        PltStubs { data_space, open: HashMap::new() }
    }

    /// Take the instruction at `vma` (`len` bytes, lifted to `ops`, rendered
    /// `text`) as the walk decodes it: continue the chain that expects it, or
    /// start one. A chain's constant rows leave `drefs` while it is open, and
    /// the load that ends it gets its slot as a `Read`. Returns the rows of
    /// the chains this instruction broke, to file as they were.
    pub(super) fn step(
        &mut self,
        vma: u64,
        len: u32,
        ops: &[FullOp],
        drefs: &mut Vec<(u64, XrefKind)>,
        text: &str,
    ) -> Vec<Held> {
        let next = vma.wrapping_add(u64::from(len));
        let mut released = Vec::new();
        if let Some(mut chain) = self.open.remove(&vma) {
            let mut values = Values::holding(self.data_space, &chain);
            if chain.adds > 0 {
                if let Some(slot) = values.load_jump(ops) {
                    drefs.retain(|&(_, kind)| kind != XrefKind::Data);
                    if !drefs.contains(&(slot, XrefKind::Read)) {
                        drefs.push((slot, XrefKind::Read));
                    }
                    return released;
                }
            }
            if chain.adds < MAX_ADDS {
                if let Some(value) = values.add_to(ops, &chain.reg) {
                    chain.value = value;
                    chain.adds += 1;
                    hold(&mut chain.held, vma, drefs, text);
                    released.extend(self.open.insert(next, chain).into_iter().flat_map(|c| c.held));
                    return released;
                }
            }
            released = chain.held;
        }
        if drefs.iter().any(|&(_, kind)| kind == XrefKind::Data) {
            if let Some((reg, value)) = Values::new(self.data_space).single_write(ops) {
                let mut chain = Chain { reg, value, adds: 0, held: Vec::new() };
                hold(&mut chain.held, vma, drefs, text);
                released.extend(self.open.insert(next, chain).into_iter().flat_map(|c| c.held));
            }
        }
        released
    }

    /// The rows of every chain still open when the body drains, to file as
    /// they were.
    pub(super) fn drain(&mut self) -> Vec<Held> {
        self.open.drain().flat_map(|(_, chain)| chain.held).collect()
    }
}

/// Move the constant rows of the instruction at `vma` out of `drefs`.
fn hold(held: &mut Vec<Held>, vma: u64, drefs: &mut Vec<(u64, XrefKind)>, text: &str) {
    drefs.retain(|&(to, kind)| {
        if kind == XrefKind::Data {
            held.push((vma, to, text.to_string()));
        }
        kind != XrefKind::Data
    });
}

/// Constant values of registers and temporaries in one instruction.
struct Values<'a> {
    data_space: Option<&'a Rc<AddrSpace>>,
    known: HashMap<(usize, u64, u32), u64>,
}

impl<'a> Values<'a> {
    fn new(data_space: Option<&'a Rc<AddrSpace>>) -> Self {
        Values { data_space, known: HashMap::new() }
    }

    /// The values at the start of an instruction a chain reaches: only its
    /// register's.
    fn holding(data_space: Option<&'a Rc<AddrSpace>>, chain: &Chain) -> Self {
        let mut values = Self::new(data_space);
        if let Some(key) = Self::key(&chain.reg) {
            values.known.insert(key, chain.value);
        }
        values
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
    /// leaves `reg` holding a known value, which it returns: `add ip,ip,#N`
    /// also computes flag temporaries, which are not followed.
    fn add_to(&mut self, ops: &[FullOp], reg: &VarnodeData) -> Option<u64> {
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
        if wrote { self.value(reg) } else { None }
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
