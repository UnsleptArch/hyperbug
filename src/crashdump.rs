//! Automatic crash post-mortem capture: on a triple fault, dump full vCPU
//! state plus a short history of recent VM exits to a file, instead of the
//! few registers `eprintln!` used to print. Tier 4 of the external
//! review's roadmap ("Automatic crash/fault post-mortem capture ... dump
//! full state automatically, not just an `eprintln!` of a few registers").
//!
//! The recent-exit ring buffer (`ExitHistory`) is deliberately *always*
//! kept, not just when a crash dump is requested — a fixed-size array of
//! `Copy` structs (no allocation, no formatting) pushed once per VM exit,
//! cheap enough to run unconditionally so a postmortem has real context
//! even on a run that never enabled `--trace-file`. Formatting only
//! happens once, at dump time, on the failure path — never on the hot
//! loop.

use std::collections::VecDeque;
use std::io::Write;

use kvm_bindings::{kvm_regs, kvm_sregs};

/// A cheap, `Copy` summary of one VM exit — enough to reconstruct "what was
/// the guest doing right before this" without the cost of formatting a
/// string (or an extra `KVM_GET_REGS` ioctl, which `VcpuExit`'s own
/// borrow of the vCPU's `kvm_run` page forbids at this point anyway — see
/// `vcpu.rs`'s own comment on why nothing may touch the vCPU while an
/// exit value is alive) on every single exit.
#[derive(Clone, Copy)]
pub struct ExitRecord {
    pub kind: ExitKind,
    pub addr: u64,
}

#[derive(Clone, Copy, Debug)]
pub enum ExitKind {
    IoOut,
    IoIn,
    MmioRead,
    MmioWrite,
    Hlt,
    Other,
}

/// How many recent exits to remember per vCPU — enough to see the
/// instructions leading into a fault without holding more than a tiny,
/// fixed amount of memory for the life of the run.
const HISTORY_LEN: usize = 32;

pub struct ExitHistory {
    records: VecDeque<ExitRecord>,
}

impl ExitHistory {
    pub fn new() -> Self {
        Self { records: VecDeque::with_capacity(HISTORY_LEN) }
    }

    #[inline]
    pub fn push(&mut self, record: ExitRecord) {
        if self.records.len() == HISTORY_LEN {
            self.records.pop_front();
        }
        self.records.push_back(record);
    }

    pub fn iter(&self) -> impl Iterator<Item = &ExitRecord> {
        self.records.iter()
    }
}

impl Default for ExitHistory {
    fn default() -> Self {
        Self::new()
    }
}

/// Writes a crash dump to `<dir>/hyperbug-crash-cpu<cpu_id>-<pid>.json`
/// (`dir` defaults to the current directory when `--crash-dir` wasn't
/// given). Best-effort: a failure to write the dump is logged, not
/// propagated — the run is already ending because of the fault this dump
/// describes, and a second failure here shouldn't mask the first or
/// change the process's exit code.
pub fn write_crash_dump(dir: Option<&str>, cpu_id: u8, reason: &str, regs: &kvm_regs, sregs: &kvm_sregs, history: &ExitHistory) {
    let dir = dir.unwrap_or(".");
    let path = format!("{dir}/hyperbug-crash-cpu{cpu_id}-{}.json", std::process::id());
    match std::fs::File::create(&path) {
        Ok(mut file) => {
            let json = build_dump_json(cpu_id, reason, regs, sregs, history);
            if let Err(e) = file.write_all(json.as_bytes()) {
                crate::log_error!("writing crash dump {path}: {e}");
                return;
            }
            crate::log_error!("crash dump written to {path}");
        }
        Err(e) => crate::log_error!("could not create crash dump {path}: {e}"),
    }
}

fn build_dump_json(cpu_id: u8, reason: &str, r: &kvm_regs, s: &kvm_sregs, history: &ExitHistory) -> String {
    let mut recent = String::from("[");
    for (i, rec) in history.iter().enumerate() {
        if i > 0 {
            recent.push(',');
        }
        recent.push_str(&format!("{{\"kind\":\"{:?}\",\"addr\":\"{:#x}\"}}", rec.kind, rec.addr));
    }
    recent.push(']');

    format!(
        "{{\n\
         \"reason\":{reason:?},\n\
         \"cpu_id\":{cpu_id},\n\
         \"regs\":{{\"rip\":\"{:#x}\",\"rsp\":\"{:#x}\",\"rbp\":\"{:#x}\",\"rflags\":\"{:#x}\",\
         \"rax\":\"{:#x}\",\"rbx\":\"{:#x}\",\"rcx\":\"{:#x}\",\"rdx\":\"{:#x}\",\
         \"rsi\":\"{:#x}\",\"rdi\":\"{:#x}\",\"r8\":\"{:#x}\",\"r9\":\"{:#x}\",\
         \"r10\":\"{:#x}\",\"r11\":\"{:#x}\",\"r12\":\"{:#x}\",\"r13\":\"{:#x}\",\
         \"r14\":\"{:#x}\",\"r15\":\"{:#x}\"}},\n\
         \"sregs\":{{\"cr0\":\"{:#x}\",\"cr2\":\"{:#x}\",\"cr3\":\"{:#x}\",\"cr4\":\"{:#x}\",\
         \"efer\":\"{:#x}\",\"cs_selector\":\"{:#x}\",\"cs_long_mode\":{}}},\n\
         \"recent_exits\":{recent}\n\
         }}\n",
        r.rip, r.rsp, r.rbp, r.rflags, r.rax, r.rbx, r.rcx, r.rdx, r.rsi, r.rdi, r.r8, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15,
        s.cr0, s.cr2, s.cr3, s.cr4, s.efer, s.cs.selector, s.cs.l != 0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_keeps_only_the_most_recent_entries() {
        let mut h = ExitHistory::new();
        for i in 0..(HISTORY_LEN as u64 + 5) {
            h.push(ExitRecord { kind: ExitKind::Hlt, addr: i });
        }
        let addrs: Vec<u64> = h.iter().map(|r| r.addr).collect();
        assert_eq!(addrs.len(), HISTORY_LEN);
        assert_eq!(addrs[0], 5, "the oldest 5 entries should have been evicted");
        assert_eq!(*addrs.last().unwrap(), HISTORY_LEN as u64 + 4);
    }

    #[test]
    fn a_crash_dump_is_written_as_valid_looking_json_with_the_recent_history() {
        let dir = std::env::temp_dir();
        let dir_str = dir.to_str().unwrap();
        let mut history = ExitHistory::new();
        history.push(ExitRecord { kind: ExitKind::IoOut, addr: 0x3f8 });
        let regs = kvm_regs { rip: 0xdead_beef, ..Default::default() };
        let sregs = kvm_sregs::default();
        write_crash_dump(Some(dir_str), 0, "TripleFault", &regs, &sregs, &history);
        let path = format!("{dir_str}/hyperbug-crash-cpu0-{}.json", std::process::id());
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("0xdeadbeef"), "got: {contents}");
        assert!(contents.contains("TripleFault"));
        assert!(contents.contains("0x3f8"), "the recent-exit history should be included");
        std::fs::remove_file(&path).unwrap();
    }
}
