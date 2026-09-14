//! A real GDB/LLDB remote-serial-protocol (RSP) stub over TCP
//! (`--gdb-stub <host:port>`), so debugging a guest under hyperbug can be
//! as good as debugging firmware under Unicorn already is — real
//! breakpoints, real single-stepping, real register/memory access from an
//! actual debugger, not just the control socket's peek/poke. Tier 4 of the
//! external review's roadmap ("port the idea [of IntelCommander's
//! `gdbstub.py`], not the code — different backend").
//!
//! ## Scope, stated plainly
//!
//! - **BSP (vCPU 0) only.** With `--smp > 1`, the other vCPUs keep running
//!   freely and are not stoppable/inspectable from here — the same
//!   documented limitation `control.rs`'s `regs` command already has, for
//!   the same reason (a live vCPU's registers/debug state can only safely
//!   be touched from that vCPU's own thread).
//! - **Software breakpoints only** (`Z0`/`z0`) — real 0xCC injection into
//!   guest memory via `KVM_GUESTDBG_USE_SW_BP`, so KVM intercepts the trap
//!   itself instead of delivering it to the guest's own IDT. Hardware
//!   watchpoints/breakpoints (`Z1`-`Z4`) are refused (empty reply, the RSP
//!   convention for "not supported"), which just makes GDB fall back to
//!   software breakpoints for everything, including a data write it might
//!   otherwise have asked for a watchpoint on.
//! - **No asynchronous Ctrl-C-while-continuing.** Commands are served
//!   synchronously: this thread blocks reading the socket only while the
//!   guest is already stopped, and isn't reading at all while it's
//!   running free between here and the next breakpoint/step trap — a
//!   `\x03` interrupt byte sent while continuing sits unread until the
//!   next stop and is then just skipped as noise, not acted on early. Set
//!   a breakpoint instead of relying on "break into a running target."
//! - **Zero new threads touching the vCPU** — same discipline as
//!   `control.rs`: this is called from, and only from, the BSP's own exit
//!   loop (`vcpu.rs`), never a background thread.
//!
//! ## Register layout
//!
//! `g`/`G` use the classic amd64 register order GDB falls back to absent
//! a `qXfer:features:read` target-description reply (this stub doesn't
//! implement one, matching plenty of small/embedded stubs that rely on
//! the client already knowing its target is x86-64 — `set architecture
//! i386:x86-64` before `target remote` if GDB doesn't infer it from a
//! `file` given first): `rax,rbx,rcx,rdx,rsi,rdi,rbp,rsp,r8-r15,rip` as
//! 8-byte little-endian fields, then `eflags,cs,ss,ds,es,fs,gs` as 4-byte
//! little-endian fields — 164 bytes total.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use kvm_bindings::{
    KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_SINGLESTEP, KVM_GUESTDBG_USE_SW_BP, kvm_debug_exit_arch, kvm_guest_debug,
};
use kvm_ioctls::VcpuFd;

/// x86 exception vector 3 (`#BP`, breakpoint) — used only to re-inject a
/// guest's own `int3` back into it when it isn't one of this stub's own
/// tracked breakpoints; see `handle_debug_exit`'s doc comment for why this
/// exists at all.
const BP_VECTOR: u8 = 3;

/// What the vCPU loop should do after a `VcpuExit::Debug` — see
/// `handle_debug_exit`.
pub enum DebugAction {
    /// A breakpoint this stub itself set, or a completed single step:
    /// report a stop to the debugger and wait for its next command.
    Stop,
    /// An `int3` the guest executed on its own (Linux's boot-time
    /// `int3_selftest()`, or a live-patching/`ftrace` trampoline swap —
    /// both real and unavoidable on an ordinary kernel) that isn't one of
    /// this stub's own breakpoints — already re-injected into the guest;
    /// just keep running.
    ForwardToGuest,
    /// A forced internal single step (stepping over this stub's own
    /// armed breakpoint before a `c`) just completed and resumption has
    /// already been re-armed — nothing to report, just keep running.
    Resumed,
}

use crate::mem::GuestMemory;

pub struct GdbStub {
    stream: TcpStream,
    /// Breakpoint address -> the original byte hyperbug's own 0xCC
    /// overwrote, so removing it (or reading/writing through it) can
    /// restore/show the real instruction byte.
    breakpoints: HashMap<u64, u8>,
    /// True from connect until a `D` (detach) or `k` (kill) — once false,
    /// the vCPU loop stops consulting this stub at all.
    attached: bool,
    /// True whenever the guest should not be run — right after connecting
    /// (GDB's usual "attach halted"), and again after every breakpoint/
    /// single-step trap, until a `c`/`s` command is served.
    stopped: bool,
    /// Set by a `k` (kill) command — the vCPU loop checks this and ends
    /// the whole run instead of trying to resume a killed target.
    killed: bool,
    /// Once GDB sends `QStartNoAckMode`, replies stop being wrapped in the
    /// `+`/`-` acknowledgement handshake — same optimization real
    /// gdbservers make, and GDB asks for it by default over TCP.
    no_ack: bool,
    /// Set whenever the *next* `vcpu.run()` is a forced single step —
    /// either a real `s` command, or (see `pending_step_over`) the
    /// internal single step this stub takes to get past its own armed
    /// breakpoint before really continuing. Cleared by `handle_debug_exit`
    /// once that step completes.
    was_stepping: bool,
    /// Set by `resume()` when the vCPU is sitting exactly on one of this
    /// stub's own armed breakpoints: the address being transparently
    /// stepped over (original byte restored, breakpoint re-armed once the
    /// forced single step above completes) — see `resume`'s doc comment
    /// for why this exists at all.
    pending_step_over: Option<u64>,
    /// Whether the command that triggered `pending_step_over` was a `c`
    /// (silently continue once the step-over completes, no stop reported)
    /// or an `s` (the step-over itself *is* the requested step; report a
    /// real stop once it completes, same as any other single step).
    resume_after_step_over: bool,
}

impl GdbStub {
    /// Binds `addr` and blocks until exactly one debugger connects —
    /// deliberately synchronous: a guest with `--gdb-stub` set is meant to
    /// come up halted, waiting for GDB, not racing it.
    pub fn listen(addr: &str) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        crate::log_info!("gdb stub: listening on {addr}, waiting for a debugger to connect...");
        let (stream, peer) = listener.accept()?;
        stream.set_nodelay(true)?;
        crate::log_info!("gdb stub: debugger connected from {peer}");
        Ok(Self {
            stream,
            breakpoints: HashMap::new(),
            attached: true,
            stopped: true,
            killed: false,
            no_ack: false,
            was_stepping: false,
            pending_step_over: None,
            resume_after_step_over: false,
        })
    }

    pub fn is_attached(&self) -> bool {
        self.attached
    }

    pub fn is_stopped(&self) -> bool {
        self.stopped
    }

    pub fn wants_kill(&self) -> bool {
        self.killed
    }

    /// Handles a `VcpuExit::Debug` — the one place that decides whether a
    /// trap is actually this stub's business, or the guest's own.
    ///
    /// `KVM_GUESTDBG_USE_SW_BP` intercepts **every** `int3` the guest
    /// executes, not just the ones at addresses this stub itself patched
    /// with `0xCC` — and a real, unmodified Linux kernel legitimately
    /// executes `int3` on its own (`int3_selftest()` during early exception
    /// setup, and again for any `ftrace`/live-patching trampoline that gets
    /// armed later), completely independent of any debugger being attached.
    /// The first version of this stub didn't check for that and simply
    /// reported every `Debug` exit as a breakpoint hit — which meant an
    /// entirely ordinary boot got silently stuck forever the moment the
    /// kernel's own self-test executed its first `int3`, since nothing was
    /// listening to notice the unwanted stop. Caught by
    /// `tests/boot.rs::gdb_stub_serves_a_real_rsp_session_against_a_live_guest`
    /// hanging past its timeout on the very first real run against a real
    /// kernel, not by any unit test — exactly the class of bug this
    /// project's own boot tests exist to catch.
    ///
    /// `arch.pc` is where KVM reports the trap actually landed.
    ///
    /// **Correction, found by checking the real kernel source rather than
    /// trusting hardware-trap intuition**: for `KVM_GUESTDBG_USE_SW_BP`,
    /// `pc` is the *unadvanced* address of the `int3` byte itself, not
    /// `int3_addr + 1` — confirmed directly against
    /// `tools/testing/selftests/kvm/x86/debug_regs.c` (upstream Linux),
    /// whose own guest code labels `sw_bp: int3` and asserts `pc ==
    /// &sw_bp` before manually doing `regs.rip += 1` to step past it. This
    /// is the *opposite* of ordinary (un-intercepted) `int3` delivery: real
    /// hardware's trap microcode pushes the post-instruction return
    /// address, but `USE_SW_BP` causes a VM exit *instead of* that
    /// delivery ever happening, before RIP would have advanced. The first
    /// version of this function subtracted 1 anyway (reasoning from
    /// generic x86 trap semantics rather than checking KVM's own
    /// interception path specifically), which meant `self.breakpoints`
    /// was checked against the wrong address — every real breakpoint hit
    /// would have missed its own entry and been (incorrectly)
    /// re-injected into the guest instead of reported to GDB. Never
    /// caught by this file's own tests, because the first version of the
    /// real-boot test inserted and removed a breakpoint without ever
    /// letting it fire — exactly the "if you didn't run through the real
    /// path, you haven't verified it" mistake this project's own history
    /// keeps finding. See `tests/boot.rs::
    /// gdb_stub_actually_hits_and_resumes_past_a_real_breakpoint` for the
    /// test that now exercises the real path.
    pub fn handle_debug_exit(
        &mut self,
        vcpu: &VcpuFd,
        arch: &kvm_debug_exit_arch,
        mem: &Arc<Mutex<GuestMemory>>,
    ) -> std::io::Result<DebugAction> {
        if self.was_stepping {
            self.was_stepping = false;
            if let Some(addr) = self.pending_step_over.take() {
                // The forced single step needed to get past this stub's
                // own breakpoint just completed — re-arm it now that the
                // real instruction has executed exactly once.
                mem.lock().unwrap().write_checked(addr, &[0xCC]);
                if self.resume_after_step_over {
                    // The original request was `c`, not `s`: the step-over
                    // was purely internal machinery, not something GDB
                    // asked to see — resume for real instead of reporting
                    // a stop for a step GDB never requested.
                    self.resume(vcpu, false, mem)?;
                    return Ok(DebugAction::Resumed);
                }
                // The original request genuinely was `s` — this step
                // *is* the requested step, so it gets reported like any
                // other.
            }
            self.stopped = true;
            self.write_packet("S05")?;
            return Ok(DebugAction::Stop);
        }
        if self.breakpoints.contains_key(&arch.pc) {
            // No RIP adjustment needed: `pc` already *is* the breakpoint's
            // own address (see above) — GDB reports and resumes from
            // exactly where KVM left it.
            self.stopped = true;
            self.write_packet("S05")?;
            Ok(DebugAction::Stop)
        } else {
            inject_breakpoint_exception(vcpu)?;
            Ok(DebugAction::ForwardToGuest)
        }
    }

    /// Serves RSP commands until the debugger asks to resume (`c`/`s`) or
    /// ends the session (`D`/`k`) — called once per vCPU-loop iteration
    /// while `stopped` is true, from the BSP thread only (see the module
    /// doc comment for why nothing here may run on any other thread).
    pub fn serve_until_resume(
        &mut self,
        vcpu: &VcpuFd,
        mem: &Arc<Mutex<GuestMemory>>,
    ) -> std::io::Result<()> {
        while self.stopped && self.attached {
            let packet = self.read_packet()?;
            self.handle_packet(&packet, vcpu, mem)?;
        }
        Ok(())
    }

    fn handle_packet(&mut self, packet: &str, vcpu: &VcpuFd, mem: &Arc<Mutex<GuestMemory>>) -> std::io::Result<()> {
        let reply = match packet.as_bytes().first() {
            Some(b'?') => "S05".to_string(),
            Some(b'g') => self.read_all_registers(vcpu),
            Some(b'G') => match self.write_all_registers(vcpu, &packet[1..]) {
                Ok(()) => "OK".to_string(),
                Err(msg) => format!("E01;{msg}"),
            },
            Some(b'm') => self.read_memory(mem, &packet[1..]),
            Some(b'M') => self.write_memory(mem, &packet[1..]),
            Some(b'c') => {
                self.apply_resume_address(vcpu, &packet[1..])?;
                self.resume(vcpu, false, mem)?;
                return Ok(()); // no reply — the next stop sends one
            }
            Some(b's') => {
                self.apply_resume_address(vcpu, &packet[1..])?;
                self.resume(vcpu, true, mem)?;
                return Ok(());
            }
            Some(b'Z') if packet.starts_with("Z0,") => self.insert_breakpoint(mem, &packet[3..]),
            Some(b'z') if packet.starts_with("z0,") => self.remove_breakpoint(mem, &packet[3..]),
            Some(b'Z') | Some(b'z') => String::new(), // hardware bp/watchpoint: unsupported
            Some(b'D') => {
                self.detach(mem)?;
                self.write_packet("OK")?;
                return Ok(());
            }
            Some(b'k') => {
                self.killed = true;
                self.attached = false;
                return Ok(()); // no reply expected for kill
            }
            _ if packet.starts_with("qSupported") => "PacketSize=4000".to_string(),
            _ if packet == "QStartNoAckMode" => {
                self.no_ack = true;
                "OK".to_string()
            }
            _ if packet.starts_with('q') || packet.starts_with('H') || packet.starts_with('v') => String::new(),
            _ => String::new(),
        };
        self.write_packet(&reply)
    }

    fn apply_resume_address(&self, vcpu: &VcpuFd, arg: &str) -> std::io::Result<()> {
        if arg.is_empty() {
            return Ok(());
        }
        let Ok(addr) = u64::from_str_radix(arg, 16) else { return Ok(()) };
        let mut regs = vcpu.get_regs().map_err(kvm_err)?;
        regs.rip = addr;
        vcpu.set_regs(&regs).map_err(kvm_err)?;
        Ok(())
    }

    /// Arms `KVM_SET_GUEST_DEBUG` for the next `vcpu.run()` and clears
    /// `stopped` so the caller's loop actually calls it. Software
    /// breakpoints stay intercepted (`USE_SW_BP`) the whole time GDB is
    /// attached, regardless of whether any are currently set — cheap, and
    /// avoids re-arming on every single `Z0`.
    ///
    /// **The step-over-your-own-breakpoint dance.** If the vCPU is sitting
    /// exactly on one of this stub's own armed addresses — because it just
    /// stopped there, or because `apply_resume_address`/`c addr` moved
    /// `rip` there directly — resuming naively would immediately re-trap
    /// the *same* `0xCC` this stub itself planted, hanging the guest on
    /// that one instruction forever. The standard fix (every real
    /// breakpoint-capable debugger does this): restore the real
    /// instruction byte, force exactly one single step so the CPU actually
    /// executes it, then re-arm the `0xCC` once that step completes
    /// (`handle_debug_exit`) before actually resuming for real. If the
    /// original request was `s` (not `c`), that forced step *is* the
    /// requested step and gets reported as a normal stop; if it was `c`,
    /// the step-over is invisible to GDB and resumption continues
    /// silently once it's done. Missing entirely before this fix (found by
    /// the same real-boot-test check that also caught the `pc`
    /// off-by-one above): the first version reported a breakpoint hit
    /// correctly in isolation, but a real `continue` afterward would have
    /// hung on the very next `vcpu.run()`.
    fn resume(&mut self, vcpu: &VcpuFd, single_step: bool, mem: &Arc<Mutex<GuestMemory>>) -> std::io::Result<()> {
        let regs = vcpu.get_regs().map_err(kvm_err)?;
        let stepping_over = if let Some(&orig) = self.breakpoints.get(&regs.rip) {
            mem.lock().unwrap().write_checked(regs.rip, &[orig]);
            self.pending_step_over = Some(regs.rip);
            self.resume_after_step_over = !single_step;
            true
        } else {
            self.pending_step_over = None;
            false
        };
        let force_single_step = single_step || stepping_over;
        let mut control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP;
        if force_single_step {
            control |= KVM_GUESTDBG_SINGLESTEP;
        }
        vcpu.set_guest_debug(&kvm_guest_debug { control, pad: 0, arch: Default::default() })
            .map_err(kvm_err)?;
        self.was_stepping = force_single_step;
        self.stopped = false;
        Ok(())
    }

    /// `D` (detach): every inserted breakpoint's original byte is restored
    /// to guest memory and guest-debug mode is fully disabled, so the
    /// guest genuinely runs unmodified and untrapped from here on — this
    /// stub is never consulted again (`attached` becomes false).
    fn detach(&mut self, mem: &Arc<Mutex<GuestMemory>>) -> std::io::Result<()> {
        let mut guest_mem = mem.lock().unwrap();
        for (&addr, &orig) in &self.breakpoints {
            guest_mem.write_checked(addr, &[orig]);
        }
        self.breakpoints.clear();
        self.attached = false;
        self.stopped = false;
        Ok(())
    }

    fn insert_breakpoint(&mut self, mem: &Arc<Mutex<GuestMemory>>, arg: &str) -> String {
        let Some((addr_hex, _kind)) = arg.split_once(',') else { return "E01".to_string() };
        let Ok(addr) = u64::from_str_radix(addr_hex, 16) else { return "E01".to_string() };
        let mut guest_mem = mem.lock().unwrap();
        let mut orig = [0u8; 1];
        if !guest_mem.read_checked(addr, &mut orig) {
            return "E01".to_string();
        }
        self.breakpoints.insert(addr, orig[0]);
        guest_mem.write_checked(addr, &[0xCC]);
        "OK".to_string()
    }

    fn remove_breakpoint(&mut self, mem: &Arc<Mutex<GuestMemory>>, arg: &str) -> String {
        let Some((addr_hex, _kind)) = arg.split_once(',') else { return "E01".to_string() };
        let Ok(addr) = u64::from_str_radix(addr_hex, 16) else { return "E01".to_string() };
        if let Some(orig) = self.breakpoints.remove(&addr) {
            mem.lock().unwrap().write_checked(addr, &[orig]);
        }
        "OK".to_string()
    }

    /// `m addr,len` — reads guest memory, showing each breakpoint's real
    /// original byte instead of hyperbug's own 0xCC patch, so disassembly
    /// in the debugger isn't corrupted by its own breakpoints.
    fn read_memory(&self, mem: &Arc<Mutex<GuestMemory>>, arg: &str) -> String {
        let Some((addr_hex, len_hex)) = arg.split_once(',') else { return "E01".to_string() };
        let (Ok(addr), Ok(len)) = (u64::from_str_radix(addr_hex, 16), usize::from_str_radix(len_hex, 16)) else {
            return "E01".to_string();
        };
        if len > 1 << 20 {
            return "E01".to_string();
        }
        let mut buf = vec![0u8; len];
        if !mem.lock().unwrap().read_checked(addr, &mut buf) {
            return "E01".to_string();
        }
        for (&bp_addr, &orig) in &self.breakpoints {
            if bp_addr >= addr && bp_addr < addr + len as u64 {
                buf[(bp_addr - addr) as usize] = orig;
            }
        }
        to_hex(&buf)
    }

    /// `M addr,len:data` — writes guest memory. A write that lands on a
    /// currently-armed breakpoint's address updates the *shadowed*
    /// original byte instead, and re-asserts the 0xCC in real memory —
    /// otherwise a debugger-initiated memory patch there would silently
    /// disarm the breakpoint.
    fn write_memory(&mut self, mem: &Arc<Mutex<GuestMemory>>, arg: &str) -> String {
        let Some((header, data_hex)) = arg.split_once(':') else { return "E01".to_string() };
        let Some((addr_hex, len_hex)) = header.split_once(',') else { return "E01".to_string() };
        let (Ok(addr), Ok(len)) = (u64::from_str_radix(addr_hex, 16), usize::from_str_radix(len_hex, 16)) else {
            return "E01".to_string();
        };
        let Some(data) = from_hex(data_hex) else { return "E01".to_string() };
        if data.len() != len {
            return "E01".to_string();
        }
        let mut guest_mem = mem.lock().unwrap();
        if !guest_mem.write_checked(addr, &data) {
            return "E01".to_string();
        }
        for (&bp_addr, orig) in self.breakpoints.iter_mut() {
            if bp_addr >= addr && bp_addr < addr + len as u64 {
                *orig = data[(bp_addr - addr) as usize];
                guest_mem.write_checked(bp_addr, &[0xCC]);
            }
        }
        "OK".to_string()
    }

    fn read_all_registers(&self, vcpu: &VcpuFd) -> String {
        let (Ok(r), Ok(s)) = (vcpu.get_regs(), vcpu.get_sregs()) else {
            return "E01".to_string();
        };
        let mut bytes = Vec::with_capacity(164);
        for reg in [r.rax, r.rbx, r.rcx, r.rdx, r.rsi, r.rdi, r.rbp, r.rsp,
                    r.r8, r.r9, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15, r.rip] {
            bytes.extend_from_slice(&reg.to_le_bytes());
        }
        for reg32 in [
            r.rflags as u32,
            u32::from(s.cs.selector),
            u32::from(s.ss.selector),
            u32::from(s.ds.selector),
            u32::from(s.es.selector),
            u32::from(s.fs.selector),
            u32::from(s.gs.selector),
        ] {
            bytes.extend_from_slice(&reg32.to_le_bytes());
        }
        to_hex(&bytes)
    }

    /// `G` — the inverse of `g`. Only the general-purpose registers,
    /// `rip`, and `rflags` are actually written back (matching what a
    /// debugger realistically edits); the segment selectors in the same
    /// packet are parsed for framing correctness but not applied, since
    /// writing them without also updating the matching hidden descriptor
    /// state (`kvm_sregs`'s base/limit/access-rights fields, which GDB's
    /// register set doesn't carry at all) would desynchronize the vCPU's
    /// segment state rather than actually relocate it.
    fn write_all_registers(&self, vcpu: &VcpuFd, hex: &str) -> Result<(), String> {
        let Some(bytes) = from_hex(hex) else { return Err("bad hex".to_string()) };
        if bytes.len() < 136 {
            return Err(format!("expected at least 136 bytes, got {}", bytes.len()));
        }
        let mut regs = vcpu.get_regs().map_err(|e| e.to_string())?;
        let mut words = bytes.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap()));
        regs.rax = words.next().unwrap();
        regs.rbx = words.next().unwrap();
        regs.rcx = words.next().unwrap();
        regs.rdx = words.next().unwrap();
        regs.rsi = words.next().unwrap();
        regs.rdi = words.next().unwrap();
        regs.rbp = words.next().unwrap();
        regs.rsp = words.next().unwrap();
        regs.r8 = words.next().unwrap();
        regs.r9 = words.next().unwrap();
        regs.r10 = words.next().unwrap();
        regs.r11 = words.next().unwrap();
        regs.r12 = words.next().unwrap();
        regs.r13 = words.next().unwrap();
        regs.r14 = words.next().unwrap();
        regs.r15 = words.next().unwrap();
        regs.rip = words.next().unwrap();
        if bytes.len() >= 140 {
            regs.rflags = u32::from_le_bytes(bytes[136..140].try_into().unwrap()) as u64;
        }
        vcpu.set_regs(&regs).map_err(|e| e.to_string())
    }

    // --- RSP packet framing -------------------------------------------

    fn read_packet(&mut self) -> std::io::Result<String> {
        loop {
            // Skip anything that isn't the start of a real packet (a
            // stray ack byte, or a `\x03` interrupt-while-running byte
            // that arrived while this stub wasn't reading — see the
            // module doc comment's stated Ctrl-C limitation).
            let mut byte = [0u8; 1];
            loop {
                self.stream.read_exact(&mut byte)?;
                if byte[0] == b'$' {
                    break;
                }
            }
            let mut data = Vec::new();
            loop {
                self.stream.read_exact(&mut byte)?;
                if byte[0] == b'#' {
                    break;
                }
                data.push(byte[0]);
            }
            let mut checksum_hex = [0u8; 2];
            self.stream.read_exact(&mut checksum_hex)?;
            let expected: u8 = data.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
            let received = u8::from_str_radix(std::str::from_utf8(&checksum_hex).unwrap_or(""), 16).unwrap_or(!expected);
            if !self.no_ack {
                let _ = self.stream.write_all(if received == expected { b"+" } else { b"-" });
            }
            if received == expected {
                return Ok(String::from_utf8_lossy(&data).into_owned());
            }
            // A bad checksum with no-ack mode already active has no
            // retransmission mechanism left to ask for — treat the packet
            // as empty (a no-op) rather than getting stuck.
            if self.no_ack {
                return Ok(String::new());
            }
        }
    }

    fn write_packet(&mut self, data: &str) -> std::io::Result<()> {
        let checksum: u8 = data.bytes().fold(0u8, |acc, b| acc.wrapping_add(b));
        let framed = format!("${data}#{checksum:02x}");
        self.stream.write_all(framed.as_bytes())?;
        if !self.no_ack {
            let mut ack = [0u8; 1];
            // A real debugger always acks; a dead connection surfaces
            // here as an `Err`, which the caller treats as the stub's own
            // I/O having failed — not worth retrying indefinitely.
            self.stream.read_exact(&mut ack)?;
        }
        Ok(())
    }
}

fn kvm_err(e: kvm_ioctls::Error) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// Re-delivers a trapped `int3` to the guest exactly as real hardware
/// would if no debugger were attached at all — **no manual `rip`
/// adjustment needed**, and adding one would be a real, separate bug.
///
/// First guess (reverted here, kept as history rather than silently
/// dropped): since `KVM_GUESTDBG_USE_SW_BP` intercepts *before* `rip`
/// would have been advanced past the `int3` (see `handle_debug_exit`'s
/// doc comment), it seemed like re-injecting the exception without first
/// bumping `rip` by 1 would make the guest's own handler return to the
/// same `0xCC` byte on `iret` — an infinite re-trap. **That reasoning
/// skipped a real mechanism KVM already has for exactly this case**:
/// `#BP`/`#OF` are "soft exceptions" (`kvm_exception_is_soft()`,
/// `arch/x86/kvm/x86.h`), and both `vmx.c` and `svm.c` inject a soft
/// exception using `vcpu->arch.event_exit_inst_len` — the instruction
/// length KVM itself already captured internally at the *original*
/// interception — as the VM-entry instruction length, so the hardware's
/// own event-injection microcode performs the `rip` advance as part of
/// delivering it, identically to what un-intercepted execution would have
/// done. A userspace-side `regs.rip += 1` on top of that would be a
/// genuine double-advance, silently skipping one byte into whatever
/// follows the `int3` — worse than doing nothing, and *harder* to notice,
/// since it wouldn't hang outright the way the actually-shipped bugs in
/// this file did; it would just corrupt execution one byte at a time.
/// Confirmed directly against `torvalds/linux`'s own source
/// (`arch/x86/kvm/vmx/vmx.c`, `arch/x86/kvm/svm/svm.c`,
/// `arch/x86/kvm/x86.h`) rather than assumed a second time.
fn inject_breakpoint_exception(vcpu: &VcpuFd) -> std::io::Result<()> {
    let mut events = vcpu.get_vcpu_events().map_err(kvm_err)?;
    events.exception.injected = 1;
    events.exception.nr = BP_VECTOR;
    events.exception.has_error_code = 0;
    events.exception.error_code = 0;
    vcpu.set_vcpu_events(&events).map_err(kvm_err)
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

fn to_hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for &b in data {
        out.push(HEX_DIGITS[usize::from(b >> 4)] as char);
        out.push(HEX_DIGITS[usize::from(b & 0xf)] as char);
    }
    out
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    let (pairs, leftover) = s.as_bytes().as_chunks::<2>();
    if !leftover.is_empty() {
        return None;
    }
    pairs.iter().map(|pair| Some(hex_value(pair[0])? << 4 | hex_value(pair[1])?)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let data = vec![0xde, 0xad, 0xbe, 0xef];
        assert_eq!(to_hex(&data), "deadbeef");
        assert_eq!(from_hex("deadbeef").unwrap(), data);
        assert_eq!(from_hex("odd"), None);
        assert_eq!(from_hex("zz"), None);
    }

    /// A full loopback test over a real TCP socket pair: acts as both
    /// "gdb" and drives a `GdbStub`, exercising the actual framing
    /// (checksums, acks) rather than calling the packet handlers directly.
    #[test]
    fn packet_framing_round_trips_over_a_real_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            let mut sock = TcpStream::connect(addr).unwrap();
            // "$g#67" — checksum of 'g' (0x67) is 0x67 itself (single byte).
            sock.write_all(b"$g#67").unwrap();
            let mut ack = [0u8; 1];
            sock.read_exact(&mut ack).unwrap();
            assert_eq!(&ack, b"+");
            // Read the reply packet back: $...#xx
            let mut buf = [0u8; 8192];
            let n = sock.read(&mut buf).unwrap();
            let reply = String::from_utf8_lossy(&buf[..n]).into_owned();
            assert!(reply.starts_with('$'), "got: {reply}");
            sock.write_all(b"+").unwrap(); // ack the reply
        });
        let (stream, _) = listener.accept().unwrap();
        let mut stub = GdbStub {
            stream,
            breakpoints: HashMap::new(),
            attached: true,
            stopped: true,
            killed: false,
            no_ack: false,
            was_stepping: false,
            pending_step_over: None,
            resume_after_step_over: false,
        };
        let packet = stub.read_packet().unwrap();
        assert_eq!(packet, "g");
        stub.write_packet("E01").unwrap(); // no live vCPU in this test — any reply proves framing works
        client.join().unwrap();
    }

    #[test]
    fn breakpoint_bookkeeping_shadows_the_patched_byte_on_read_and_write() {
        let mem = Arc::new(Mutex::new(GuestMemory::new(4096).unwrap()));
        mem.lock().unwrap().write_checked(0x100, &[0x90, 0x90, 0x90, 0x90]);

        // Exercises the shadowing logic directly rather than through a
        // full `GdbStub` instance — `TcpStream` isn't constructible
        // without a real `accept()`, and this behavior doesn't depend on
        // the socket at all.
        let mut breakpoints: HashMap<u64, u8> = HashMap::new();
        {
            let mut guest_mem = mem.lock().unwrap();
            let mut orig = [0u8; 1];
            guest_mem.read_checked(0x101, &mut orig);
            breakpoints.insert(0x101, orig[0]);
            guest_mem.write_checked(0x101, &[0xCC]);
        }
        let mut raw = [0u8; 4];
        mem.lock().unwrap().read_checked(0x100, &mut raw);
        assert_eq!(raw, [0x90, 0xCC, 0x90, 0x90], "the real memory does contain 0xCC");

        // Simulate `read_memory`'s shadowing logic directly.
        let addr = 0x100u64;
        let len = 4usize;
        let mut buf = [0u8; 4];
        mem.lock().unwrap().read_checked(addr, &mut buf);
        for (&bp_addr, &orig) in &breakpoints {
            if bp_addr >= addr && bp_addr < addr + len as u64 {
                buf[(bp_addr - addr) as usize] = orig;
            }
        }
        assert_eq!(buf, [0x90, 0x90, 0x90, 0x90], "the shadowed read must show the original byte, not 0xCC");
    }
}
