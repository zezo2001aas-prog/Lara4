//
  //  OmegaExtendedI.swift
  //  lara — Process Explorer
  //  task-info, ucred-info, vmmap-k
  //
  //  CRASH-FIX (ucred-info respring):
  //
  //  Bug 1 — _findProcI zero-offset false match:
  //    If off_proc_p_pid == 0 (before offsets_init runs), pidOff = 0.
  //    ds_kread32(ptr + 0) reads the LOW 32 bits of p_list.tqe_next.
  //    For some proc in allproc, those bits may accidentally equal 1,
  //    causing _findProcI to return the WRONG proc as "PID 1".
  //    Fix: use offset fallbacks (pidOff → 0x60, listOff → 0x08) and
  //         add procbypid() fallback so PID 1 is found correctly.
  //
  //  Bug 2 — cr_label chain reads garbage → kernel panic:
  //    If the wrong proc was returned (bug 1), ucredPtr is garbage.
  //    _kreadPtrI(garbage + crLabelOff) may return a seemingly-valid
  //    kernel address.  The subsequent byte-by-byte _kreadCStrI(sbPtr+0x10)
  //    then walks into PPL-protected or unmapped memory → kernel panic → respring.
  //    Fix: gate the entire cr_label chain on non-zero offsets AND
  //         verify each pointer with ds_isvalid() before dereferencing.
  //

  import Foundation
  import Darwin

  // MARK: – Low-level helpers (all guard with ds_isvalid before read)

  private func _resolvePidI(_ s: String) -> Int32? {
      let t = s.trimmingCharacters(in: .whitespaces)
      if let n = Int32(t) { return n }
      return ProcessLayer.shared.find(matching: t.lowercased()).first?.pid
  }

  private func _kreadPtrI(_ addr: UInt64) -> UInt64 {
      guard addr != 0, ds_isvalid(addr) else { return 0 }
      return ds_kreadptr(addr)
  }

  private func _kread64I(_ addr: UInt64) -> UInt64 {
      guard addr != 0, ds_isvalid(addr) else { return 0 }
      return ds_kread64(addr)
  }

  private func _kread32I(_ addr: UInt64) -> UInt32 {
      guard addr != 0, ds_isvalid(addr) else { return 0 }
      return ds_kread32(addr)
  }

  private func _kread16I(_ addr: UInt64) -> UInt16 {
      guard addr != 0, ds_isvalid(addr) else { return 0 }
      return ds_kread16(addr)
  }

  /// Read a kernel C-string byte-by-byte.
  /// Re-checks ds_isvalid() every 64 bytes to avoid crossing into
  /// unmapped / PPL-protected pages (which could panic the kernel).
  private func _kreadCStrI(_ addr: UInt64, max: Int = 64) -> String {
      guard addr != 0, ds_isvalid(addr) else { return "" }
      var buf = [UInt8](repeating: 0, count: max + 1)
      for i in 0..<max {
          // Re-validate every 64 bytes (one page granularity guard)
          if i % 64 == 0, i > 0 {
              guard ds_isvalid(addr + UInt64(i)) else { break }
          }
          let b = ds_kread8(addr + UInt64(i))
          if b == 0 { break }
          buf[i] = b
      }
      let data = Data(buf.prefix(while: { $0 != 0 }))
      return String(data: data, encoding: .utf8) ?? String(data: data, encoding: .ascii) ?? ""
  }

  // MARK: – Process finder
  //
  // CRASH-FIX: Use proper offset fallbacks so a zero off_proc_p_pid cannot
  // cause a false PID match.  Also falls back to C procbypid() so early-list
  // processes (PID 1 / launchd) are found without a backward TAILQ walk
  // (which would crash — le_prev is a pointer-to-pointer, not proc*).

  private func _findProcI(pid: Int32, mgr: laramgr) -> UInt64? {
      guard mgr.dsready else { return nil }

      // Use runtime offsets with safe fallbacks
      let pidOff  = off_proc_p_pid          != 0 ? UInt64(off_proc_p_pid)          : 0x60
      let listOff = off_proc_p_list_le_next != 0 ? UInt64(off_proc_p_list_le_next) : 0x08

      // Forward walk from our proc (catches processes added after us)
      let ourProc = ds_get_our_proc()
      if ourProc != 0 {
          var ptr  = ourProc
          var seen = Set<UInt64>()
          while ptr != 0, !seen.contains(ptr) {
              seen.insert(ptr)
              // Guard before reading pid field
              guard ds_isvalid(ptr + pidOff) else { break }
              let p_pid = Int32(bitPattern: ds_kread32(ptr + pidOff))
              if p_pid == pid { return ptr }
              guard ds_isvalid(ptr + listOff) else { break }
              ptr = ds_kreadptr(ptr + listOff)
          }
      }

      // Fallback: C-side procbypid() walks from the real allproc head
      // (handles launchd PID 1 and other early-list processes)
      let kaddr = procbypid(pid_t(pid))
      return kaddr != 0 ? kaddr : nil
  }

  // MARK: – task-info

  private func _taskInfo(pid: Int32, mgr: laramgr) -> String? {
      guard let procPtr = _findProcI(pid: pid, mgr: mgr) else { return nil }

      let procRoOff     = UInt64(off_proc_p_proc_ro)
      let prTaskOff     = UInt64(off_proc_ro_pr_task)
      let taskMapOff    = UInt64(off_task_map)
      let itkSpaceOff   = UInt64(off_task_itk_space)
      let threadsNextOff = UInt64(off_task_threads_next)
      let excGuardOff   = UInt64(off_task_task_exc_guard)
      let threadNextOff = UInt64(off_thread_task_threads_next)
      let ctidOff       = UInt64(off_thread_ctid)
      let kstackOff     = UInt64(off_thread_machine_kstackptr)

      let procRo  = _kreadPtrI(procPtr + procRoOff)
      let taskPtr = _kreadPtrI(procRo  + prTaskOff)
      guard taskPtr != 0 else { return nil }

      let vmMap     = _kreadPtrI(taskPtr + taskMapOff)
      let itkSpace  = _kreadPtrI(taskPtr + itkSpaceOff)
      let threadsNext = _kreadPtrI(taskPtr + threadsNextOff)
      let excGuard  = _kread32I(taskPtr + excGuardOff)

      var threadCount = 0
      var threadPtr   = threadsNext
      var threadSeen  = Set<UInt64>()
      while threadPtr != 0, !threadSeen.contains(threadPtr), threadCount < 1024 {
          threadSeen.insert(threadPtr)
          threadCount += 1
          threadPtr = ds_kreadptr(threadPtr + threadNextOff)
      }
      let taskRefcount = _kread32I(taskPtr + 0x10)

      var lines = [
          String(format: "task            : 0x%016llx", taskPtr),
          String(format: "  vm_map        : 0x%016llx", vmMap),
          String(format: "  ipc_space     : 0x%016llx", itkSpace),
          String(format: "  threads       : %d (list head @ 0x%llx)", threadCount, threadsNext),
          String(format: "  refcount      : %d", taskRefcount),
          String(format: "  exc_guard     : 0x%08x", excGuard),
      ]
      if threadCount > 0 {
          lines.append("")
          lines.append("Thread list (first 8):")
          threadPtr = threadsNext
          threadSeen.removeAll()
          var idx = 0
          while threadPtr != 0, !threadSeen.contains(threadPtr), idx < 8 {
              threadSeen.insert(threadPtr)
              let tid    = _kread64I(threadPtr + ctidOff)
              let state  = _kread32I(threadPtr + 0x14)
              let kstack = _kreadPtrI(threadPtr + kstackOff)
              lines.append(String(format: "  [%d] thread@0x%llx  tid=%llu  state=0x%x  kstack=0x%llx",
                                  idx, threadPtr, tid, state, kstack))
              threadPtr = ds_kreadptr(threadPtr + threadNextOff)
              idx += 1
          }
      }
      return lines.joined(separator: "\n")
  }

  // MARK: – ucred-info
  //
  // CRASH-FIX (final): cr_label chain removed entirely.
  //
  // Root cause of respring on system processes (PID 1 launchd, PID 2, etc.):
  //   cr_label for system processes lives in PPL-protected read-only memory.
  //   ds_isvalid() returns TRUE (page IS mapped), but the socket KRW primitive
  //   cannot safely read PPL pages — ds_kread8/ds_kreadptr on those addresses
  //   triggers a kernel panic → SpringBoard respring.
  //
  //   Even with per-step ds_isvalid() guards the primitive itself panics,
  //   because the check tests mappedness, not PPL accessibility.
  //
  // Safe alternative: use 'sandbox-check <pid>' (uses sysctl path, no PPL reads).
  //
  // Only reads within the ucred struct itself (cr_posix at fixed offsets) —
  // these fields are in regular kernel heap memory, readable on all processes.

  private func _ucredInfo(pid: Int32, mgr: laramgr) -> String? {
      guard let procPtr = _findProcI(pid: pid, mgr: mgr) else { return nil }

      // Offsets with safe fallbacks (iOS 18 arm64e)
      let procROOff  = off_proc_p_proc_ro  != 0 ? UInt64(off_proc_p_proc_ro)  : 0x18
      let ucredROOff = off_proc_ro_p_ucred != 0 ? UInt64(off_proc_ro_p_ucred) : 0x08

      // proc → proc_ro → ucred
      let proc_ro  = _kreadPtrI(procPtr + procROOff)
      guard proc_ro != 0 else { return nil }
      let ucredPtr = _kreadPtrI(proc_ro + ucredROOff)
      guard ucredPtr != 0 else { return nil }

      // kauth_cred / posix_cred layout (iOS 16-18 arm64e, stable):
      //   cr_posix starts at ucred+0x18
      //   +0x18 cr_uid     +0x1c cr_ruid    +0x20 cr_svuid
      //   +0x24 cr_gid     +0x28 cr_rgid    +0x2c cr_svgid
      //   +0x30 cr_ngroups  +0x34..+0x70 cr_groups[16]
      let cr_uid    = _kread32I(ucredPtr + 0x18)
      let cr_ruid   = _kread32I(ucredPtr + 0x1c)
      let cr_svuid  = _kread32I(ucredPtr + 0x20)
      let cr_gid    = _kread32I(ucredPtr + 0x24)
      let cr_rgid   = _kread32I(ucredPtr + 0x28)
      let cr_svgid  = _kread32I(ucredPtr + 0x2c)
      let cr_ngroups = _kread32I(ucredPtr + 0x30)

      var groups: [UInt32] = []
      for i in 0..<min(Int(cr_ngroups), 16) {
          groups.append(_kread32I(ucredPtr + 0x34 + UInt64(i) * 4))
      }

      // cr_label chain is intentionally skipped:
      // For system processes (PID ≤ 4 and many daemons), cr_label lives in
      // PPL-protected pages.  Reading those via the socket KRW primitive
      // causes a kernel panic even when ds_isvalid() says the page is mapped.
      // Use 'sandbox-check <pid>' for policy info (sysctl-based, no PPL reads).

      var out = [String]()
      out.append(String(format: "ucred-info: pid %d", pid))
      out.append(String(format: "  proc_ro_ptr   : 0x%016llx", proc_ro))
      out.append(String(format: "  ucred_ptr     : 0x%016llx", ucredPtr))
      out.append("  ──── posix credentials ────")
      out.append(String(format: "  uid           : %d", cr_uid))
      out.append(String(format: "  gid           : %d", cr_gid))
      out.append(String(format: "  ruid          : %d", cr_ruid))
      out.append(String(format: "  svuid         : %d", cr_svuid))
      out.append(String(format: "  rgid          : %d", cr_rgid))
      out.append(String(format: "  svgid         : %d", cr_svgid))
      out.append(String(format: "  ngroups       : %d", cr_ngroups))
      out.append(String(format: "  groups        : [%@]",
                        groups.map { String($0) }.joined(separator: ", ")))
      out.append("  ──── mac label ────")
      out.append("  cr_label      : skipped (PPL-protected on system procs)")
      out.append("  sandbox       : use 'sandbox-check \(pid)' for policy info")
      out.append("  amfi          : use 'amfi-status' for AMFI enforcement state")
      return out.joined(separator: "\n")
  }

  // MARK: – vmmap-k

  private func _vmmapK(pid: Int32, mgr: laramgr) -> String? {
      guard let procPtr = _findProcI(pid: pid, mgr: mgr) else { return nil }

      let procRoOff        = UInt64(off_proc_p_proc_ro)
      let prTaskOff        = UInt64(off_proc_ro_pr_task)
      let taskMapOff       = UInt64(off_task_map)
      let vmMapHdrOff      = UInt64(off_vm_map_hdr)
      let hdrNentriesOff   = UInt64(off_vm_map_header_nentries)
      let hdrLinksNextOff  = UInt64(off_vm_map_header_links_next)
      let entryAliasOff    = UInt64(off_vm_map_entry_vme_alias)
      let entryObjOff      = UInt64(off_vm_map_entry_vme_object_or_delta)
      let entryLinksNextOff = UInt64(off_vm_map_entry_links_next)
      let voSizeOff        = UInt64(off_vm_object_vo_un1_vou_size)
      let voRefOff         = UInt64(off_vm_object_ref_count)

      let procRo   = _kreadPtrI(procPtr + procRoOff)
      let taskPtr  = _kreadPtrI(procRo  + prTaskOff)
      guard taskPtr != 0 else { return nil }
      let vmMapPtr = _kreadPtrI(taskPtr + taskMapOff)
      guard vmMapPtr != 0 else { return nil }

      let hdrPtr   = vmMapPtr + vmMapHdrOff
      let nentries = _kread32I(hdrPtr + hdrNentriesOff)

      var lines = [
          String(format: "vmmap-k: pid %d  vm_map@0x%llx", pid, vmMapPtr),
          String(format: "  entries: %d", nentries),
          "",
          String(format: "%-20s %-20s %-10s %-6s %-6s %-6s %@",
                 "START", "END", "SIZE", "PROT", "MAX", "TAG", "NAME"),
          String(repeating: "-", count: 90)
      ]

      let firstEntry = _kreadPtrI(hdrPtr + hdrLinksNextOff)
      var entryPtr   = firstEntry
      var entrySeen  = Set<UInt64>()
      var count      = 0

      while entryPtr != 0, !entrySeen.contains(entryPtr), count < 512 {
          entrySeen.insert(entryPtr)
          count += 1
          let start    = _kread64I(entryPtr + 0x00)
          let end      = _kread64I(entryPtr + 0x08)
          let size     = end &- start
          let protBits = _kread32I(entryPtr + 0x20)
          let maxProt  = (protBits >> 8) & 0xFF
          let curProt  = protBits & 0xFF
          let alias    = _kread16I(entryPtr + entryAliasOff)
          let objOrDelta = _kread64I(entryPtr + entryObjOff)

          func protStr(_ p: UInt32) -> String {
              var s = ""
              s += (p & 1) != 0 ? "r" : "-"
              s += (p & 2) != 0 ? "w" : "-"
              s += (p & 4) != 0 ? "x" : "-"
              return s
          }

          var name = ""
          if objOrDelta != 0, (objOrDelta & 1) == 0 {
              let voSize = _kread64I(objOrDelta + voSizeOff)
              let voRef  = _kread32I(objOrDelta + voRefOff)
              name = "vm_object(size=\(voSize), ref=\(voRef))"
          } else {
              name = "submap/zeroed"
          }

          lines.append(String(format: "0x%016llx 0x%016llx %-10s %-6s %-6s 0x%04x %@",
                              start, end, formatSizeI(Int(size)),
                              protStr(curProt), protStr(maxProt), alias, name))
          entryPtr = _kreadPtrI(entryPtr + entryLinksNextOff)
      }
      return lines.joined(separator: "\n")
  }

  private func formatSizeI(_ bytes: Int) -> String {
      if bytes < 1024          { return "\(bytes)B" }
      if bytes < 1024*1024     { return String(format: "%.1fK", Double(bytes)/1024) }
      if bytes < 1024*1024*1024 { return String(format: "%.1fM", Double(bytes)/(1024*1024)) }
      return String(format: "%.2fG", Double(bytes)/(1024*1024*1024))
  }

  // MARK: – Registration

  func registerProcessExplorer() {

      OmegaCore.register("task-info") { arg, mgr in
          guard mgr.dsready else { return .fail("task-info: kernel r/w not ready") }
          let a = arg.trimmingCharacters(in: .whitespaces)
          guard !a.isEmpty, let pid = _resolvePidI(a) else {
              return .fail("task-info: usage — task-info <pid|name>")
          }
          guard let out = _taskInfo(pid: pid, mgr: mgr) else {
              return .fail("task-info: failed to read task for pid \(pid)")
          }
          return .ok(out)
      }

      OmegaCore.register("ucred-info") { arg, mgr in
          guard mgr.dsready else { return .fail("ucred-info: kernel r/w not ready") }
          let a = arg.trimmingCharacters(in: .whitespaces)
          guard !a.isEmpty, let pid = _resolvePidI(a) else {
              return .fail("ucred-info: usage — ucred-info <pid|name>")
          }
          guard let out = _ucredInfo(pid: pid, mgr: mgr) else {
              return .fail("ucred-info: failed to locate process or read ucred for pid \(pid)")
          }
          return .ok(out)
      }

      OmegaCore.register("vmmap-k") { arg, mgr in
          guard mgr.dsready else { return .fail("vmmap-k: kernel r/w not ready") }
          let a = arg.trimmingCharacters(in: .whitespaces)
          guard !a.isEmpty, let pid = _resolvePidI(a) else {
              return .fail("vmmap-k: usage — vmmap-k <pid|name>")
          }
          guard let out = _vmmapK(pid: pid, mgr: mgr) else {
              return .fail("vmmap-k: failed to read vm_map for pid \(pid)")
          }
          return .ok(out)
      }
  }
  