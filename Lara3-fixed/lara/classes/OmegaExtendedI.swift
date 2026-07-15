//
//  OmegaExtendedI.swift
//  lara — Process Explorer
//  task-info, ucred-info, vmmap-k
//

import Foundation
import Darwin

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

private func _kreadCStrI(_ addr: UInt64, max: Int = 64) -> String {
    guard addr != 0, ds_isvalid(addr) else { return "" }
    var buf = [UInt8](repeating: 0, count: max + 1)
    for i in 0..<max {
        let b = ds_kread8(addr + UInt64(i))
        if b == 0 { break }
        buf[i] = b
    }
    let data = Data(buf.prefix(while: { $0 != 0 }))
    return String(data: data, encoding: .utf8) ?? String(data: data, encoding: .ascii) ?? ""
}

private func _findProcI(pid: Int32, mgr: laramgr) -> UInt64? {
    guard mgr.dsready else { return nil }
    let ourProc = ds_get_our_proc()
    guard ourProc != 0 else { return nil }
    var ptr = ourProc
    var seen = Set<UInt64>()
    while ptr != 0 && !seen.contains(ptr) {
        seen.insert(ptr)
        let p_pid = Int32(bitPattern: ds_kread32(ptr + procPPidOff))
        if p_pid == pid { return ptr }
        ptr = ds_kreadptr(ptr + procPListLeNextOff)
    }
    return nil
}

// MARK: – task-info

private func _taskInfo(pid: Int32, mgr: laramgr) -> String? {
    guard let procPtr = _findProcI(pid: pid, mgr: mgr) else { return nil }
    let procRo = _kreadPtrI(procPtr + procPProcRoOff)
    let taskPtr = _kreadPtrI(procRo + procRoPrTaskOff)
    guard taskPtr != 0 else { return nil }

    let vmMap = _kreadPtrI(taskPtr + taskMapOff)
    let itkSpace = _kreadPtrI(taskPtr + taskItkSpaceOff)
    let threadsNext = _kreadPtrI(taskPtr + taskThreadsNextOff)
    let excGuard = _kread32I(taskPtr + taskTaskExcGuardOff)

    var threadCount = 0
    var threadPtr = threadsNext
    var threadSeen = Set<UInt64>()
    while threadPtr != 0 && !threadSeen.contains(threadPtr) && threadCount < 1024 {
        threadSeen.insert(threadPtr)
        threadCount += 1
        threadPtr = ds_kreadptr(threadPtr + threadTaskThreadsNextOff)
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
        while threadPtr != 0 && !threadSeen.contains(threadPtr) && idx < 8 {
            threadSeen.insert(threadPtr)
            let tid = _kread64I(threadPtr + threadCtidOff)
            let state = _kread32I(threadPtr + 0x14)
            let kstack = _kreadPtrI(threadPtr + threadMachineKstackptrOff)
            lines.append(String(format: "  [%d] thread@0x%llx  tid=%llu  state=0x%x  kstack=0x%llx",
                              idx, threadPtr, tid, state, kstack))
            threadPtr = ds_kreadptr(threadPtr + threadTaskThreadsNextOff)
            idx += 1
        }
    }
    return lines.joined(separator: "\n")
}

// MARK: – ucred-info

private func _ucredInfo(pid: Int32, mgr: laramgr) -> String? {
    guard let procPtr = _findProcI(pid: pid, mgr: mgr) else { return nil }
    let procRo = _kreadPtrI(procPtr + procPProcRoOff)
    let ucredPtr = _kreadPtrI(procRo + procRoPUcredOff)
    guard ucredPtr != 0 else { return nil }

    let cr_uid = _kread32I(ucredPtr + 0x18)
    let cr_ruid = _kread32I(ucredPtr + 0x1C)
    let cr_svuid = _kread32I(ucredPtr + 0x20)
    let cr_rgid = _kread32I(ucredPtr + 0x24)
    let cr_svgid = _kread32I(ucredPtr + 0x28)
    let cr_ngroups = _kread32I(ucredPtr + 0x2C)
    let cr_label = _kreadPtrI(ucredPtr + ucredCrLabelOff)

    var sandboxStr = "none"
    if cr_label != 0 {
        let sbPtr = _kreadPtrI(cr_label + labelLPerpolicySandboxOff)
        if sbPtr != 0 {
            sandboxStr = _kreadCStrI(sbPtr + 0x10, max: 64)
            if sandboxStr.isEmpty { sandboxStr = "present (unknown name)" }
        }
    }

    var amfiStr = "none"
    if cr_label != 0 {
        let amfiPtr = _kreadPtrI(cr_label + labelLPerpolicyAmfiOff)
        if amfiPtr != 0 { amfiStr = "present" }
    }

    var groups: [UInt32] = []
    for i in 0..<min(Int(cr_ngroups), 16) {
        groups.append(_kread32I(ucredPtr + 0x30 + UInt64(i) * 4))
    }

    let textvp = _kreadPtrI(procPtr + procPTextvpOff)
    let entStr = textvp != 0 ? "use 'proc-entitlements <pid>' for full dump" : "unavailable"

    let lines = [
        String(format: "ucred           : 0x%016llx", ucredPtr),
        String(format: "  uid           : %d", cr_uid),
        String(format: "  gid           : %d", cr_rgid),
        String(format: "  ruid          : %d", cr_ruid),
        String(format: "  svuid         : %d", cr_svuid),
        String(format: "  rgid          : %d", cr_rgid),
        String(format: "  svgid         : %d", cr_svgid),
        String(format: "  ngroups       : %d", cr_ngroups),
        String(format: "  groups        : [%@]", groups.map { String($0) }.joined(separator: ", ")),
        String(format: "  cr_label      : 0x%016llx", cr_label),
        String(format: "  sandbox       : %@", sandboxStr),
        String(format: "  amfi          : %@", amfiStr),
        String(format: "  entitlements  : %@", entStr),
    ]
    return lines.joined(separator: "\n")
}

// MARK: – vmmap-k

private func _vmmapK(pid: Int32, mgr: laramgr) -> String? {
    guard let procPtr = _findProcI(pid: pid, mgr: mgr) else { return nil }
    let procRo = _kreadPtrI(procPtr + procPProcRoOff)
    let taskPtr = _kreadPtrI(procRo + procRoPrTaskOff)
    guard taskPtr != 0 else { return nil }
    let vmMapPtr = _kreadPtrI(taskPtr + taskMapOff)
    guard vmMapPtr != 0 else { return nil }

    let hdrPtr = vmMapPtr + vmMapHdrOff
    let nentries = _kread32I(hdrPtr + vmMapHeaderNentriesOff)

    var lines = [
        String(format: "vmmap-k: pid %d  vm_map@0x%llx", pid, vmMapPtr),
        String(format: "  entries: %d", nentries),
        "",
        String(format: "%-20s %-20s %-10s %-6s %-6s %-6s %@",
               "START", "END", "SIZE", "PROT", "MAX", "TAG", "NAME"),
        String(repeating: "-", count: 90)
    ]

    let firstEntry = _kreadPtrI(hdrPtr + vmMapHeaderLinksNextOff)
    var entryPtr = firstEntry
    var entrySeen = Set<UInt64>()
    var count = 0

    while entryPtr != 0 && !entrySeen.contains(entryPtr) && count < 512 {
        entrySeen.insert(entryPtr)
        count += 1
        let start = _kread64I(entryPtr + 0x00)
        let end = _kread64I(entryPtr + 0x08)
        let size = end - start
        let protBits = _kread32I(entryPtr + 0x20)
        let maxProt = (protBits >> 8) & 0xFF
        let curProt = protBits & 0xFF
        let alias = _kread16I(entryPtr + vmMapEntryVmeAliasOff)
        let objOrDelta = _kread64I(entryPtr + vmMapEntryVmeObjectOrDeltaOff)

        func protStr(_ p: UInt32) -> String {
            var s = ""
            s += (p & 1) != 0 ? "r" : "-"
            s += (p & 2) != 0 ? "w" : "-"
            s += (p & 4) != 0 ? "x" : "-"
            return s
        }

        var name = ""
        if objOrDelta != 0 && (objOrDelta & 1) == 0 {
            let voSize = _kread64I(objOrDelta + vmObjectVoUn1VouSizeOff)
            let voRef = _kread32I(objOrDelta + vmObjectRefCountOff)
            name = "vm_object(size=\(voSize), ref=\(voRef))"
        } else {
            name = "submap/zeroed"
        }

        lines.append(String(format: "0x%016llx 0x%016llx %-10s %-6s %-6s 0x%04x %@",
                          start, end, formatSizeI(Int(size)),
                          protStr(curProt), protStr(maxProt), alias, name))
        entryPtr = _kreadPtrI(entryPtr + vmMapEntryLinksNextOff)
    }
    return lines.joined(separator: "\n")
}

private func formatSizeI(_ bytes: Int) -> String {
    if bytes < 1024 { return "\(bytes)B" }
    if bytes < 1024*1024 { return String(format: "%.1fK", Double(bytes)/1024) }
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
            return .fail("ucred-info: failed to read ucred for pid \(pid)")
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
