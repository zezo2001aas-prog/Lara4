//
//  OmegaExtendedJ.swift
//  lara — IPC Explorer
//  ipc-space, port-info
//

import Foundation
import Darwin

private func _resolvePidJ(_ s: String) -> Int32? {
    let t = s.trimmingCharacters(in: .whitespaces)
    if let n = Int32(t) { return n }
    return ProcessLayer.shared.find(matching: t.lowercased()).first?.pid
}

private func _kreadPtrJ(_ addr: UInt64) -> UInt64 {
    guard addr != 0, ds_isvalid(addr) else { return 0 }
    return ds_kreadptr(addr)
}

private func _kread64J(_ addr: UInt64) -> UInt64 {
    guard addr != 0, ds_isvalid(addr) else { return 0 }
    return ds_kread64(addr)
}

private func _kread32J(_ addr: UInt64) -> UInt32 {
    guard addr != 0, ds_isvalid(addr) else { return 0 }
    return ds_kread32(addr)
}

private func _parseAddrJ(_ s: String) -> UInt64? {
private func _ipcSpace(pid: Int32, mgr: laramgr) -> String? {
    guard mgr.dsready else { return nil }
    let ourProc = ds_get_our_proc()
    guard ourProc != 0 else { return nil }

    var procPtr: UInt64 = 0
    var ptr = ourProc
    var seen = Set<UInt64>()
    while ptr != 0 && !seen.contains(ptr) {
        seen.insert(ptr)
        let p_pid = Int32(bitPattern: ds_kread32(ptr + procPPidOff))
        if p_pid == pid { procPtr = ptr; break }
        ptr = ds_kreadptr(ptr + procPListLeNextOff)
    }
    guard procPtr != 0 else { return nil }

    let procRo = _kreadPtrJ(procPtr + procPProcRoOff)
    let taskPtr = _kreadPtrJ(procRo + procRoPrTaskOff)
    guard taskPtr != 0 else { return nil }

    let itkSpace = _kreadPtrJ(taskPtr + taskItkSpaceOff)
    guard itkSpace != 0 else { return nil }

    let isTable = _kreadPtrJ(itkSpace + ipcSpaceIsTableOff)
    let isTableSize = _kread32J(itkSpace + ipcSpaceIsTableOff + 8)

    var lines = [
        String(format: "ipc-space: pid %d", pid),
        String(format: "  ipc_space     : 0x%016llx", itkSpace),
        String(format: "  is_table      : 0x%016llx", isTable),
        String(format: "  table_size    : %d", isTableSize),
        "",
        String(format: "%-8s %-20s %-20s %-10s %@", "PORT", "RECEIVER", "KOBJECT", "RIGHTS", "TYPE"),
        String(repeating: "-", count: 80)
    ]

    let entrySize = UInt64(sizeof_ipc_entry)
    guard entrySize > 0 else {
        lines.append("  (sizeof_ipc_entry is 0 — cannot walk table)")
        return lines.joined(separator: "\n")
    }

    for i in 0..<min(Int(isTableSize), 256) {
        let entryAddr = isTable + UInt64(i) * entrySize
        let ieObject = _kreadPtrJ(entryAddr + ipcEntryIeObjectOff)
        if ieObject == 0 { continue }

        let ipKobject = _kreadPtrJ(ieObject + ipcPortIpKobjectOff)
        let ieBits = _kread32J(entryAddr + 0x08)
        let rights = ieBits & 0xFFFF

        var typeStr = "UNKNOWN"
        if ipKobject != 0 {
            let kobjHigh = ipKobject >> 40
            typeStr = (kobjHigh == 0xFFF) ? "TASK/THREAD" : "OBJECT"
        }

        let rightsStr: String
        switch rights {
        case 0: rightsStr = "dead"
        case 1: rightsStr = "send"
        case 2: rightsStr = "receive"
        case 3: rightsStr = "send+recv"
        case 4: rightsStr = "port_set"
        case 5: rightsStr = "send-once"
        case 6: rightsStr = "labelh"
        default: rightsStr = "other(\(rights))"
        }

        lines.append(String(format: "0x%-6x 0x%016llx 0x%016llx %-10s %@",
                          i, ieObject, ipKobject, rightsStr, typeStr))
    }
    return lines.joined(separator: "\n")
}

// MARK: – port-info

private func _portInfo(portAddr: UInt64) -> String? {
    guard portAddr != 0, ds_isvalid(portAddr) else { return nil }

    let ipKobject = _kreadPtrJ(portAddr + ipcPortIpKobjectOff)
    let ipBits = _kread32J(portAddr + 0x08)
    let ipSrights = _kread32J(portAddr + 0x10)
    let ipReceiver = _kreadPtrJ(portAddr + 0x18)

    var lines = [
        String(format: "port-info: 0x%016llx", portAddr),
        String(format: "  ip_kobject    : 0x%016llx", ipKobject),
        String(format: "  ip_bits       : 0x%08x", ipBits),
        String(format: "  ip_srights    : %d", ipSrights),
        String(format: "  ip_receiver   : 0x%016llx", ipReceiver),
    ]
    if ipKobject != 0 {
        let kobjType = _kread32J(ipKobject + 0x00)
        lines.append(String(format: "  kobject_type  : 0x%08x (heuristic)", kobjType))
    }
    return lines.joined(separator: "\n")
}

// MARK: – Registration

func registerIPCExplorer() {

    OmegaCore.register("ipc-space") { arg, mgr in
        guard mgr.dsready else { return .fail("ipc-space: kernel r/w not ready") }
        let a = arg.trimmingCharacters(in: .whitespaces)
        guard !a.isEmpty, let pid = _resolvePidJ(a) else {
            return .fail("ipc-space: usage — ipc-space <pid|name>")
        }
        guard let out = _ipcSpace(pid: pid, mgr: mgr) else {
            return .fail("ipc-space: failed to read ipc_space for pid \(pid)")
        }
        return .ok(out)
    }

    OmegaCore.register("port-info") { arg, mgr in
        guard mgr.dsready else { return .fail("port-info: kernel r/w not ready") }
        guard let addr = _parseAddrJ(arg.trimmingCharacters(in: .whitespaces)) else {
            return .fail("port-info: usage — port-info <port_addr_hex>")
        }
        guard let out = _portInfo(portAddr: addr) else {
            return .fail("port-info: invalid port address 0x\(String(format: "%llx", addr))")
        }
        return .ok(out)
    }
}
