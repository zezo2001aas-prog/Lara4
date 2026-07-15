//
//  OmegaExtendedH.swift
//  lara — Kernel Object Explorer
//  fd-info, socket-info, socket-dump, socket-diff
//

import Foundation
import Darwin

// MARK: – Socket Snapshot Store (for socket-diff)

private final class SocketSnapshotStore {
    static let shared = SocketSnapshotStore()
    private var store: [Int: (Date, Data)] = [:]
    private let lock = NSLock()

    func save(fd: Int, data: Data) {
        lock.lock(); defer { lock.unlock() }
        store[fd] = (Date(), data)
    }

    func load(fd: Int) -> (Date, Data)? {
        lock.lock(); defer { lock.unlock() }
        return store[fd]
    }

    func clear(fd: Int) {
        lock.lock(); defer { lock.unlock() }
        store.removeValue(forKey: fd)
    }
}

// MARK: – Helpers

private func _kreadPtrH(_ addr: UInt64) -> UInt64 {
    guard addr != 0, ds_isvalid(addr) else { return 0 }
    return ds_kreadptr(addr)
}

private func _kread64H(_ addr: UInt64) -> UInt64 {
    guard addr != 0, ds_isvalid(addr) else { return 0 }
    return ds_kread64(addr)
}

private func _kread32H(_ addr: UInt64) -> UInt32 {
    guard addr != 0, ds_isvalid(addr) else { return 0 }
    return ds_kread32(addr)
}

private func _resolvePidH(_ s: String) -> Int32? {
    let t = s.trimmingCharacters(in: .whitespaces)
    if let n = Int32(t) { return n }
    return ProcessLayer.shared.find(matching: t.lowercased()).first?.pid
}

private func _parseAddrH(_ s: String) -> UInt64? {
    let t = s.trimmingCharacters(in: .whitespaces)
    let c = (t.hasPrefix("0x") || t.hasPrefix("0X")) ? String(t.dropFirst(2)) : t
    return UInt64(c, radix: 16)
}

private func _kreadCStrH(_ addr: UInt64, max: Int = 64) -> String {
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

// MARK: – fd-info

private func _fdInfo(pid: Int32, fd: Int32, mgr: laramgr) -> String? {
    guard mgr.dsready else { return nil }

    let procPListLeNextOff = UInt64(off_proc_p_list_le_next)
    let procPPidOff = UInt64(off_proc_p_pid)
    let procPFdOff = UInt64(off_proc_p_fd)
    let filedescFdOfilesOff = UInt64(off_filedesc_fd_ofiles)
    let fileprocFpGlobOff = UInt64(off_fileproc_fp_glob)
    let fileglobFgDataOff = UInt64(off_fileglob_fg_data)
    let vnodeVUsecountOff = UInt64(off_vnode_v_usecount)
    let vnodeVIocountOff = UInt64(off_vnode_v_iocount)

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

    let fdPtr = _kreadPtrH(procPtr + procPFdOff)
    guard fdPtr != 0 else { return nil }
    let ofilesPtr = _kreadPtrH(fdPtr + filedescFdOfilesOff)
    guard ofilesPtr != 0 else { return nil }
    let fileprocPtr = _kreadPtrH(ofilesPtr + UInt64(fd) * 8)
    guard fileprocPtr != 0 else { return nil }
    let fileglobPtr = _kreadPtrH(fileprocPtr + fileprocFpGlobOff)
    guard fileglobPtr != 0 else { return nil }
    let fg_flag = _kread32H(fileglobPtr + 0x10)
    let fg_data = _kreadPtrH(fileglobPtr + fileglobFgDataOff)
    let fg_ops  = _kreadPtrH(fileglobPtr + 0x28)

    var fg_typeStr = "UNKNOWN"
    if fg_data != 0 {
        let so_type = _kread32H(fg_data + 0x04)
        if so_type >= 1 && so_type <= 10 {
            fg_typeStr = "DTYPE_SOCKET"
        } else {
            let v_usecount = _kread32H(fg_data + vnodeVUsecountOff)
            let v_iocount  = _kread32H(fg_data + vnodeVIocountOff)
            if v_usecount > 0 && v_usecount < 0x10000 && v_iocount > 0 && v_iocount < 0x10000 {
                fg_typeStr = "DTYPE_VNODE"
            } else {
                fg_typeStr = "DTYPE_OTHER(\(fg_flag))"
            }
        }
    }

    var lines = [
        String(format: "FD              : %d", fd),
        String(format: "fileproc        : 0x%016llx", fileprocPtr),
        String(format: "fileglob        : 0x%016llx", fileglobPtr),
        String(format: "fg_type         : %@", fg_typeStr),
        String(format: "fg_flag         : 0x%08x", fg_flag),
        String(format: "fg_ops          : 0x%016llx", fg_ops),
        String(format: "fg_data         : 0x%016llx", fg_data),
    ]
    if fg_typeStr == "DTYPE_SOCKET" && fg_data != 0 {
        lines.append("")
        lines.append("Socket structure detected — use 'socket-info <fd>' for full decode.")
    }
    return lines.joined(separator: "\n")
}

// MARK: – socket-info

private func _socketInfo(fd: Int32, mgr: laramgr) -> String? {
    guard mgr.dsready else { return nil }

    let procPListLeNextOff = UInt64(off_proc_p_list_le_next)
    let procPPidOff = UInt64(off_proc_p_pid)
    let procPFdOff = UInt64(off_proc_p_fd)
    let filedescFdOfilesOff = UInt64(off_filedesc_fd_ofiles)
    let fileprocFpGlobOff = UInt64(off_fileproc_fp_glob)
    let fileglobFgDataOff = UInt64(off_fileglob_fg_data)
    let socketSoProtoOff = UInt64(off_socket_so_proto)
    let socketSoUsecntOff = UInt64(off_socket_so_usecount)

    let ourProc = ds_get_our_proc()
    guard ourProc != 0 else { return nil }

    var procPtr: UInt64 = 0
    var ptr = ourProc
    var seen = Set<UInt64>()
    let pid = getpid()
    while ptr != 0 && !seen.contains(ptr) {
        seen.insert(ptr)
        let p_pid = Int32(bitPattern: ds_kread32(ptr + procPPidOff))
        if p_pid == pid { procPtr = ptr; break }
        ptr = ds_kreadptr(ptr + procPListLeNextOff)
    }
    guard procPtr != 0 else { return nil }

    let fdPtr = _kreadPtrH(procPtr + procPFdOff)
    guard fdPtr != 0 else { return nil }
    let ofilesPtr = _kreadPtrH(fdPtr + filedescFdOfilesOff)
    guard ofilesPtr != 0 else { return nil }
    let fileprocPtr = _kreadPtrH(ofilesPtr + UInt64(fd) * 8)
    guard fileprocPtr != 0 else { return nil }
    let fileglobPtr = _kreadPtrH(fileprocPtr + fileprocFpGlobOff)
    guard fileglobPtr != 0 else { return nil }
    let socketAddr = _kreadPtrH(fileglobPtr + fileglobFgDataOff)
    guard socketAddr != 0 else { return nil }

    return _socketInfoFromAddr(socketAddr: socketAddr)
}

private func _socketInfoFromAddr(socketAddr: UInt64) -> String? {
    guard socketAddr != 0, ds_isvalid(socketAddr) else { return nil }

    let socketSoProtoOff = UInt64(off_socket_so_proto)
    let socketSoUsecntOff = UInt64(off_socket_so_usecount)

    let so_type     = _kread32H(socketAddr + 0x04)
    let so_state    = _kread32H(socketAddr + 0x08)
    let so_options  = _kread32H(socketAddr + 0x10)
    let so_proto    = _kreadPtrH(socketAddr + socketSoProtoOff)
    let so_pcb      = _kreadPtrH(socketAddr + 0x80)
    let so_usecount = _kread32H(socketAddr + socketSoUsecntOff)
    let so_rcv_cc    = _kread32H(socketAddr + 0xA0)
    let so_rcv_hiwat = _kread32H(socketAddr + 0xA8)
    let so_snd_cc    = _kread32H(socketAddr + 0x120)
    let so_snd_hiwat = _kread32H(socketAddr + 0x128)

    let typeNames = [1: "SOCK_STREAM", 2: "SOCK_DGRAM", 3: "SOCK_RAW",
                     4: "SOCK_RDM", 5: "SOCK_SEQPACKET", 6: "SOCK_DCCP", 10: "SOCK_PACKET"]
    let typeStr = typeNames[Int(so_type)] ?? "UNKNOWN(\(so_type))"

    var stateFlags: [String] = []
    if (so_state & 0x001) != 0 { stateFlags.append("SS_NOFDREF") }
    if (so_state & 0x002) != 0 { stateFlags.append("SS_ISCONNECTED") }
    if (so_state & 0x004) != 0 { stateFlags.append("SS_ISCONNECTING") }
    if (so_state & 0x008) != 0 { stateFlags.append("SS_ISDISCONNECTING") }
    if (so_state & 0x010) != 0 { stateFlags.append("SS_CANTSENDMORE") }
    if (so_state & 0x020) != 0 { stateFlags.append("SS_CANTRCVMORE") }
    if (so_state & 0x040) != 0 { stateFlags.append("SS_RCVATMARK") }
    if (so_state & 0x080) != 0 { stateFlags.append("SS_PRIV") }
    if (so_state & 0x100) != 0 { stateFlags.append("SS_NBIO") }
    if (so_state & 0x200) != 0 { stateFlags.append("SS_ASYNC") }
    if (so_state & 0x400) != 0 { stateFlags.append("SS_ISCONFIRMING") }
    if (so_state & 0x800) != 0 { stateFlags.append("SS_INCOMP") }
    if (so_state & 0x1000) != 0 { stateFlags.append("SS_COMP") }
    if (so_state & 0x2000) != 0 { stateFlags.append("SS_ISDISCONNECTED") }
    let stateStr = stateFlags.isEmpty ? "0" : stateFlags.joined(separator: " | ")

    let lines = [
        String(format: "socket          : 0x%016llx", socketAddr),
        String(format: "so_type         : %@ (%d)", typeStr, so_type),
        String(format: "so_state        : 0x%08x (%@)", so_state, stateStr),
        String(format: "so_options      : 0x%08x", so_options),
        String(format: "so_proto        : 0x%016llx", so_proto),
        String(format: "so_pcb          : 0x%016llx", so_pcb),
        String(format: "so_usecount     : %d", so_usecount),
        String(format: "so_rcv          : cc=%d hiwat=%d", so_rcv_cc, so_rcv_hiwat),
        String(format: "so_snd          : cc=%d hiwat=%d", so_snd_cc, so_snd_hiwat),
    ]
    return lines.joined(separator: "\n")
}

// MARK: – socket-dump

private func _socketDump(fd: Int32, mgr: laramgr) -> String? {
    guard mgr.dsready else { return nil }

    let procPListLeNextOff = UInt64(off_proc_p_list_le_next)
    let procPPidOff = UInt64(off_proc_p_pid)
    let procPFdOff = UInt64(off_proc_p_fd)
    let filedescFdOfilesOff = UInt64(off_filedesc_fd_ofiles)
    let fileprocFpGlobOff = UInt64(off_fileproc_fp_glob)
    let fileglobFgDataOff = UInt64(off_fileglob_fg_data)

    let ourProc = ds_get_our_proc()
    guard ourProc != 0 else { return nil }

    var procPtr: UInt64 = 0
    var ptr = ourProc
    var seen = Set<UInt64>()
    let pid = getpid()
    while ptr != 0 && !seen.contains(ptr) {
        seen.insert(ptr)
        let p_pid = Int32(bitPattern: ds_kread32(ptr + procPPidOff))
        if p_pid == pid { procPtr = ptr; break }
        ptr = ds_kreadptr(ptr + procPListLeNextOff)
    }
    guard procPtr != 0 else { return nil }

    let fdPtr = _kreadPtrH(procPtr + procPFdOff)
    guard fdPtr != 0 else { return nil }
    let ofilesPtr = _kreadPtrH(fdPtr + filedescFdOfilesOff)
    guard ofilesPtr != 0 else { return nil }
    let fileprocPtr = _kreadPtrH(ofilesPtr + UInt64(fd) * 8)
    guard fileprocPtr != 0 else { return nil }
    let fileglobPtr = _kreadPtrH(fileprocPtr + fileprocFpGlobOff)
    guard fileglobPtr != 0 else { return nil }
    let socketAddr = _kreadPtrH(fileglobPtr + fileglobFgDataOff)
    guard socketAddr != 0 else { return nil }

    let dumpSize = 0x200
    var lines = [String(format: "socket-dump @ 0x%016llx  (%d bytes)", socketAddr, dumpSize), ""]

    let fieldMap: [UInt64: String] = [
        0x00: "so_list.le_next", 0x08: "so_list.le_prev",
        0x10: "so_type/so_family", 0x18: "so_state",
        0x20: "so_pcb", 0x28: "so_proto",
        0x30: "so_head", 0x38: "so_incomp",
        0x40: "so_comp", 0x48: "so_qlen/so_qlimit",
        0x50: "so_options", 0x58: "so_cred",
        0x60: "so_label", 0x68: "so_gencnt",
        0x70: "so_flags", 0x74: "so_usecount",
        0x78: "so_retaincnt", 0x7C: "so_filter",
        0x80: "so_rcv.sb_cc", 0x88: "so_rcv.sb_hiwat",
        0x90: "so_rcv.sb_mbcnt", 0x98: "so_rcv.sb_mbmax",
        0xA0: "so_rcv.sb_mtx", 0xA8: "so_rcv.sb_tstmp",
        0xB0: "so_snd.sb_cc", 0xB8: "so_snd.sb_hiwat",
        0xC0: "so_snd.sb_mbcnt", 0xC8: "so_snd.sb_mbmax",
        0xD0: "so_snd lowat/flags", 0xD8: "so_snd.sb_sel",
        0xE0: "so_snd.sb_mtx", 0xE8: "so_snd.sb_tstmp",
        0xF0: "so_upcall/arg", 0xF8: "so_cred2",
        0x100: "so_label2", 0x108: "so_gencnt2",
        0x110: "so_flags2", 0x118: "so_usecount2",
        0x120: "so_retaincnt2", 0x128: "so_filter2",
        0x130: "so_kern_ctl", 0x138: "so_acc_sas",
        0x140: "so_acc_sas_sz", 0x148: "so_ev_pcb",
        0x150: "so_ev_pcbarg", 0x158: "so_ev_state",
        0x160: "so_ev_rcvpending", 0x168: "so_traffic_mgt",
        0x170: "so_netsvctype", 0x178: "so_resv",
        0x180: "so_extended", 0x188: "so_waitq",
        0x190: "so_waitq_link", 0x198: "so_zone",
    ]

    for off in stride(from: 0, to: dumpSize, by: 8) {
        let val = _kread64H(socketAddr + UInt64(off))
        let desc = fieldMap[UInt64(off)] ?? "field_0x\(String(format: "%03X", off))"
        lines.append(String(format: "0x%03X  0x%016llx  %@", off, val, desc))
    }
    return lines.joined(separator: "\n")
}

// MARK: – socket-save / socket-diff helpers

private func _getSocketAddr(fd: Int, mgr: laramgr) -> UInt64? {
    guard mgr.dsready else { return nil }

    let procPListLeNextOff = UInt64(off_proc_p_list_le_next)
    let procPPidOff = UInt64(off_proc_p_pid)
    let procPFdOff = UInt64(off_proc_p_fd)
    let filedescFdOfilesOff = UInt64(off_filedesc_fd_ofiles)
    let fileprocFpGlobOff = UInt64(off_fileproc_fp_glob)
    let fileglobFgDataOff = UInt64(off_fileglob_fg_data)

    let ourProc = ds_get_our_proc()
    guard ourProc != 0 else { return nil }

    var procPtr: UInt64 = 0
    var ptr = ourProc
    var seen = Set<UInt64>()
    let pid = getpid()
    while ptr != 0 && !seen.contains(ptr) {
        seen.insert(ptr)
        let p_pid = Int32(bitPattern: ds_kread32(ptr + procPPidOff))
        if p_pid == pid { procPtr = ptr; break }
        ptr = ds_kreadptr(ptr + procPListLeNextOff)
    }
    guard procPtr != 0 else { return nil }
    let fdPtr = _kreadPtrH(procPtr + procPFdOff)
    guard fdPtr != 0 else { return nil }
    let ofilesPtr = _kreadPtrH(fdPtr + filedescFdOfilesOff)
    guard ofilesPtr != 0 else { return nil }
    let fileprocPtr = _kreadPtrH(ofilesPtr + UInt64(fd) * 8)
    guard fileprocPtr != 0 else { return nil }
    let fileglobPtr = _kreadPtrH(fileprocPtr + fileprocFpGlobOff)
    guard fileglobPtr != 0 else { return nil }
    return _kreadPtrH(fileglobPtr + fileglobFgDataOff)
}

// MARK: – Registration

func registerKernelObjectExplorer() {

    OmegaCore.register("fd-info") { arg, mgr in
        guard mgr.dsready else { return .fail("fd-info: kernel r/w not ready") }
        let parts = arg.split(separator: " ").map { String($0) }
        guard parts.count >= 2,
              let pid = _resolvePidH(parts[0]),
              let fd = Int32(parts[1]) else {
            return .fail("fd-info: usage — fd-info <pid|name> <fd>")
        }
        guard let out = _fdInfo(pid: pid, fd: fd, mgr: mgr) else {
            return .fail("fd-info: failed to resolve fd \(fd) for pid \(pid)")
        }
        return .ok(out)
    }

    OmegaCore.register("socket-info") { arg, mgr in
        guard mgr.dsready else { return .fail("socket-info: kernel r/w not ready") }
        guard let fd = Int32(arg.trimmingCharacters(in: .whitespaces)) else {
            return .fail("socket-info: usage — socket-info <fd>")
        }
        guard let out = _socketInfo(fd: fd, mgr: mgr) else {
            return .fail("socket-info: fd \(fd) is not a socket or not found")
        }
        return .ok(out)
    }

    OmegaCore.register("socket-info-addr") { arg, mgr in
        guard mgr.dsready else { return .fail("socket-info-addr: kernel r/w not ready") }
        guard let addr = _parseAddrH(arg) else {
            return .fail("socket-info-addr: usage — socket-info-addr <socket_addr_hex>")
        }
        guard let out = _socketInfoFromAddr(socketAddr: addr) else {
            return .fail("socket-info-addr: invalid socket address 0x\(String(format: "%llx", addr))")
        }
        return .ok(out)
    }

    OmegaCore.register("socket-dump") { arg, mgr in
        guard mgr.dsready else { return .fail("socket-dump: kernel r/w not ready") }
        guard let fd = Int32(arg.trimmingCharacters(in: .whitespaces)) else {
            return .fail("socket-dump: usage — socket-dump <fd>")
        }
        guard let out = _socketDump(fd: fd, mgr: mgr) else {
            return .fail("socket-dump: fd \(fd) is not a socket or not found")
        }
        return .ok(out)
    }

    OmegaCore.register("socket-save") { arg, mgr in
        guard mgr.dsready else { return .fail("socket-save: kernel r/w not ready") }
        guard let fd = Int(arg.trimmingCharacters(in: .whitespaces)) else {
            return .fail("socket-save: usage — socket-save <fd>")
        }
        guard let socketAddr = _getSocketAddr(fd: fd, mgr: mgr), socketAddr != 0 else {
            return .fail("socket-save: fd \(fd) is not a socket")
        }
        var data = Data()
        for off in stride(from: 0, to: 0x200, by: 8) {
            var val = _kread64H(socketAddr + UInt64(off))
            data.append(Data(bytes: &val, count: 8))
        }
        SocketSnapshotStore.shared.save(fd: fd, data: data)
        return .ok(String(format: "socket-save: fd=%d  socket@0x%llx  saved %d bytes", fd, socketAddr, data.count))
    }

    OmegaCore.register("socket-diff") { arg, mgr in
        guard mgr.dsready else { return .fail("socket-diff: kernel r/w not ready") }
        guard let fd = Int(arg.trimmingCharacters(in: .whitespaces)) else {
            return .fail("socket-diff: usage — socket-diff <fd>")
        }
        guard let (timestamp, before) = SocketSnapshotStore.shared.load(fd: fd) else {
            return .fail("socket-diff: no snapshot for fd \(fd). Run 'socket-save <fd>' first.")
        }
        guard let socketAddr = _getSocketAddr(fd: fd, mgr: mgr), socketAddr != 0 else {
            return .fail("socket-diff: fd \(fd) is not a socket")
        }
        var after = Data()
        for off in stride(from: 0, to: 0x200, by: 8) {
            var val = _kread64H(socketAddr + UInt64(off))
            after.append(Data(bytes: &val, count: 8))
        }
        guard before.count == after.count else {
            return .fail("socket-diff: size mismatch")
        }
        var diffs: [(Int, UInt64, UInt64)] = []
        for i in stride(from: 0, to: before.count, by: 8) {
            let b = before.withUnsafeBytes { $0.load(fromByteOffset: i, as: UInt64.self) }
            let a = after.withUnsafeBytes { $0.load(fromByteOffset: i, as: UInt64.self) }
            if b != a { diffs.append((i, b, a)) }
        }
        if diffs.isEmpty {
            return .ok("socket-diff: fd=\(fd)  no changes since \(timestamp)")
        }
        var lines = [
            String(format: "socket-diff: fd=%d  socket@0x%llx", fd, socketAddr),
            "  saved: \(timestamp)",
            "  changed offsets: \(diffs.count)", ""
        ]
        for (off, b, a) in diffs {
            lines.append(String(format: "Offset 0x%03X:", off))
            lines.append(String(format: "  before: 0x%016llx", b))
            lines.append(String(format: "  after : 0x%016llx", a))
            lines.append("")
        }
        return .ok(lines.joined(separator: "\n"))
    }
}
