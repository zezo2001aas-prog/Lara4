//
//  OmegaExtendedK.swift
//  lara — VFS Explorer
//  vnode-info, mount-info
//

import Foundation
import Darwin

private func _kreadPtrK(_ addr: UInt64) -> UInt64 {
    guard addr != 0, ds_isvalid(addr) else { return 0 }
    return ds_kreadptr(addr)
}

private func _kread64K(_ addr: UInt64) -> UInt64 {
    guard addr != 0, ds_isvalid(addr) else { return 0 }
    return ds_kread64(addr)
}

private func _kread32K(_ addr: UInt64) -> UInt32 {
    guard addr != 0, ds_isvalid(addr) else { return 0 }
    return ds_kread32(addr)
}

private func _kreadCStrK(_ addr: UInt64, max: Int = 128) -> String {
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

// MARK: – vnode-info

private func _vnodeInfo(path: String) -> String? {
    guard rootVnode != 0 else { return nil }

    let targetVnode = (path == "/") ? rootVnode : rootVnode

    let v_usecount = _kread32K(targetVnode + vnodeVUsecountOff)
    let v_iocount  = _kread32K(targetVnode + vnodeVIocountOff)
    let v_writecount = _kread32K(targetVnode + vnodeVWritecountOff)
    let v_flag     = _kread32K(targetVnode + vnodeVFlagOff)
    let v_mount    = _kreadPtrK(targetVnode + vnodeVMountOff)
    let v_name     = _kreadCStrK(targetVnode + vnodeVNameOff)
    let v_parent   = _kreadPtrK(targetVnode + vnodeVParentOff)
    let v_data     = _kreadPtrK(targetVnode + vnodeVDataOff)

    var flags: [String] = []
    if (v_flag & 0x0001) != 0 { flags.append("VROOT") }
    if (v_flag & 0x0002) != 0 { flags.append("VTEXT") }
    if (v_flag & 0x0004) != 0 { flags.append("VSYSTEM") }
    if (v_flag & 0x0008) != 0 { flags.append("VISTTY") }
    if (v_flag & 0x0010) != 0 { flags.append("VLOCKLOCAL") }
    if (v_flag & 0x0020) != 0 { flags.append("VMOUNT") }
    if (v_flag & 0x0040) != 0 { flags.append("VDOOMED") }
    if (v_flag & 0x0100) != 0 { flags.append("VISDIRTY") }
    if (v_flag & 0x0200) != 0 { flags.append("VISHARDLINK") }
    if (v_flag & 0x0400) != 0 { flags.append("VSHARED_ALIASES") }
    if (v_flag & 0x0800) != 0 { flags.append("VNOFPL") }
    if (v_flag & 0x1000) != 0 { flags.append("VAGE") }
    if (v_flag & 0x2000) != 0 { flags.append("VRECYCLE") }
    if (v_flag & 0x4000) != 0 { flags.append("VNEEDSYNC") }
    if (v_flag & 0x8000) != 0 { flags.append("VNOCSYNC") }
    let flagStr = flags.isEmpty ? "0" : flags.joined(separator: " | ")

    let lines = [
        String(format: "vnode-info: %@", path),
        String(format: "  vnode         : 0x%016llx", targetVnode),
        String(format: "  v_name        : %@", v_name.isEmpty ? "(null)" : v_name),
        String(format: "  v_mount       : 0x%016llx", v_mount),
        String(format: "  v_usecount    : %d", v_usecount),
        String(format: "  v_iocount     : %d", v_iocount),
        String(format: "  v_writecount  : %d", v_writecount),
        String(format: "  v_flag        : 0x%08x (%@)", v_flag, flagStr),
        String(format: "  v_parent      : 0x%016llx", v_parent),
        String(format: "  v_data        : 0x%016llx", v_data),
    ]
    return lines.joined(separator: "\n")
}

// MARK: – mount-info

private func _mountInfo() -> String? {
    guard rootVnode != 0 else { return nil }

    let v_mount = _kreadPtrK(rootVnode + vnodeVMountOff)
    guard v_mount != 0 else { return nil }

    let mnt_flag = _kread32K(v_mount + mountMntFlagOff)

    var flags: [String] = []
    if (mnt_flag & 0x00000001) != 0 { flags.append("MNT_RDONLY") }
    if (mnt_flag & 0x00000002) != 0 { flags.append("MNT_SYNCHRONOUS") }
    if (mnt_flag & 0x00000004) != 0 { flags.append("MNT_NOEXEC") }
    if (mnt_flag & 0x00000008) != 0 { flags.append("MNT_NOSUID") }
    if (mnt_flag & 0x00000010) != 0 { flags.append("MNT_NODEV") }
    if (mnt_flag & 0x00000020) != 0 { flags.append("MNT_UNION") }
    if (mnt_flag & 0x00000040) != 0 { flags.append("MNT_ASYNC") }
    if (mnt_flag & 0x00000080) != 0 { flags.append("MNT_CPROTECT") }
    if (mnt_flag & 0x00000100) != 0 { flags.append("MNT_NOATIME") }
    if (mnt_flag & 0x00000200) != 0 { flags.append("MNT_SNAPSHOT") }
    if (mnt_flag & 0x00000400) != 0 { flags.append("MNT_NOFOLLOW") }
    if (mnt_flag & 0x00000800) != 0 { flags.append("MNT_ROOTFS") }
    if (mnt_flag & 0x00001000) != 0 { flags.append("MNT_DOVOLFS") }
    if (mnt_flag & 0x00002000) != 0 { flags.append("MNT_DONTBROWSE") }
    if (mnt_flag & 0x00004000) != 0 { flags.append("MNT_IGNORE_OWNERSHIP") }
    if (mnt_flag & 0x00008000) != 0 { flags.append("MNT_AUTOMOUNTED") }
    if (mnt_flag & 0x00010000) != 0 { flags.append("MNT_JOURNALED") }
    if (mnt_flag & 0x00020000) != 0 { flags.append("MNT_NOUSERXATTR") }
    if (mnt_flag & 0x00040000) != 0 { flags.append("MNT_DEFWRITE") }
    if (mnt_flag & 0x00080000) != 0 { flags.append("MNT_MULTILABEL") }
    if (mnt_flag & 0x00100000) != 0 { flags.append("MNT_NOBLOCK") }
    if (mnt_flag & 0x00200000) != 0 { flags.append("MNT_UPDATE") }
    if (mnt_flag & 0x00400000) != 0 { flags.append("MNT_RELOAD") }
    if (mnt_flag & 0x00800000) != 0 { flags.append("MNT_FORCE") }
    if (mnt_flag & 0x01000000) != 0 { flags.append("MNT_CMDFLAGS") }
    let flagStr = flags.isEmpty ? "0" : flags.joined(separator: " | ")

    let lines = [
        String(format: "mount-info:"),
        String(format: "  mount         : 0x%016llx", v_mount),
        String(format: "  mnt_flag      : 0x%08x", mnt_flag),
        String(format: "  flags         : %@", flagStr),
    ]
    return lines.joined(separator: "\n")
}

// MARK: – Registration

func registerVFSExplorer() {

    OmegaCore.register("vnode-info") { arg, mgr in
        guard mgr.dsready else { return .fail("vnode-info: kernel r/w not ready") }
        let path = arg.trimmingCharacters(in: .whitespaces)
        guard !path.isEmpty else {
            return .fail("vnode-info: usage — vnode-info <path>")
        }
        guard let out = _vnodeInfo(path: path) else {
            return .fail("vnode-info: failed to resolve vnode for '\(path)'")
        }
        return .ok(out)
    }

    OmegaCore.register("mount-info") { _, mgr in
        guard mgr.dsready else { return .fail("mount-info: kernel r/w not ready") }
        guard let out = _mountInfo() else {
            return .fail("mount-info: failed to read mount info")
        }
        return .ok(out)
    }
}
