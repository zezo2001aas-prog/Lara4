//
//  OmegaExtendedN.swift
//  lara — Snapshot Engine
//  snapshot, snapshot-diff
//

import Foundation
import Darwin

private struct KernelSnapshot: Codable {
    let timestamp: Date
    let procAddr: UInt64
    let taskAddr: UInt64
    let ucredAddr: UInt64
    let socketAddr: UInt64
    let vmMapAddr: UInt64
    let procData: Data
    let taskData: Data
    let ucredData: Data
    let socketData: Data
    let vmMapData: Data
}

private final class SnapshotStore {
    static let shared = SnapshotStore()
    private var snapshots: [String: KernelSnapshot] = [:]
    private let lock = NSLock()

    func save(id: String, snapshot: KernelSnapshot) {
        lock.lock(); defer { lock.unlock() }
        snapshots[id] = snapshot
    }
    func load(id: String) -> KernelSnapshot? {
        lock.lock(); defer { lock.unlock() }
        return snapshots[id]
    }
    func clear(id: String) {
        lock.lock(); defer { lock.unlock() }
        snapshots.removeValue(forKey: id)
    }
    func list() -> [String] {
        lock.lock(); defer { lock.unlock() }
        return Array(snapshots.keys)
    }
}

private func _kreadPtrN(_ addr: UInt64) -> UInt64 {
    guard addr != 0, ds_isvalid(addr) else { return 0 }
    return ds_kreadptr(addr)
}

private func _kread64N(_ addr: UInt64) -> UInt64 {
    guard addr != 0, ds_isvalid(addr) else { return 0 }
    return ds_kread64(addr)
}

// MARK: – snapshot kernel

private func _snapshotKernel() -> String? {
    guard ourProc != 0 else { return nil }

    let procRo = _kreadPtrN(ourProc + procPProcRoOff)
    let taskPtr = _kreadPtrN(procRo + procRoPrTaskOff)
    let ucredPtr = _kreadPtrN(procRo + procRoPUcredOff)
    let vmMapPtr = _kreadPtrN(taskPtr + taskMapOff)

    var socketAddr: UInt64 = 0
    let fdPtr = _kreadPtrN(ourProc + procPFdOff)
    if fdPtr != 0 {
        let ofilesPtr = _kreadPtrN(fdPtr + filedescFdOfilesOff)
        if ofilesPtr != 0 {
            for fd in 0..<32 {
                let fileprocPtr = _kreadPtrN(ofilesPtr + UInt64(fd) * 8)
                if fileprocPtr != 0 {
                    let fileglobPtr = _kreadPtrN(fileprocPtr + fileprocFpGlobOff)
                    if fileglobPtr != 0 {
                        let fg_data = _kreadPtrN(fileglobPtr + fileglobFgDataOff)
                        if fg_data != 0 {
                            let so_type = ds_kread32(fg_data + 0x04)
                            if so_type >= 1 && so_type <= 10 { socketAddr = fg_data; break }
                        }
                    }
                }
            }
        }
    }

    func readData(_ addr: UInt64, size: Int) -> Data {
        guard addr != 0 else { return Data() }
        var data = Data()
        for off in stride(from: 0, to: size, by: 8) {
            var val = _kread64N(addr + UInt64(off))
            data.append(Data(bytes: &val, count: 8))
        }
        return data
    }

    let snap = KernelSnapshot(
        timestamp: Date(),
        procAddr: ourProc,
        taskAddr: taskPtr,
        ucredAddr: ucredPtr,
        socketAddr: socketAddr,
        vmMapAddr: vmMapPtr,
        procData: readData(ourProc, size: 0x100),
        taskData: readData(taskPtr, size: 0x100),
        ucredData: readData(ucredPtr, size: 0x80),
        socketData: readData(socketAddr, size: 0x200),
        vmMapData: readData(vmMapPtr, size: 0x80)
    )

    SnapshotStore.shared.save(id: "kernel", snapshot: snap)

    return String(format:
        "snapshot kernel: saved at %@\n" +
        "  proc    @ 0x%016llx  (%d bytes)\n" +
        "  task    @ 0x%016llx  (%d bytes)\n" +
        "  ucred   @ 0x%016llx  (%d bytes)\n" +
        "  socket  @ 0x%016llx  (%d bytes)\n" +
        "  vm_map  @ 0x%016llx  (%d bytes)",
        snap.timestamp as NSDate,
        snap.procAddr, snap.procData.count,
        snap.taskAddr, snap.taskData.count,
        snap.ucredAddr, snap.ucredData.count,
        snap.socketAddr, snap.socketData.count,
        snap.vmMapAddr, snap.vmMapData.count
    )
}

// MARK: – snapshot diff

private func _snapshotDiff() -> String? {
    guard let before = SnapshotStore.shared.load(id: "kernel") else {
        return "snapshot diff: no snapshot saved. Run 'snapshot kernel' first."
    }

    let ourProc = ds_get_our_proc()
    guard ourProc != 0 else { return nil }

    let procRo = _kreadPtrN(ourProc + UInt64(off_proc_p_proc_ro))
    let taskPtr = _kreadPtrN(procRo + UInt64(off_proc_ro_pr_task))
    let ucredPtr = _kreadPtrN(procRo + UInt64(off_proc_ro_p_ucred))
    let vmMapPtr = _kreadPtrN(taskPtr + UInt64(off_task_map))

    var socketAddr: UInt64 = 0
    let fdPtr = _kreadPtrN(ourProc + UInt64(off_proc_p_fd))
    if fdPtr != 0 {
        let ofilesPtr = _kreadPtrN(fdPtr + UInt64(off_filedesc_fd_ofiles))
        if ofilesPtr != 0 {
            for fd in 0..<32 {
                let fileprocPtr = _kreadPtrN(ofilesPtr + UInt64(fd) * 8)
                if fileprocPtr != 0 {
                    let fileglobPtr = _kreadPtrN(fileprocPtr + UInt64(off_fileproc_fp_glob))
                    if fileglobPtr != 0 {
                        let fg_data = _kreadPtrN(fileglobPtr + UInt64(off_fileglob_fg_data))
                        if fg_data != 0 {
                            let so_type = ds_kread32(fg_data + 0x04)
                            if so_type >= 1 && so_type <= 10 { socketAddr = fg_data; break }
                        }
                    }
                }
            }
        }
    }

    func readData(_ addr: UInt64, size: Int) -> Data {
        guard addr != 0 else { return Data() }
        var data = Data()
        for off in stride(from: 0, to: size, by: 8) {
            var val = _kread64N(addr + UInt64(off))
            data.append(Data(bytes: &val, count: 8))
        }
        return data
    }

    let after = KernelSnapshot(
        timestamp: Date(),
        procAddr: ourProc,
        taskAddr: taskPtr,
        ucredAddr: ucredPtr,
        socketAddr: socketAddr,
        vmMapAddr: vmMapPtr,
        procData: readData(ourProc, size: 0x100),
        taskData: readData(taskPtr, size: 0x100),
        ucredData: readData(ucredPtr, size: 0x80),
        socketData: readData(socketAddr, size: 0x200),
        vmMapData: readData(vmMapPtr, size: 0x80)
    )

    func diffData(name: String, before: Data, after: Data, addr: UInt64) -> [String] {
        guard before.count == after.count else {
            return ["\(name): size mismatch (before=\(before.count) after=\(after.count))"]
        }
        var lines: [String] = []
        var diffs: [(Int, UInt64, UInt64)] = []
        for i in stride(from: 0, to: before.count, by: 8) {
            let b = before.withUnsafeBytes { $0.load(fromByteOffset: i, as: UInt64.self) }
            let a = after.withUnsafeBytes { $0.load(fromByteOffset: i, as: UInt64.self) }
            if b != a { diffs.append((i, b, a)) }
        }
        if diffs.isEmpty {
            lines.append("\(name): no changes")
        } else {
            lines.append("\(name): \(diffs.count) changes")
            for (off, b, a) in diffs.prefix(8) {
                lines.append(String(format: "  0x%03X: 0x%016llx -> 0x%016llx", off, b, a))
            }
            if diffs.count > 8 { lines.append("  ... and \(diffs.count - 8) more") }
        }
        return lines
    }

    var lines = [
        "snapshot diff:",
        "  before: \(before.timestamp)",
        "  after : \(after.timestamp)",
        ""
    ]

    lines += diffData(name: "proc",   before: before.procData,   after: after.procData,   addr: before.procAddr)
    lines += diffData(name: "task",   before: before.taskData,   after: after.taskData,   addr: before.taskAddr)
    lines += diffData(name: "ucred",  before: before.ucredData,  after: after.ucredData,  addr: before.ucredAddr)
    lines += diffData(name: "socket", before: before.socketData, after: after.socketData, addr: before.socketAddr)
    lines += diffData(name: "vm_map", before: before.vmMapData,  after: after.vmMapData,  addr: before.vmMapAddr)

    return lines.joined(separator: "\n")
}

// MARK: – Registration

func registerSnapshotEngine() {

    OmegaCore.register("snapshot") { arg, mgr in
        guard mgr.dsready else { return .fail("snapshot: kernel r/w not ready") }
        let a = arg.trimmingCharacters(in: .whitespaces).lowercased()
        guard a == "kernel" else {
            return .fail("snapshot: usage — snapshot kernel")
        }
        guard let out = _snapshotKernel() else {
            return .fail("snapshot: failed to capture kernel snapshot")
        }
        return .ok(out)
    }

    OmegaCore.register("snapshot-diff") { _, mgr in
        guard mgr.dsready else { return .fail("snapshot-diff: kernel r/w not ready") }
        guard let out = _snapshotDiff() else {
            return .fail("snapshot-diff: failed to compute diff")
        }
        return .ok(out)
    }
}
