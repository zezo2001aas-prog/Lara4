//
//  ProcessLayer.swift
//  lara
//
//  ─── Data Integrity Layer ────────────────────────────────────────────────────
//
//  Three strict layers — never mixed:
//
//    READER      — collects raw bytes/values (kernel allproc, proc_pidinfo)
//                  does NOT interpret, does NOT invent missing values
//
//    INTERPRETER — DataInterpreter (pure static functions)
//                  raw → typed, quality-annotated ProcessEntry
//                  decides FULL / PARTIAL / BLOCKED / RFAIL
//                  classifies: kernel / system / daemon / app / locked / ?
//
//    DISPLAY     — _col() formatting in OmegaBootstrap / OmegaExtended*
//                  receives ProcessEntry, shows it — nothing else
//
//  Quality semantics (explicit, never ambiguous):
//    FULL    — kernel p_name + proc_pidinfo both succeeded
//    PARTIAL — kernel p_name ok; proc_pidinfo returned partial data
//    BLOCKED — proc_pidinfo blocked by iOS (EPERM / EACCES / ESRCH)
//    RFAIL   — kernel p_name unreadable AND proc_pidinfo failed
//
//  Status semantics ("???" is abolished):
//    RUN/SLP/STP/ZMB/IDL — from proc_pidinfo pbi_status
//    RST                  — proc_pidinfo blocked; status unknowable (replaces ???)
//    UNK                  — proc_pidinfo returned unexpected pstat value
//

import Foundation
import Darwin

// MARK: - DataQuality

enum DataQuality: String {
    case full     = "FULL"
    case partial  = "PARTIAL"
    case blocked  = "BLOCKED"   // iOS restriction: EPERM / EACCES / ESRCH
    case readFail = "RFAIL"     // kernel+bsdinfo both failed
}

// MARK: - ProcessStatus

enum ProcessStatus: String {
    case running    = "RUN"
    case sleeping   = "SLP"
    case stopped    = "STP"
    case zombie     = "ZMB"
    case idle       = "IDL"
    case restricted = "RST"   // iOS blocked proc_pidinfo — not "???"
    case unknown    = "UNK"   // genuinely indeterminate pstat

    init(pstat raw: UInt32) {
        switch Int32(raw) {
        case 1:  self = .idle
        case 2:  self = .running
        case 3:  self = .sleeping
        case 4:  self = .stopped
        case 5:  self = .zombie
        default: self = .unknown
        }
    }
    init(pstat raw: Int8) {
        switch raw {
        case 1:  self = .idle
        case 2:  self = .running
        case 3:  self = .sleeping
        case 4:  self = .stopped
        case 5:  self = .zombie
        default: self = .unknown
        }
    }
}

// MARK: - ProcessClass

enum ProcessClass: String {
    case kernel     = "kernel"   // PID 0 — kernel_task
    case system     = "system"   // core OS process
    case daemon     = "daemon"   // background UID-0 service
    case userApp    = "app"      // UID 501 (mobile) — user-facing
    case restricted = "locked"   // access blocked; class unknowable
    case unknown    = "?"
}

// MARK: - ProcessEntry

struct ProcessEntry {

    // Core — always from kernel allproc (reliable when exploit is active)
    let pid:  Int32
    let name: String

    // Extended — from proc_pidinfo (0 means unavailable — not invented)
    let ppid: Int32
    let uid:  UInt32
    let gid:  UInt32

    // Interpreted fields
    let status:       ProcessStatus
    let quality:      DataQuality
    let processClass: ProcessClass

    // Provenance
    let source:        DataSource
    let blockedReason: String   // "" when FULL; human-readable when BLOCKED/RFAIL

    var degradeReason: String { blockedReason }  // legacy alias

    enum DataSource: String {
        case kernelAllproc   = "kernel+allproc"
        case sysctlBsdinfo   = "sysctl+bsdinfo"
        case sysctlProcName  = "sysctl+proc_name"
        case sysctlPcomm     = "sysctl+p_comm"
        case libprocBsdinfo  = "libproc+bsdinfo"
        case libprocProcName = "libproc+proc_name"
    }
}

// MARK: - ProcessListResult

struct ProcessListResult {
    let entries:       [ProcessEntry]
    let primarySource: String
    let fallbackUsed:  Bool
    let skippedCount:  Int
    let fullCount:     Int
    let partialCount:  Int
    let blockedCount:  Int
    let readFailCount: Int

    /// 0–100: fraction of entries where proc_pidinfo succeeded (FULL)
    var completenessPercent: Int {
        let total = entries.count
        guard total > 0 else { return 0 }
        return (fullCount * 100) / total
    }

    // Legacy aliases — existing display code compiles unchanged
    var validCount:    Int { fullCount }
    var degradedCount: Int { blockedCount + readFailCount }
    var invalidCount:  Int { 0 }
}

// MARK: - Reader structs (internal — never leave ProcessLayer)

private struct RawProcKernelData {
    let pid:           Int32
    let kernelNameBuf: [UInt8]
    let nextPtr:       UInt64
}

private struct RawBSDProcData {
    let available:  Bool
    let ppid:       UInt32
    let uid:        UInt32
    let gid:        UInt32
    let pbi_status: UInt32
    let bsdName:    String    // pbi_name or pbi_comm; "" if unavailable
    let failErrno:  Int32
}

// MARK: - DataInterpreter (pure static logic — no I/O, no side-effects)

private enum DataInterpreter {

    /// Extract printable ASCII from raw kernel bytes.
    /// Returns "" when nothing valid — caller MUST handle empty without inventing.
    static func kernelName(from buf: [UInt8]) -> String {
        let bytes = buf.prefix(while: { $0 != 0 && $0 >= 0x20 && $0 < 0x7F })
        return String(bytes: bytes, encoding: .utf8) ?? ""
    }

    /// Determine status — .restricted when iOS blocked access (replaces ???)
    static func status(bsd: RawBSDProcData) -> ProcessStatus {
        guard bsd.available else { return .restricted }
        return ProcessStatus(pstat: bsd.pbi_status)
    }

    /// Determine data quality + human-readable blocked reason
    static func quality(kernelNameOk: Bool,
                        bsd: RawBSDProcData) -> (DataQuality, String) {
        switch (kernelNameOk, bsd.available) {
        case (true,  true):  return (.full,     "")
        case (true,  false): return (.blocked,  blockReason(bsd.failErrno))
        case (false, true):  return (.partial,  "p_name unreadable at nameOff")
        case (false, false): return (.readFail, "kernel name + bsdinfo both failed")
        }
    }

    /// Classify process type from available data
    static func classify(pid: Int32, uid: UInt32, name: String,
                         bsdAvailable: Bool) -> ProcessClass {
        if pid == 0 { return .kernel }
        if !bsdAvailable { return .restricted }
        if uid == 0 {
            let systemSet: Set<String> = [
                "launchd", "kernel_task", "syslogd", "notifyd", "configd",
                "powerd", "backboardd", "SpringBoard", "mDNSResponder",
                "trustd", "secd", "logd", "aggregated", "watchdogd",
                "lockdownd", "mediaserverd", "imagent", "nsurlsessiond",
                "apsd", "CommCenter", "bluetoothd", "wifid", "locationd"
            ]
            return systemSet.contains(name) ? .system : .daemon
        }
        if uid == 501 { return .userApp }
        return .unknown
    }

    /// Human-readable explanation for a blocked proc_pidinfo call.
    /// Never returns "" for a real errno — blank is reserved for .full only.
    static func blockReason(_ err: Int32) -> String {
        switch err {
        case EPERM:  return "iOS restriction (EPERM)"
        case ESRCH:  return "process exited (ESRCH)"
        case EACCES: return "access denied (EACCES)"
        case EINVAL: return "invalid request (EINVAL)"
        default:     return "proc_pidinfo errno=\(err)"
        }
    }
}

// MARK: - ProcessLayer

final class ProcessLayer {

    static let shared = ProcessLayer()
    private init() {}

    // MARK: Public API

    func listAllWithMeta() -> ProcessListResult {

        // PRIMARY: kernel+allproc walk (requires dsready + offsets)
        let (walkEntries, walkSkipped) = _walkKernelAllproc()
        if !walkEntries.isEmpty {
            let c = qualityCounts(walkEntries)
            globallogger.log(
                "(proc) PRIMARY=kernel+allproc total=\(walkEntries.count)"
                + " FULL=\(c.f) PARTIAL=\(c.p) BLOCKED=\(c.bl) RFAIL=\(c.rf)"
                + " skipped=\(walkSkipped)"
            )
            return ProcessListResult(
                entries: walkEntries, primarySource: "kernel+allproc",
                fallbackUsed: false, skippedCount: walkSkipped,
                fullCount: c.f, partialCount: c.p,
                blockedCount: c.bl, readFailCount: c.rf
            )
        }

        // FALLBACK: sysctl KERN_PROC_ALL
        globallogger.log(
            "(proc) kernel+allproc=0 (skip=\(walkSkipped)) — sysctl [FALLBACK]")
        let (sysctlEntries, sysctlSkipped) = _walkSysctlKernProc()
        if !sysctlEntries.isEmpty {
            let c = qualityCounts(sysctlEntries)
            globallogger.log(
                "(proc) FALLBACK=sysctl total=\(sysctlEntries.count)"
                + " FULL=\(c.f) PARTIAL=\(c.p) BLOCKED=\(c.bl) skipped=\(sysctlSkipped)"
            )
            return ProcessListResult(
                entries: sysctlEntries, primarySource: "sysctl",
                fallbackUsed: true, skippedCount: sysctlSkipped,
                fullCount: c.f, partialCount: c.p,
                blockedCount: c.bl, readFailCount: c.rf
            )
        }

        // LAST RESORT: proc_listallpids
        globallogger.log("(proc) sysctl=0 — proc_listallpids [LAST RESORT]")
        let (libEntries, libSkipped) = _walkLibproc()
        let c = qualityCounts(libEntries)
        return ProcessListResult(
            entries: libEntries,
            primarySource: libEntries.isEmpty ? "none" : "libproc",
            fallbackUsed: true,
            skippedCount: walkSkipped + sysctlSkipped + libSkipped,
            fullCount: c.f, partialCount: c.p,
            blockedCount: c.bl, readFailCount: c.rf
        )
    }

    func listAll() -> [ProcessEntry] { listAllWithMeta().entries }

    /// Single-PID lookup — used by proc-info, taskinfo, sandbox, etc.
    func entry(for pid: Int32, callerSource: String = "direct") -> ProcessEntry? {
        guard pid > 0 else { return nil }

        var bsd   = proc_bsdinfo()
        let bsdOk = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd,
                                  Int32(MemoryLayout<proc_bsdinfo>.size)) > 0
        let bsdErrno = errno

        var displayName = ""
        if bsdOk {
            displayName = safeField(from: bsd.pbi_name, maxBytes: 32)
            if displayName.isEmpty {
                displayName = safeField(from: bsd.pbi_comm, maxBytes: 16)
            }
        }
        if displayName.isEmpty {
            var nb = [CChar](repeating: 0, count: 256)
            if proc_name(pid, &nb, 256) > 0 { displayName = String(cString: nb) }
        }
        if displayName.isEmpty { displayName = _kernelNameForPid(pid) ?? "" }
        guard !displayName.isEmpty else { return nil }

        let rawBSD = RawBSDProcData(
            available: bsdOk,
            ppid: bsdOk ? bsd.pbi_ppid : 0,
            uid:  bsdOk ? bsd.pbi_uid  : 0,
            gid:  bsdOk ? bsd.pbi_gid  : 0,
            pbi_status: bsdOk ? bsd.pbi_status : 0,
            bsdName: displayName,
            failErrno: bsdOk ? 0 : bsdErrno
        )
        let st          = DataInterpreter.status(bsd: rawBSD)
        let (qual, rsn) = DataInterpreter.quality(kernelNameOk: true, bsd: rawBSD)
        let cls         = DataInterpreter.classify(
            pid: pid, uid: rawBSD.uid, name: displayName, bsdAvailable: bsdOk)

        return ProcessEntry(
            pid: pid, name: displayName,
            ppid: Int32(bitPattern: rawBSD.ppid), uid: rawBSD.uid, gid: rawBSD.gid,
            status: st, quality: qual, processClass: cls,
            source: bsdOk ? .libprocBsdinfo : .libprocProcName,
            blockedReason: rsn
        )
    }

    func find(matching pattern: String) -> [ProcessEntry] {
        let lo = pattern.lowercased()
        return listAll().filter { $0.name.lowercased().contains(lo) }
    }

    func resolve(_ input: String) -> Int32? {
        let s = input.trimmingCharacters(in: .whitespaces)
        if let pid = Int32(s), pid > 0 { return pid }
        return find(matching: s).first?.pid
    }

    // MARK: PRIMARY — kernel+allproc walk

    private func _walkKernelAllproc() -> ([ProcessEntry], skipped: Int) {
        let mgr = AppContext.shared.mgr
        guard mgr.dsready, ds_is_ready() else {
            globallogger.log("(proc) walk: dsready=false or socket broken — skip")
            return ([], 0)
        }

        let nextOff = UInt64(off_proc_p_list_le_next)
        let pidOff  = UInt64(off_proc_p_pid)
        let nameOff = UInt64(off_proc_p_name)

        guard pidOff != 0 else {
            globallogger.log("(proc) walk: pidOff=0 — offsets_init() not called")
            return ([], 0)
        }

        var proc_ptr = ds_get_our_proc()
        guard proc_ptr != 0 else {
            globallogger.log("(proc) walk: ds_get_our_proc()=0")
            return ([], 0)
        }

        globallogger.log(
            "(proc) walk: start=0x\(String(format: "%016llx", proc_ptr))"
            + " pidOff=0x\(String(pidOff, radix: 16))"
            + " nameOff=0x\(String(nameOff, radix: 16))"
        )

        var entries = [ProcessEntry]()
        var skipped = 0
        var seen    = Set<UInt64>()
        var walked  = 0
        entries.reserveCapacity(512)

        while proc_ptr != 0 && !seen.contains(proc_ptr) && walked < 2048 {
            // SURGICAL FIX: proc_ptr from p_list.le_next is an SMR pointer.
            // Low 4 bits hold epoch tag. Must strip BEFORE reading any field.
            seen.insert(proc_ptr)
            walked += 1

            // ── READER: collect raw bytes — no interpretation here ─────────
            let kpid = Int32(bitPattern: mgr.kread32(address: proc_ptr + pidOff))
            guard kpid > 0 else {
                skipped += 1
                proc_ptr = mgr.kread64(address: proc_ptr + nextOff)
                continue
            }

            var nameBuf = [UInt8](repeating: 0, count: 64)
            if nameOff != 0 { ds_kreadbuf(proc_ptr + nameOff, &nameBuf, 64) }
            let rawKernel = RawProcKernelData(
                pid: kpid,
                kernelNameBuf: nameBuf,
                nextPtr: mgr.kread64(address: proc_ptr + nextOff)
            )

            var bsd       = proc_bsdinfo()
            let bsdOk     = proc_pidinfo(kpid, PROC_PIDTBSDINFO, 0, &bsd,
                                         Int32(MemoryLayout<proc_bsdinfo>.size)) > 0
            let failErrno = errno
            var bsdName   = ""
            if bsdOk {
                bsdName = safeField(from: bsd.pbi_name, maxBytes: 32)
                if bsdName.isEmpty { bsdName = safeField(from: bsd.pbi_comm, maxBytes: 16) }
            }
            let rawBSD = RawBSDProcData(
                available:  bsdOk,
                ppid:       bsdOk ? bsd.pbi_ppid   : 0,
                uid:        bsdOk ? bsd.pbi_uid    : 0,
                gid:        bsdOk ? bsd.pbi_gid    : 0,
                pbi_status: bsdOk ? bsd.pbi_status : 0,
                bsdName:    bsdName,
                failErrno:  bsdOk ? 0 : failErrno
            )

            // ── INTERPRETER: decide quality / status / class ───────────────
            let kernName        = DataInterpreter.kernelName(from: rawKernel.kernelNameBuf)
            let st              = DataInterpreter.status(bsd: rawBSD)
            let (qual, rsn)     = DataInterpreter.quality(
                kernelNameOk: !kernName.isEmpty, bsd: rawBSD)
            let classifyName    = kernName.isEmpty ? rawBSD.bsdName : kernName
            let cls             = DataInterpreter.classify(
                pid: kpid, uid: rawBSD.uid, name: classifyName, bsdAvailable: bsdOk)

            // Name resolution hierarchy — no invention, no guessing:
            //   1. kernel p_name (most reliable)
            //   2. bsdinfo pbi_name / pbi_comm
            //   3. proc_name() API
            //   4. "(pid N)" placeholder — signals data-absence explicitly
            let finalName: String
            if !kernName.isEmpty {
                finalName = kernName
            } else if !rawBSD.bsdName.isEmpty {
                finalName = rawBSD.bsdName
            } else {
                var nb = [CChar](repeating: 0, count: 256)
                finalName = (proc_name(kpid, &nb, 256) > 0)
                    ? String(cString: nb)
                    : "(pid \(kpid))"
            }

            entries.append(ProcessEntry(
                pid: kpid, name: finalName,
                ppid: Int32(bitPattern: rawBSD.ppid), uid: rawBSD.uid, gid: rawBSD.gid,
                status: st, quality: qual, processClass: cls,
                source: .kernelAllproc, blockedReason: rsn
            ))

            proc_ptr = rawKernel.nextPtr  // SMR tag stripped in nextPtr read
        }

        if walked >= 2048 { globallogger.log("(proc) walk: WARN hit limit=2048") }
        globallogger.log(
            "(proc) walk: done walked=\(walked) found=\(entries.count) skipped=\(skipped)")
        return (entries.sorted { $0.pid < $1.pid }, skipped)
    }

    // MARK: FALLBACK — sysctl KERN_PROC_ALL

    private func _walkSysctlKernProc() -> ([ProcessEntry], skipped: Int) {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size = 0
        guard sysctl(&mib, 4, nil, &size, nil, 0) == 0,
              size >= MemoryLayout<kinfo_proc>.stride else {
            globallogger.log("(proc) sysctl size-query failed errno=\(errno)")
            return ([], 0)
        }
        var buf = [kinfo_proc](repeating: kinfo_proc(),
                                count: size / MemoryLayout<kinfo_proc>.stride + 16)
        guard sysctl(&mib, 4, &buf, &size, nil, 0) == 0 else {
            globallogger.log("(proc) sysctl data-fetch failed errno=\(errno)")
            return ([], 0)
        }
        let rawCount = size / MemoryLayout<kinfo_proc>.stride
        guard rawCount > 0 else { return ([], 0) }

        var entries = [ProcessEntry]()
        var skipped = 0
        entries.reserveCapacity(rawCount)

        for i in 0..<rawCount {
            let pid = buf[i].kp_proc.p_pid
            guard pid > 0 else { skipped += 1; continue }

            let pcomm    = safeField(from: buf[i].kp_proc.p_comm, maxBytes: 17)
            let pstatRaw = buf[i].kp_proc.p_stat

            var bsd       = proc_bsdinfo()
            let bsdOk     = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd,
                                         Int32(MemoryLayout<proc_bsdinfo>.size)) > 0
            let failErrno = errno
            var bsdName   = ""
            if bsdOk {
                bsdName = safeField(from: bsd.pbi_name, maxBytes: 32)
                if bsdName.isEmpty { bsdName = safeField(from: bsd.pbi_comm, maxBytes: 16) }
                if bsdName.isEmpty { bsdName = pcomm }
            }
            let rawBSD = RawBSDProcData(
                available:  bsdOk,
                ppid:       bsdOk ? bsd.pbi_ppid   : 0,
                uid:        bsdOk ? bsd.pbi_uid    : 0,
                gid:        bsdOk ? bsd.pbi_gid    : 0,
                pbi_status: bsdOk ? bsd.pbi_status : 0,
                bsdName:    bsdName,
                failErrno:  bsdOk ? 0 : failErrno
            )

            let name: String = rawBSD.bsdName.isEmpty
                ? (pcomm.isEmpty ? "(pid \(pid))" : pcomm)
                : rawBSD.bsdName
            let st: ProcessStatus = bsdOk
                ? ProcessStatus(pstat: rawBSD.pbi_status)
                : ProcessStatus(pstat: pstatRaw)
            let (qual, rsn) = DataInterpreter.quality(
                kernelNameOk: !pcomm.isEmpty, bsd: rawBSD)
            let cls = DataInterpreter.classify(
                pid: pid, uid: rawBSD.uid, name: name, bsdAvailable: bsdOk)

            entries.append(ProcessEntry(
                pid: pid, name: name,
                ppid: Int32(bitPattern: rawBSD.ppid), uid: rawBSD.uid, gid: rawBSD.gid,
                status: st, quality: qual, processClass: cls,
                source: bsdOk ? .sysctlBsdinfo : .sysctlPcomm, blockedReason: rsn
            ))
        }
        return (entries.sorted { $0.pid < $1.pid }, skipped)
    }

    // MARK: LAST RESORT — proc_listallpids

    private func _walkLibproc() -> ([ProcessEntry], skipped: Int) {
        let count = proc_listallpids(nil, 0)
        guard count > 0 else { return ([], 0) }
        var pids = [pid_t](repeating: 0, count: Int(count) + 64)
        let got  = proc_listallpids(&pids, Int32(MemoryLayout<pid_t>.stride * pids.count))
        guard got > 0 else { return ([], 0) }
        let valid = pids.prefix(Int(got)).filter { $0 > 0 }
        var entries = [ProcessEntry]()
        var skipped = 0
        entries.reserveCapacity(valid.count)
        for pid in valid {
            if let e = entry(for: pid, callerSource: "libproc") { entries.append(e) }
            else { skipped += 1 }
        }
        return (entries.sorted { $0.pid < $1.pid }, skipped)
    }

    // MARK: Helpers

    private func _kernelNameForPid(_ targetPid: Int32) -> String? {
        let mgr = AppContext.shared.mgr
        guard mgr.dsready, mgr.hasOffsets else { return nil }
        let nextOff = UInt64(off_proc_p_list_le_next)
        let pidOff  = UInt64(off_proc_p_pid)
        let nameOff = UInt64(off_proc_p_name)
        guard pidOff != 0, nameOff != 0 else { return nil }
        var proc_ptr = ds_get_our_proc()
        var seen     = Set<UInt64>()
        while proc_ptr != 0 && !seen.contains(proc_ptr) {
            seen.insert(proc_ptr)
            if Int32(bitPattern: mgr.kread32(address: proc_ptr + pidOff)) == targetPid {
                var buf = [UInt8](repeating: 0, count: 64)
                ds_kreadbuf(proc_ptr + nameOff, &buf, 64)
                let n = DataInterpreter.kernelName(from: buf)
                return n.isEmpty ? nil : n
            }
            proc_ptr = mgr.kread64(address: proc_ptr + nextOff)
            if seen.count > 2048 { break }
        }
        return nil
    }

    func safeField<T>(from field: T, maxBytes: Int) -> String {
        withUnsafeBytes(of: field) { raw in
            let limit = min(raw.count, maxBytes)
            var buf   = [UInt8](repeating: 0, count: limit + 1)
            for i in 0..<limit {
                let b = raw[i]; guard b != 0 else { break }
                buf[i] = b
            }
            let slice = Array(buf.prefix(while: { $0 != 0 }))
            guard !slice.isEmpty else { return "" }
            return String(bytes: slice, encoding: .utf8)
                ?? String(bytes: slice, encoding: .isoLatin1)
                ?? ""
        }
    }

    private func qualityCounts(_ e: [ProcessEntry]) -> (f: Int, p: Int, bl: Int, rf: Int) {
        var f = 0, p = 0, bl = 0, rf = 0
        for x in e {
            switch x.quality {
            case .full:     f  += 1
            case .partial:  p  += 1
            case .blocked:  bl += 1
            case .readFail: rf += 1
            }
        }
        return (f, p, bl, rf)
    }
}
