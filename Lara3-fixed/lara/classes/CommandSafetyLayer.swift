//
//  CommandSafetyLayer.swift
//  lara
//
//  SURGICAL SAFETY LAYER — iOS 18.3.1
//
//  Mission:   Validate every command before kernel dispatch,
//             cross-validate every result after execution,
//             warn before dangerous operations.
//
//  Principle: "Fail safe, not silent."
//

import Foundation
import Darwin

enum SafetyResult {
    case safe
    case warning(String)
    case dangerous(String)
    case blocked(String)

    var shouldExecute: Bool {
        switch self {
        case .blocked: return false
        default:       return true
        }
    }
}

final class CommandSafetyLayer {
    static let shared = CommandSafetyLayer()
    private init() {}

    private let dangerousZones: [(start: UInt64, end: UInt64, name: String)] = [
        (0xFFFFFE0000000000, 0xFFFFFFFF00000000, "PPL/KTRR protected region"),
        (0xFFFFFFF007004000, 0xFFFFFFF007800000, "kernel text (KTRR) — read-only, panic on write"),
    ]

    private let criticalPIDs: Set<Int32> = [0, 1, 2, 3, 4, 11, 14, 15, 16, 17, 18, 19, 20]

    private let krwCommands: Set<String> = [
        "kread", "kwrite", "kread32", "kwrite32", "kbytes", "kcstr",
        "proc-cred", "proc-info", "proc-csflags", "proc-csflags-set",
        "ucred-info", "vmmap-k", "inject-root", "cs-grant", "cs-flags",
        "task-info", "ipc-space", "port-info", "kstruct", "ksearch", "xref",
        "watch32", "watch64", "trace-write", "snapshot", "snapshot-diff",
        "proc-walk", "kalloc", "proc-entitlements", "proc-open-files",
        "proc-mem-info", "fd-info", "socket-info", "socket-dump",
    ]

    private let writeCommands: Set<String> = [
        "kwrite", "kwrite32", "inject-root", "proc-csflags-set",
        "cs-grant", "voverwrite", "vwrite", "vzero",
    ]

    private let systemProcCommands: Set<String> = [
        "inject-root", "proc-kill", "proc-signal", "proc-suspend",
    ]

    func preflight(command: String, arg: String, mgr: laramgr) -> SafetyResult {
        if krwCommands.contains(command) {
            let health = validateKRWHealth(mgr: mgr)
            if case .blocked(let msg) = health { return .blocked(msg) }
            if case .warning(let msg) = health { return .warning(msg) }
        }

        if ["kread", "kwrite", "kread32", "kwrite32", "kbytes", "kcstr"].contains(command) {
            return validateKernelAddressCommand(command: command, arg: arg, mgr: mgr)
        }

        if command.hasPrefix("proc-") || ["ucred-info", "task-info", "vmmap-k", "inject-root", "ipc-space", "fd-info", "socket-info"].contains(command) {
            return validatePIDCommand(command: command, arg: arg, mgr: mgr)
        }

        if ["voverwrite", "vwrite", "vzero"].contains(command) {
            return validateFileWriteCommand(command: command, arg: arg, mgr: mgr)
        }

        return assessDanger(command: command, arg: arg, mgr: mgr)
    }

    func postflight(command: String, output: String, mgr: laramgr) -> String {
        if command == "ucred-info" { return validateUcredOutput(output) }
        if command == "proc-cred" { return validateProcCredOutput(output) }
        if command == "kread" || command == "kread32" { return validateKReadOutput(output) }
        return output
    }

    private func validateKRWHealth(mgr: laramgr) -> SafetyResult {
        guard mgr.dsready else {
            return .blocked("KRW session not ready — run 'run' first")
        }
        let kbase = ds_get_kernel_base()
        guard kbase != 0 else {
            return .blocked("KRW session degraded — kernel_base is zero. Run 'revive'")
        }
        do {
            let magic = ds_kread32(kbase)
            guard magic == 0xFEEDFACF else {
                return .blocked("KRW session corrupted — kernel magic mismatch. Run 'revive'")
            }
        } catch {
            return .blocked("KRW socket disconnected. Run 'revive'")
        }
        let thermal = ProcessInfo.processInfo.thermalState
        if thermal == .critical {
            return .warning("CRITICAL thermal state — KRW ops may be throttled by iOS")
        } else if thermal == .serious {
            return .warning("SERIOUS thermal state — consider cooling device")
        }
        return .safe
    }

    private func validateKernelAddressCommand(command: String, arg: String, mgr: laramgr) -> SafetyResult {
        let parts = arg.split(separator: " ").map { String($0) }
        guard let addrStr = parts.first, let addr = parseHex(addrStr) else {
            return .blocked("invalid address format — use 0x...")
        }
        if (addr & (1 << 63)) == 0 {
            return .blocked("0x" + String(addr, radix: 16) + " is not a valid kernel address (bit63=0)")
        }
        if !ds_isvalid(addr) {
            return .blocked("0x" + String(addr, radix: 16) + " is not mapped in kernel space")
        }
        for zone in dangerousZones {
            if addr >= zone.start && addr < zone.end {
                if writeCommands.contains(command) {
                    return .blocked("address falls in " + zone.name + " — WRITE WILL PANIC")
                } else {
                    return .dangerous("WARNING: address in " + zone.name + ". Read-only recommended. Any write = kernel panic.")
                }
            }
        }
        if command == "kread32" || command == "kwrite32" {
            if addr % 4 != 0 {
                return .warning("Address 0x" + String(addr, radix: 16) + " is not 4-byte aligned")
            }
        }
        if writeCommands.contains(command) {
            guard parts.count >= 2 else {
                return .blocked("missing value argument")
            }
            guard parseHex(parts[1]) != nil else {
                return .blocked("invalid value format — use 0x...")
            }
            return .dangerous("DANGER: Writing to kernel memory at 0x" + String(addr, radix: 16) + ". This can cause kernel panic, data loss, or device boot-loop.")
        }
        return .safe
    }

    private func validatePIDCommand(command: String, arg: String, mgr: laramgr) -> SafetyResult {
        let parts = arg.split(separator: " ").map { String($0) }
        guard let pidStr = parts.first, let pid = Int32(pidStr) else {
            return .blocked("invalid PID — use numeric value")
        }
        guard pid >= 0 else {
            return .blocked("PID cannot be negative")
        }
        var info = proc_bsdinfo()
        let exists = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size)) > 0
        if !exists && !mgr.dsready {
            return .blocked("PID " + String(pid) + " does not exist and KRW unavailable")
        }
        if criticalPIDs.contains(pid) || (exists && info.pbi_uid == 0 && pid <= 100) {
            if systemProcCommands.contains(command) {
                return .dangerous("CRITICAL: PID " + String(pid) + " is a system process. " + command + " on system processes can cause kernel panic or respring.")
            }
            if command == "proc-cred" || command == "ucred-info" {
                return .warning("PID " + String(pid) + " is a system process. Some fields may be PPL-protected.")
            }
        }
        if command == "inject-root" {
            if pid == getpid() {
                return .dangerous("WARNING: You are about to inject root into LARA itself (PID " + String(pid) + "). This is usually unnecessary.")
            }
            guard exists else {
                return .blocked("PID " + String(pid) + " does not exist")
            }
            guard info.pbi_uid != 0 else {
                return .dangerous("PID " + String(pid) + " already runs as root. inject-root is redundant.")
            }
        }
        return .safe
    }

    private func validateFileWriteCommand(command: String, arg: String, mgr: laramgr) -> SafetyResult {
        let parts = arg.split(separator: " ").map { String($0) }
        guard let path = parts.first else {
            return .blocked("missing path argument")
        }
        if path.hasPrefix("/System/") || path.hasPrefix("/usr/libexec/") || path.hasPrefix("/usr/sbin/") || path.hasPrefix("/sbin/") {
            return .dangerous("DANGER: Path '" + path + "' is on Signed System Volume (SSV). Writes may be reverted on reboot or cause boot-loop.")
        }
        if path.contains("kernelcache") || path.contains("com.apple.kernel") {
            return .blocked("path contains kernelcache — PPL-protected, write WILL PANIC")
        }
        return .safe
    }

    private func assessDanger(command: String, arg: String, mgr: laramgr) -> SafetyResult {
        if command == "respring" {
            return .dangerous("WARNING: respring will restart SpringBoard. All unsaved KRW state will be lost.")
        }
        if command == "revive" || command == "run" {
            return .warning("This will re-run the full kernel exploit. Expect 3-5 seconds of socket spraying.")
        }
        return .safe
    }

    private func validateUcredOutput(_ output: String) -> String {
        if let range = output.range(of: "ngroups"),
           let valRange = output[range.upperBound...].range(of: #"\d+"#, options: .regularExpression) {
            let valStr = String(output[valRange])
            if let ng = Int(valStr), ng > 16 {
                return output + "\n\nSAFETY WARNING: ngroups=" + String(ng) + " exceeds NGROUPS_MAX (16). This indicates WRONG ucred offsets. Do NOT trust uid/gid values above."
            }
        }
        return output
    }

    private func validateProcCredOutput(_ output: String) -> String {
        if output.contains("gid   : 4") && output.contains("uid   : 501") {
            return output + "\n\nSAFETY WARNING: gid=4 with uid=501 is SUSPICIOUS. On iOS, app processes should have gid=501. gid=4 suggests WRONG offset layout."
        }
        return output
    }

    private func validateKReadOutput(_ output: String) -> String {
        if output.contains("=  0x0000000000000000") {
            return output + "\n  [NOTE: zero read — may indicate unmapped page or stripped PAC]"
        }
        return output
    }

    private func parseHex(_ s: String) -> UInt64? {
        let cleaned = s.trimmingCharacters(in: .whitespaces)
        if cleaned.hasPrefix("0x") || cleaned.hasPrefix("0X") {
            return UInt64(cleaned.dropFirst(2), radix: 16)
        }
        return UInt64(cleaned, radix: 16) ?? UInt64(cleaned)
    }
}
