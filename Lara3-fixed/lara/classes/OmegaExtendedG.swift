//
//  OmegaExtendedG.swift
//  lara
//
//  Phase 1: Kernel Inspection Shell — decode-pte, watch, ucredinfo, csinfo
//  Pure KRW. Zero fabrication. Every byte is read live from kernel memory.
//

import Foundation
import Darwin

private func _ghex(_ s: String) -> UInt64? {
    let t = s.trimmingCharacters(in: .whitespaces)
    let x = (t.hasPrefix("0x") || t.hasPrefix("0X")) ? String(t.dropFirst(2)) : t
    return UInt64(x, radix: 16)
}

func registerKernelInspectCommands() {
    _regDecodePTE(); _regWatch(); _regUcredInfo(); _regCSInfo(); _regHelpInspect()
}

private func _regDecodePTE() {
    OmegaCore.register("decode-pte") { rawArg, mgr in
        guard let pte = _ghex(rawArg) else {
            return .fail("decode-pte: usage — decode-pte <pte_hex>\nexample: decode-pte 0x60000000000703")
        }
        let r = ki_decode_pte(pte)
        return r.code == 0 ? .ok(String(cString: r.msg)) : .fail(String(cString: r.msg))
    }
}

private func _regWatch() {
    OmegaCore.register("watch") { rawArg, mgr in
        guard mgr.dsready else { return .fail("watch: exploit not ready — run 'run' first") }
        guard let va = _ghex(rawArg) else {
            return .fail("watch: usage — watch <kernel_va_hex>\nexample: watch 0xfffffff007004000")
        }
        let r = ki_watch(va)
        return r.code == 0 ? .ok(String(cString: r.msg)) : .fail(String(cString: r.msg))
    }
}

private func _regUcredInfo() {
    OmegaCore.register("ucredinfo") { rawArg, mgr in
        guard mgr.dsready else { return .fail("ucredinfo: exploit not ready") }
        let pid = Int32(rawArg.trimmingCharacters(in: .whitespaces)) ?? 0
        let r = ki_ucredinfo(pid)
        return r.code == 0 ? .ok(String(cString: r.msg)) : .fail(String(cString: r.msg))
    }
}

private func _regCSInfo() {
    OmegaCore.register("csinfo") { rawArg, mgr in
        guard mgr.dsready else { return .fail("csinfo: exploit not ready") }
        let pid = Int32(rawArg.trimmingCharacters(in: .whitespaces)) ?? 0
        let r = ki_csinfo(pid)
        return r.code == 0 ? .ok(String(cString: r.msg)) : .fail(String(cString: r.msg))
    }
}

private func _regHelpInspect() {
    OmegaCore.register("help-inspect") { _, mgr in
        let lines = [
            "===============================================================",
            "  KERNEL INSPECTION COMMANDS (Phase 1)",
            "===============================================================",
            "",
            "  decode-pte <pte_hex>  — Decode an ARM64 PTE value (pure logic)",
            "  watch <kernel_va>     — Single-shot memory snapshot + hex dump",
            "  ucredinfo [pid]       — Dump ucred struct (uid/gid/groups/label)",
            "  csinfo [pid]          — Dump code-signing flags (CS_VALID/HARD/etc)",
            "",
            "  All commands read LIVE kernel memory via darksword KRW.",
            "  No fabricated data. No misleading statistics.",
            "===============================================================",
        ]
        return .ok(lines.joined(separator: "\n"))
    }
}
