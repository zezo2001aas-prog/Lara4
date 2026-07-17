import Foundation
import UIKit
import Darwin
import MobileCoreServices

// MARK: - Helpers (internal to bootstrap)

private func parseAddr(_ s: String) -> UInt64? {
    let t = s.trimmingCharacters(in: .whitespaces)
    if t.hasPrefix("0x") || t.hasPrefix("0X") {
        return UInt64(t.dropFirst(2), radix: 16)
    }
    return UInt64(t, radix: 16) ?? UInt64(t)
}

private func formatBytes(_ n: Int64) -> String {
    let b = Double(n)
    if n < 1024 { return "\(n) B" }
    if n < 1024 * 1024 { return String(format: "%.1f KB", b / 1024) }
    if n < 1024 * 1024 * 1024 { return String(format: "%.1f MB", b / (1024 * 1024)) }
    return String(format: "%.2f GB", b / (1024 * 1024 * 1024))
}

private func formatBytes(_ n: Int) -> String { formatBytes(Int64(n)) }

private func formatSize(_ bytes: Int) -> String { formatBytes(bytes) }

private func octalPerms(_ mode: UInt16) -> String {
    var s = ""
    s += (mode & 0o400) != 0 ? "r" : "-"
    s += (mode & 0o200) != 0 ? "w" : "-"
    s += (mode & 0o100) != 0 ? "x" : "-"
    s += (mode & 0o040) != 0 ? "r" : "-"
    s += (mode & 0o020) != 0 ? "w" : "-"
    s += (mode & 0o010) != 0 ? "x" : "-"
    s += (mode & 0o004) != 0 ? "r" : "-"
    s += (mode & 0o002) != 0 ? "w" : "-"
    s += (mode & 0o001) != 0 ? "x" : "-"
    return s
}

// ── PID helpers — all route through ProcessLayer for consistent PID mapping ──────────
// Bug fixed: these previously called listAllPIDs() (independent codepath),
// causing PID mapping inconsistency vs ps/proc-find/proc-walk.

private func listAllPIDsSafe() -> [Int32] {
    ProcessLayer.shared.listAll().map { $0.pid }
}

private func pidName(_ pid: Int32) -> String {
    ProcessLayer.shared.entry(for: pid, callerSource: "pidName")?.name ?? ""
}

private func findPidByName(_ name: String) -> Int32? {
    ProcessLayer.shared.find(matching: name).first?.pid
}

private func findPidByBundleId(_ bundleId: String, mgr: laramgr) -> Int32? {
    guard let appList = mgr.getAppList(), let info = appList[bundleId] else { return nil }
    // Use ProcessLayer.find so results match ps/proc-find
    return ProcessLayer.shared.find(matching: info.executable).first?.pid
}

// MARK: - csops syscall (for proc-entitlements kernel fallback)
@_silgen_name("csops")
func csops(_ pid: pid_t, _ ops: UInt32, _ useraddr: UnsafeMutableRawPointer, _ usersize: Int) -> Int32

// MARK: - OmegaBootstrap

final class OmegaBootstrap {

    private static var started = false

    static func start() {
        guard !started else { return }
        started = true
        register()
    }

    private static func register() {
        OmegaExtended.registerAll()
        registerShell()
        registerFilesystem()
        registerKernel()
        registerVFS()
        registerVFSExtended()
        registerApps()
        registerPlist()
        registerExec()
        registerFileTools()
        registerSandbox()
        registerGestalt()
        registerDefaults()
        registerProcessControl()
        registerAppControl()
        registerSystemInfo()
        registerLara()
        registerKernelScannerCommands()
        registerExtendedECommands()
        registerProcLinkCommands()
        registerPrivilegeShellCommands()
        registerPPLShellCommands()
        registerKernelObjectExplorer()
        registerProcessExplorer()
        registerIPCExplorer()
        registerVFSExplorer()
        // registerMemoryExplorer() // TODO: Implement OmegaExtendedL.swift or remove
        registerDebuggerCommands()
        registerSnapshotEngine()
    }

    // MARK: - Shell Basics

    private static func registerShell() {
        OmegaCore.register("help") { _, _ in
            .ok("""
LARA Shell — full command reference (iSH-level access)

  ── FILESYSTEM ──────────────────────────────────────────
  ls [-l] [-a] [path]          list directory
  pwd                          print working directory
  cd <path>                    change directory  (~ = home)
  cat <file>                   print file contents
  head [-n N] <file>           first N lines (default 10)
  tail [-n N] <file>           last N lines  (default 10)
  touch <file>                 create / update timestamp
  mkdir [-p] <dir>             create directory
  rm [-rf] <path>              remove file or directory
  cp <src> <dst>               copy file or directory
  mv <src> <dst>               move / rename
  write <file> <text>          overwrite file with text
  stat <path>                  detailed file metadata
  find [path] [-name pat]      recursive search
  chmod <mode> <file>          change permissions (octal)
  chown <uid:gid> <path>       change owner (apfs_own)
  ln -s <target> <link>        create symbolic link
  readlink <path>              read symbolic link target
  du [-h] [path]               disk usage of directory
  file <path>                  identify file type

  ── KERNEL R/W ──────────────────────────────────────────
  kinfo                        kernel base, slide, proc, task
  kread <addr>                 read 64-bit kernel value
  kwrite <addr> <val>          write 64-bit to kernel
  kread32 <addr>               read 32-bit kernel value
  kwrite32 <addr> <val>        write 32-bit to kernel
  kcstr <addr>                 read C-string from kernel
  kbytes <addr> <n>            read N bytes as hex dump
  kalloc <size>                kalloc_data allocation info
  proc-walk                    walk kernel allproc list

  ── VFS (kernel-level file access) ──────────────────────
  vls [path]                   list directory via VFS
  vcat <path>                  read file via VFS
  vhex <path>                  hex-dump file via VFS
  vsize <path>                 get file size via VFS
  vwrite <path> <text>         write text to file via VFS
  vcopy <src> <dst>            copy file via VFS
  voverwrite <dst> <src>       overwrite system file (VFS)
  vzero <path>                 zero first page of file (VFS)
  vstat <path>                 stat file via VFS

  ── APPS ────────────────────────────────────────────────
  apps [filter]                list installed apps
  app-info <bundleId>          full app info + paths
  app-data <bundleId>          cd to app data container
  app-bundle <bundleId>        cd to app bundle
  app-prefs <bundleId>         read app preferences plist
  app-env <bundleId>           show app environment plist
  app-entitlements <bundleId>  read app entitlements
  app-version <bundleId>       show version info
  app-list-files <bundleId>    list top-level container files

  ── PROCESS CONTROL ─────────────────────────────────────
  ps [-e] [-v]                 process list (extended info)
  proc-info <pid>              detailed process info
  proc-kill <pid>              kill process (SIGKILL)
  proc-signal <pid> <sig>      send signal to process
  proc-suspend <pid>           suspend process (SIGSTOP)
  proc-resume <pid>            resume process (SIGCONT)
  proc-cred <pid>              read uid/gid from kernel
  proc-csflags <pid>           read CS flags from kernel
  proc-csflags-set <pid> <fl>  write CS flags (hex)
  proc-entitlements <pid>      dump entitlements from proc
  proc-find <name>             find PID by process name
  proc-open-files <pid>        list open file descriptors
  proc-mem-info <pid>          memory regions summary

  ── APP CONTROL ─────────────────────────────────────────
  app-kill <bundleId>          kill app by bundle ID
  app-pid <bundleId>           get PID of running app
  app-sandbox-escape <bId>     break app out of sandbox
  app-csflags <bundleId>       read app CS flags
  app-csflags-set <bId> <fl>   set app CS flags (debuggable)
  app-container <bundleId>     full container UUID paths

  ── SANDBOX ─────────────────────────────────────────────
  sbx-info                     sandbox status + entitlements
  sbx-token <pid>              get sandbox token for pid
  sbx-token-str <pid>          get token as string
  sbx-issue <class> <path>     issue extension token
  sbx-elevate                  elevate our sandbox

  ── PLIST ────────────────────────────────────────────────
  plist <path>                 read plist (binary or XML)
  plist-get <path> <key>       read single key
  plist-set <path> <key> <type> <val>  write key
                               types: str | bool | int | float
  plist-del <path> <key>       delete key
  plist-keys <path>            list all top-level keys

  ── MOBILEGESTALT ────────────────────────────────────────
  mg-info                      gestalt file path + subtype
  mg-get <key>                 read MobileGestalt key
  mg-set <key> <val>           set MobileGestalt value
  mg-keys                      dump all gestalt keys

  ── PREFERENCES ──────────────────────────────────────────
  defaults read <domain> [key]           read preference
  defaults write <domain> <key> <val>    write preference
  defaults delete <domain> <key>         delete preference
  defaults domains                       list all domains

  ── EXECUTION ────────────────────────────────────────────
  exec <binary> [args...]      run binary + capture output
  exec-bg <binary> [args...]   run binary in background
  sysctl [name]                read sysctl value
  sysctl-all                   dump all sysctl values
  notif <name>                 post Darwin notification
  env                          environment variables
  launchctl <cmd>              launchctl wrapper

  ── FILE TOOLS ───────────────────────────────────────────
  hexdump <path> [bytes]       hex dump file
  grep <pattern> <path|->      search in file or stdin
  strings <path> [min]         extract printable strings
  b64 <path>                   base64-encode file
  b64d <path>                  base64-decode file
  sha256 <path>                SHA-256 of file
  wc <path|->                  word / line / byte count
  sort [-r] <path|->           sort lines
  uniq <path|->                deduplicate lines
  head / tail                  also accept - for stdin

  ── SYSTEM INFO ──────────────────────────────────────────
  device-info                  full device + OS info
  memory-info                  VM memory statistics
  disk-info                    disk space statistics
  boot-args                    kernel boot arguments (nvram)
  bundle-id                    show our bundle ID
  jb-status                    full exploit/subsystem status
  uid                          current uid / gid / euid
  entitlements                 dump our own entitlements

  ── LARA ─────────────────────────────────────────────────
  health                       KRW session health score (0-100)
  memstats                     memory operation statistics
  status                       subsystem status summary
  run                          trigger DarkSword exploit
  vfs                          initialize VFS
  sbx                          escape sandbox
  rc                           initialize RemoteCall
  respring                     respring SpringBoard
  logs                         show lara system logs
  clear-logs                   clear lara logs
  reset-history                clear command history

  ── TERMINAL ─────────────────────────────────────────────
  clear                        clear screen
  history                      command history
  echo <text>                  print text
  date                         current date/time
  uname                        kernel/device info
  whoami                       current user
  hostname                     device hostname
  ps                           process list
  env                          environment variables
  pipe: cmd1 | cmd2            pipeline (grep, head, tail, etc.)

  ── EXTENDED MODULES ─────────────────────────────────────
  help-priv                    privilege escalation commands (OmegaExtendedF)
                               (ucred, cs-flags, AMFI, sandbox, system-files)
  help-ppl                     PAC/KTRR/SMR/PPL analysis commands (OmegaExtendedG)
                               (pac-reader, ktrr-*, smr-*, ppl-*, auto-ppl-breaker)

  ── KERNEL OBJECT EXPLORER ──────────────────────────────
  fd-info <pid> <fd>           file descriptor kernel info
  socket-info <pid> <fd>       decode socket struct
  socket-info-addr <addr>      decode socket at address
  socket-dump <pid> <fd>       structured socket memory dump
  socket-save <pid> <fd>       save socket snapshot
  socket-diff <pid> <fd>       compare socket to saved snapshot

  ── PROCESS EXPLORER ─────────────────────────────────────
  task-info <pid>              task/vm_map/ipc_space/threads/refcount
  ucred-info <pid>             uid/gid/groups/label/sandbox/entitlements
  vmmap-k <pid>                kernel-level vmmap

  ── IPC EXPLORER ─────────────────────────────────────────
  ipc-space <pid>              Mach port table for process
  port-info <addr>             ipc_port detailed info

  ── VFS EXPLORER ─────────────────────────────────────────
  vnode-info <path>            vnode metadata
  mount-info                   current mount flags

  ── MEMORY EXPLORER ─────────────────────────────────────
  kstruct <type> <addr>        auto-decode kernel struct
                               types: socket, proc, task, ucred, vnode, ipc_port
  ksearch <pattern> [s] [e]    search kernel for pointer/pattern
  xref <target> [s] [e]        find all references to address

  ── DEBUGGER ─────────────────────────────────────────────
  watch32 <addr> [int] [dur]   watch 32-bit value changes
  watch64 <addr> [int] [dur]   watch 64-bit value changes
  trace-write <addr> [dur]     log all writes to address

  ── SNAPSHOT ENGINE ──────────────────────────────────────
  snapshot kernel              save proc/task/ucred/socket/vm_map
  snapshot-diff                compare current state to snapshot
""")
        }

        OmegaCore.register("clear") { _, _ in .ok("__CLEAR__") }

        OmegaCore.register("history") { _, _ in
            let h = TerminalHistory.shared.load()
            if h.isEmpty { return .ok("(empty)") }
            return .ok(h.enumerated().map {
                String(format: "  %3d  %@", $0.offset + 1, $0.element)
            }.joined(separator: "\n"))
        }

        OmegaCore.register("reset-history") { _, _ in
            TerminalHistory.shared.clear()
            return .ok("command history cleared")
        }

        OmegaCore.register("echo") { arg, _ in .ok(arg) }

        OmegaCore.register("uname") { _, _ in
            let d = UIDevice.current
            return .ok("Darwin — \(d.systemName) \(d.systemVersion) (\(d.model)) [\(d.name)]")
        }

        OmegaCore.register("date") { _, _ in
            let df = DateFormatter()
            df.dateFormat = "EEE MMM dd HH:mm:ss zzz yyyy"
            return .ok(df.string(from: Date()))
        }

        OmegaCore.register("env") { _, _ in
            let sorted = ProcessInfo.processInfo.environment.sorted { $0.key < $1.key }
                .map { "\($0.key)=\($0.value)" }.joined(separator: "\n")
            return .ok(sorted.isEmpty ? "(empty)" : sorted)
        }

        OmegaCore.register("whoami") { _, _ in
            let uid = Foundation.ProcessInfo.processInfo.environment["USER"] ?? "mobile"
            return .ok("\(uid) (uid=\(getuid()) gid=\(getgid()) euid=\(geteuid()))")
        }

        OmegaCore.register("uid") { _, _ in
            return .ok("uid=\(getuid())  gid=\(getgid())  euid=\(geteuid())  egid=\(getegid())")
        }

        OmegaCore.register("hostname") { _, _ in
            return .ok(ProcessInfo.processInfo.hostName)
        }

        // MARK: ── Session Health Commands ─────────────────────────────────────

        OmegaCore.register("health") { _, _ in
            let score = ds_session_health_score()
            let status: String
            switch score {
            case 100: status = "PERFECT"
            case 85...99: status = "HEALTHY"
            case 60...84: status = "DEGRADED"
            case 30...59: status = "WARNING"
            case 1...29: status = "CRITICAL"
            default: status = "NOT READY"
            }
            return .ok("KRW Health Score: \(score)/100 — \(status)")
        }

        OmegaCore.register("memstats") { _, _ in
            return .ok(MemoryOperationTracker.shared.stats)
        }

        OmegaCore.register("ps") { arg, _ in
            let verbose  = arg.contains("-v")
            let extended = arg.contains("-e") || arg.contains("-ax") || verbose
            let meta     = ProcessLayer.shared.listAllWithMeta()
            let procs    = meta.entries

            if procs.isEmpty {
                return .fail(
                    "ps: 0 processes returned\n"
                    + "  source tried : \(meta.primarySource)\n"
                    + "  fallback used: \(meta.fallbackUsed)\n"
                    + "  skipped      : \(meta.skippedCount)\n"
                    + "  hint: run 'run' to activate exploit, then retry"
                )
            }

            // iOS access report — always shown
            let sourceTag = "  [source: \(meta.primarySource)"
                + (meta.fallbackUsed ? " (fallback)" : "")
                + "  total=\(procs.count)"
                + "  FULL=\(meta.fullCount) PARTIAL=\(meta.partialCount)"
                + " BLOCKED=\(meta.blockedCount)"
                + "  iOS-access=\(meta.completenessPercent)%]"

            if verbose {
                // -v: максимум информации + source per-entry
                var lines: [String] = [
                    _col([7, 5, 5, 5, 4, 20, 16], ["PID","PPID","UID","GID","STA","NAME","SOURCE"]),
                    String(repeating: "─", count: 76),
                ]
                for p in procs {
                    lines.append(_col([7,5,5,5,4,20,16],
                        [String(p.pid), String(p.ppid), String(p.uid),
                         String(p.gid), p.status.rawValue, p.name, p.source.rawValue]))
                }
                lines.append(sourceTag)
                return .ok(lines.joined(separator: "\n"))

            } else if extended {
                // -e / -ax: extended without per-entry source
                var lines: [String] = [
                    _col([7, 5, 5, 5, 4, 26], ["PID","PPID","UID","GID","STA","NAME"]),
                    String(repeating: "─", count: 62)
                ]
                for p in procs {
                    lines.append(_col([7,5,5,5,4,26],
                        [String(p.pid), String(p.ppid), String(p.uid),
                         String(p.gid), p.status.rawValue, p.name]))
                }
                lines.append(sourceTag)
                return .ok(lines.joined(separator: "\n"))

            } else {
                // plain ps
                var lines: [String] = [
                    _col([7, 26], ["PID","NAME"]),
                    String(repeating: "─", count: 37)
                ]
                for p in procs {
                    lines.append(_col([7,26], [String(p.pid), p.name]))
                    if lines.count > 122 { lines.append("  ... (use 'ps -e' for full list)"); break }
                }
                lines.append(sourceTag)
                return .ok(lines.joined(separator: "\n"))
            }
        }
    }

    // MARK: - Filesystem

    private static func registerFilesystem() {
        let fs = OmegaFS.shared

        OmegaCore.register("ls")    { arg, _ in .result(fs.ls(arg)) }
        OmegaCore.register("pwd")   { _, _ in .ok(fs.pwd()) }
        OmegaCore.register("cd")    { arg, _ in .result(fs.cd(arg.trimmingCharacters(in: .whitespaces))) }
        OmegaCore.register("cat")   { arg, _ in .result(fs.cat(arg)) }
        OmegaCore.register("head")  { arg, _ in .result(fs.head(arg)) }
        OmegaCore.register("tail")  { arg, _ in .result(fs.tail(arg)) }
        OmegaCore.register("touch") { arg, _ in .result(fs.touch(arg)) }
        OmegaCore.register("mkdir") { arg, _ in .result(fs.mkdir(arg)) }
        OmegaCore.register("rm")    { arg, _ in .result(fs.rm(arg)) }
        OmegaCore.register("cp")    { arg, _ in .result(fs.cp(arg)) }
        OmegaCore.register("mv")    { arg, _ in .result(fs.mv(arg)) }
        OmegaCore.register("stat")  { arg, _ in .result(fs.stat(arg)) }
        OmegaCore.register("find")  { arg, _ in .result(fs.find(arg)) }
        OmegaCore.register("chmod") { arg, _ in .result(fs.chmod(arg)) }

        OmegaCore.register("write") { arg, _ in
            let parts = arg.split(separator: " ", maxSplits: 1).map { String($0) }
            guard parts.count == 2 else { return .fail("write: usage: write <file> <text>") }
            return .result(fs.write(parts[0], parts[1]))
        }

        OmegaCore.register("chown") { arg, mgr in
            let parts = arg.split(separator: " ").map { String($0) }
            guard parts.count == 2 else { return .fail("chown: usage: chown <uid:gid> <path>") }
            let ug = parts[0].split(separator: ":").map { String($0) }
            guard ug.count == 2, let uid = UInt32(ug[0]), let gid = UInt32(ug[1]) else {
                return .fail("chown: invalid uid:gid — example: chown 501:501 /path")
            }
            let path = fs.resolve(parts[1])
            let ok = mgr.apfsown(path: path, uid: uid, gid: gid)
            return ok ? .ok("chown: \(path) → \(uid):\(gid)") : .fail("chown: failed on \(path)")
        }

        OmegaCore.register("ln") { arg, _ in
            let parts = arg.split(separator: " ").map { String($0) }
            guard parts.count >= 3, parts[0] == "-s" else {
                return .fail("ln: usage: ln -s <target> <link>")
            }
            let target = fs.resolve(parts[1])
            let link   = fs.resolve(parts[2])
            do {
                try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: target)
                return .ok("ln: \(link) -> \(target)")
            } catch { return .fail("ln: \(error.localizedDescription)") }
        }

        OmegaCore.register("readlink") { arg, _ in
            let path = fs.resolve(arg.trimmingCharacters(in: .whitespaces))
            guard let dst = try? FileManager.default.destinationOfSymbolicLink(atPath: path) else {
                return .fail("readlink: \(arg): not a symlink or error")
            }
            return .ok(dst)
        }

        OmegaCore.register("du") { arg, _ in
            let parts = arg.split(separator: " ").map { String($0) }
            var human = false
            var targetArg = ""
            for p in parts {
                if p == "-h" { human = true } else { targetArg = p }
            }
            let path = targetArg.isEmpty ? fs.cwd : fs.resolve(targetArg)
            var total: Int64 = 0
            let fm = FileManager.default
            if let en = fm.enumerator(atPath: path) {
                for case let f as String in en {
                    let full = (path as NSString).appendingPathComponent(f)
                    if let a = try? fm.attributesOfItem(atPath: full), let s = a[.size] as? Int {
                        total += Int64(s)
                    }
                }
            }
            let display = human ? formatBytes(total) : "\(total)"
            return .ok("\(display)\t\(path)")
        }

        OmegaCore.register("file") { arg, _ in
            let path = fs.resolve(arg.trimmingCharacters(in: .whitespaces))
            guard let handle = try? FileHandle(forReadingFrom: URL(fileURLWithPath: path)) else {
                return .fail("file: \(arg): cannot read")
            }
            let magic = handle.readData(ofLength: 16)
            handle.closeFile()

            var kind = "data"
            if magic.starts(with: [0xCF, 0xFA, 0xED, 0xFE]) || magic.starts(with: [0xCE, 0xFA, 0xED, 0xFE]) {
                kind = "Mach-O binary (arm64)"
            } else if magic.starts(with: [0xCA, 0xFE, 0xBA, 0xBE]) {
                kind = "Mach-O fat binary"
            } else if magic.starts(with: Data("bplist".utf8)) {
                kind = "Apple binary property list"
            } else if magic.starts(with: Data("<?xml".utf8)) {
                kind = "XML document"
            } else if magic.starts(with: Data("PK".utf8)) {
                kind = "ZIP archive"
            } else if magic.starts(with: [0x1F, 0x8B]) {
                kind = "gzip compressed data"
            } else if magic.starts(with: Data("{".utf8)) || magic.starts(with: Data("[".utf8)) {
                kind = "JSON data"
            } else if let text = String(data: magic, encoding: .utf8), text.unicodeScalars.allSatisfy({ $0.value < 128 }) {
                kind = "ASCII text"
            }
            let attrs = try? FileManager.default.attributesOfItem(atPath: path)
            let size = attrs?[.size] as? Int ?? 0
            return .ok("\(path): \(kind)  (\(formatBytes(size)))")
        }
    }

    // MARK: - Kernel R/W

    private static func registerKernel() {
OmegaCore.register("kinfo") { _, mgr in
            guard mgr.dsready else { return .fail("kinfo: exploit not ready — run 'run' first") }

            var lines: [String] = []

            // Device & Process Info (runtime — real device data)
            var sysInfo = utsname()
            uname(&sysInfo)
            let machine = withUnsafePointer(to: &sysInfo.machine) {
                $0.withMemoryRebound(to: CChar.self, capacity: 1) {
                    String(cString: $0)
                }
            }
            let deviceName = UIDevice.current.name
            let iosVersion = UIDevice.current.systemVersion
            let pid = getpid()
            lines.append(String(format: "[DEVICE]   %@ | iOS %@ | %@ | PID=%d",
                deviceName, iosVersion, machine, pid))
            lines.append("")

            lines.append("=== KERNEL STATE DIAGNOSTIC ===")
            lines.append("")

            // 1. KRW Subsystem
            let krwReady = ds_is_ready()
            let krwState = krwReady ? "OPERATIONAL" : "FAILED"
            lines.append(String(format: "[KRW]      State: %-20@  Backend: kernel r/w via exploit primitive", krwState as NSString))

            // 2. Pointer Integrity
            let kbase = ds_get_kernel_base()
            let kslide = ds_get_kernel_slide()
            let ourProc = ds_get_our_proc()
            let ourTask = ds_get_our_task()
            let rwPCB = ds_get_rw_socket_pcb()

            let procState = (ourProc != 0 && (ourProc & 0xFFFF000000000000) != 0) ? "VALID" : "NULL/CORRUPT"
            let taskState = (ourTask != 0 && (ourTask & 0xFFFF000000000000) != 0) ? "VALID" : "NULL/CORRUPT"
            let kbaseState = (kbase != 0 && kbase & 0xFFF == 0) ? "VALID" : "INVALID"
            let pcbState = rwPCB != 0 ? "VALID" : "NULL"

            lines.append(String(format: "[PTR]      proc: %-20@  0x%012llx", procState as NSString, ourProc))
            lines.append(String(format: "           task: %-20@  0x%012llx", taskState as NSString, ourTask))
            lines.append(String(format: "           kbase: %-19@  0x%016llx", kbaseState as NSString, kbase))
            lines.append(String(format: "           slide: %-19@  0x%016llx", (kslide != 0 ? "VALID" : "ZERO") as NSString, kslide))
            lines.append(String(format: "           rwpcb: %-19@  0x%012llx", pcbState as NSString, rwPCB))

            // 3. Privilege
            let uid = getuid()
            let gid = getgid()
            let euid = geteuid()
            let privState = uid == 0 ? "ROOT" : (euid == 0 ? "ELEVATED (euid=0)" : "UNPRIVILEGED")
            lines.append(String(format: "[PRIV]     Level: %-20@  uid=%d  gid=%d  euid=%d", privState as NSString, uid, gid, euid))

            // 4. Protections
            let hasPAC = true  // A12+ always armed
            let pplBypassed = ppl_is_bypassed()
            let pmOK = pm_fingerprint_ok()
            let amfiEnforce = amfi_get_mac_proc_enforce()

            // FIX: 0xFFFFFFFF (-1) means READ FAILED, not "enforcing"
            let amfiState: String
            if amfiEnforce == 0xFFFFFFFF {
                amfiState = "UNKNOWN ❌ (offset unreadable)"
            } else if amfiEnforce == 0 {
                amfiState = "DISABLED ✅"
            } else {
                amfiState = "ENFORCING ⚠️"
            }

            let pplState: String
            if pplBypassed {
                pplState = "BYPASSED ✅"
            } else if pmOK {
                pplState = "ENFORCED (physmap mapped) ⚠️"
            } else {
                pplState = "ENFORCED (physmap unavailable) ❌"
            }

            var ktrrActive = false
            let ktrrR = tp_ktrr_enforcement_detector(&ktrrActive)
            let ktrrState = ktrrR.code == 0 ? (ktrrActive ? "ACTIVE ⚠️" : "INACTIVE ✅") : "UNKNOWN ❌"

            lines.append(String(format: "[PAC]      Status: %@", hasPAC ? "ARMED ⚠️" : "ABSENT ✅"))
            lines.append(String(format: "[PPL]      Status: %@", pplState))
            lines.append(String(format: "[KTRR]     Status: %@", ktrrState))
            lines.append(String(format: "[AMFI]     Status: %@", amfiState))
// 6. Offsets / Symbols
            let offsetsOK = mgr.hasOffsets
            let keyOff1 = off_proc_p_proc_ro
            let keyOff2 = off_proc_ro_p_ucred
            let keyOff3 = off_task_map
            let symState = (keyOff1 != 0 && keyOff2 != 0 && keyOff3 != 0) ? "RESOLVED" : "PARTIAL"

            lines.append(String(format: "[OFFSETS]  State: %-20@  Resolver: %@", (offsetsOK ? "LOADED" : "MISSING") as NSString, symState))
            if symState == "PARTIAL" {
                lines.append(String(format: "           proc_ro=%u  ucred=%u  task_map=%u", keyOff1, keyOff2, keyOff3))
            }

            // 7. Subsystems
            lines.append(String(format: "[VFS]      State: %@", mgr.vfsready ? "MOUNTED" : "NOT MOUNTED"))
            lines.append(String(format: "[SBX]      State: %@", mgr.sbxready ? "ESCAPED" : "CONFINED"))
            lines.append(String(format: "[RC]       State: %@", mgr.rcready ? "ARMED" : "DISARMED"))
            lines.append(String(format: "[KACCESS]  State: %@", mgr.kaccessready ? "READY" : (mgr.kaccesserror != nil ? "FAULT: \(mgr.kaccesserror!)" : "NOT READY")))

            // 8. Actionable Summary
            lines.append("")
            lines.append("--- ASSESSMENT ---")
            if !krwReady {
                lines.append("❌ KRW subsystem failed. Execute 'run' to re-exploit.")
            } else if !offsetsOK {
                lines.append("❌ Kernel offsets unresolved. Execute 'offsets' or 'fixoffsets'.")
            } else if amfiEnforce == 0xFFFFFFFF {
                lines.append("❌ AMFI status unreadable (mac_proc_enforce offset unknown).")
                lines.append("   Run: offsets → fixoffsets → auto-ppl-breaker")
                lines.append("   Or:  This iOS version may require updated offsets.")
            } else if !pmOK && !pplBypassed {
                lines.append("❌ PPL bypass unavailable — physmap fingerprint failed.")
                lines.append("   Phase 1 returned: pmap not found (pm_phase1_fingerprint = -2)")
                lines.append("   This device/iOS combination may not support physmap bypass.")
            } else if uid != 0 && !pplBypassed {
                lines.append("⚠️  Unprivileged (uid=\(uid)). PPL active but bypass ready.")
                lines.append("   Execute: auto-ppl-breaker")
            } else if uid == 0 && amfiEnforce != 0 {
                lines.append("⚠️  Root acquired but AMFI enforcing.")
                lines.append("   Execute: amfi-disable-globally")
            } else if uid == 0 {
                lines.append("✅ Fully privileged. AMFI disabled. Ready for operations.")
            } else {
                lines.append("⚠️  Partial state. Review individual subsystem states above.")
            }
            lines.append("=== END DIAGNOSTIC ===")
        return .ok(lines.joined(separator: "\n"))
        }


        OmegaCore.register("kread") { arg, mgr in
            guard mgr.dsready else { return .fail("kread: exploit not ready") }
            guard ds_is_ready() else { return .fail("kread: kernel r/w unavailable — revive session or re-run exploit") }
            guard let addr = parseAddr(arg) else {
                return .fail("kread: invalid address — example: kread 0xfffffff014d60000")
            }
            guard ds_isvalid(addr) else {
                return .fail(String(format: "kread: 0x%016llx is not a valid kernel address (bit63 must be set on arm64e)", addr))
            }
            let val = mgr.kread64(address: addr)
            var pacNote = ""
            if val != 0 && (val & 0xFFFF000000000000) != 0 {
                if (val & (1 << 63)) == 0 {
                    pacNote = "  [WARNING: bit63=0 — stripped PAC or non-pointer value]"
                }
            }
            return .ok(String(format: "0x%016llx  =  0x%016llx  (%llu)%@", addr, val, val, pacNote))
        }

        OmegaCore.register("kwrite") { arg, mgr in
            guard mgr.dsready else { return .fail("kwrite: exploit not ready") }
            let parts = arg.split(separator: " ").map { String($0) }
            guard parts.count == 2, let addr = parseAddr(parts[0]), let val = parseAddr(parts[1]) else {
                return .fail("kwrite: usage: kwrite <addr> <value>")
            }
            guard ds_isvalid(addr) else {
                return .fail(String(format: "kwrite: 0x%016llx is not a valid kernel address (bit63 must be set on arm64e)", addr))
            }
            mgr.kwrite64(address: addr, value: val)
            return .ok(String(format: "wrote 0x%016llx → [0x%016llx]", val, addr))
        }

        OmegaCore.register("kread32") { arg, mgr in
            guard mgr.dsready else { return .fail("kread32: exploit not ready") }
            guard let addr = parseAddr(arg) else { return .fail("kread32: invalid address") }
            let val = mgr.kread32(address: addr)
            return .ok(String(format: "0x%016llx  =  0x%08x  (%u)", addr, val, val))
        }

        OmegaCore.register("kwrite32") { arg, mgr in
            guard mgr.dsready else { return .fail("kwrite32: exploit not ready") }
            let parts = arg.split(separator: " ").map { String($0) }
            guard parts.count == 2,
                  let addr = parseAddr(parts[0]),
                  let val  = UInt32(parts[1].hasPrefix("0x") ? String(parts[1].dropFirst(2)) : parts[1],
                                    radix: parts[1].hasPrefix("0x") ? 16 : 10) else {
                return .fail("kwrite32: usage: kwrite32 <addr> <value>")
            }
            mgr.kwrite32(address: addr, value: val)
            return .ok(String(format: "wrote 0x%08x → [0x%016llx]", val, addr))
        }

        OmegaCore.register("kcstr") { arg, mgr in
            guard mgr.dsready else { return .fail("kcstr: exploit not ready") }
            guard let addr = parseAddr(arg) else { return .fail("kcstr: invalid address") }
            var result = ""
            var a = addr
            for _ in 0..<256 {
                let word = mgr.kread64(address: a)
                for shift in [0, 8, 16, 24, 32, 40, 48, 56] {
                    let byte = UInt8((word >> shift) & 0xFF)
                    if byte == 0 { return .ok(result.isEmpty ? "(empty string)" : result) }
                    result.append(Character(UnicodeScalar(byte)))
                }
                a += 8
            }
            return .ok(result + "... (truncated)")
        }

        OmegaCore.register("kbytes") { arg, mgr in
            guard mgr.dsready else { return .fail("kbytes: exploit not ready") }
            let parts = arg.split(separator: " ").map { String($0) }
            guard parts.count >= 1, let addr = parseAddr(parts[0]) else {
                return .fail("kbytes: usage: kbytes <addr> [count]")
            }
            let count = min(parts.count > 1 ? Int(parts[1]) ?? 64 : 64, 512)
            var lines: [String] = []
            var off = 0
            var a = addr
            while off < count {
                let word = mgr.kread64(address: a)
                var row = String(format: "  %016llx  ", a)
                for b in 0..<8 {
                    if off + b < count {
                        row += String(format: "%02x ", UInt8((word >> (b * 8)) & 0xFF))
                    }
                }
                lines.append(row)
                a += 8
                off += 8
            }
            return .ok(lines.joined(separator: "\n"))
        }

        OmegaCore.register("proc-walk") { _, _ in
              // proc-walk — قائمة العمليات من libproc (Single Source of Truth)
              // لا يتطلب exploit — يعمل دائماً بدون kernel allproc
              let meta  = ProcessLayer.shared.listAllWithMeta()
              let procs = meta.entries

              guard !procs.isEmpty else {
                  return .fail(
                      "proc-walk: 0 processes returned\n"
                      + "  source: \(meta.primarySource)  skipped: \(meta.skippedCount)\n"
                      + "  check logs with: logs"
                  )
              }

              var lines: [String] = [
                  "  Process Walk — libproc (Single Source of Truth)",
                  "  source: \(meta.primarySource)  total: \(procs.count)",
                  "  FULL=\(meta.fullCount)  PARTIAL=\(meta.partialCount)  BLOCKED=\(meta.blockedCount)  RFAIL=\(meta.readFailCount)  iOS-access=\(meta.completenessPercent)%  skipped=\(meta.skippedCount)",
                  "",
                  _col([7, 6, 6, 4, 28], ["PID", "PPID", "UID", "STA", "NAME"]),
                  String(repeating: "─", count: 58),
              ]

              for p in procs {
                  lines.append(_col([7, 6, 6, 4, 28],
                      [String(p.pid), String(p.ppid), String(p.uid),
                       p.status.rawValue, p.name]))
              }
              lines.append("")
              lines.append("  [source: \(meta.primarySource)\(meta.fallbackUsed ? " (fallback)" : "")  iOS-access: \(meta.completenessPercent)% full]")
              return .ok(lines.joined(separator: "\n"))
          }
    }

    // MARK: - VFS

    private static func registerVFS() {
        let fs = OmegaFS.shared

        OmegaCore.register("vls") { arg, mgr in
            guard mgr.vfsready else { return .fail("vls: VFS not ready — run 'vfs' first") }
            let path = arg.isEmpty ? fs.cwd : fs.resolve(arg)
            guard let entries = mgr.vfslistdir(path: path) else {
                return .fail("vls: cannot list \(path)")
            }
            if entries.isEmpty { return .ok("(empty)") }
            let lines = entries.map { e -> String in
                let icon = e.isDir ? "d" : "-"
                return "\(icon)  \(e.name)"
            }
            return .ok("vfs listing: \(path)\n" + lines.joined(separator: "\n"))
        }

        OmegaCore.register("vcat") { arg, mgr in
            guard mgr.vfsready else { return .fail("vcat: VFS not ready") }
            let path = fs.resolve(arg.trimmingCharacters(in: .whitespaces))
            guard let data = mgr.vfsread(path: path) else {
                return .fail("vcat: cannot read \(path)")
            }
            if let plist = santanderfs.plisttext(data: data) { return .ok(plist) }
            if let text = santanderfs.textdecode(data: data) { return .ok(text) }
            return .ok(santanderfs.hexdump(data: data))
        }

        OmegaCore.register("vsize") { arg, mgr in
            guard mgr.vfsready else { return .fail("vsize: VFS not ready") }
            let path = fs.resolve(arg.trimmingCharacters(in: .whitespaces))
            let sz = mgr.vfssize(path: path)
            guard sz >= 0 else { return .fail("vsize: cannot stat \(path)") }
            return .ok("\(path)\n  size: \(sz) bytes (\(formatBytes(sz)))")
        }

        OmegaCore.register("voverwrite") { arg, mgr in
            let parts = arg.split(separator: " ", maxSplits: 1).map { String($0) }
            guard parts.count == 2 else {
                return .fail("voverwrite: usage: voverwrite <target_path> <local_source>")
            }
            let result = mgr.lara_overwritefile(target: parts[0], source: fs.resolve(parts[1]))
            return result.ok ? .ok("[OK] overwritten: \(parts[0])") : .fail("voverwrite: \(result.message)")
        }

        OmegaCore.register("vzero") { arg, mgr in
            guard mgr.vfsready else { return .fail("vzero: VFS not ready") }
            let path = arg.trimmingCharacters(in: .whitespaces)
            let ok = mgr.vfszeropage(at: path, dumb: false)
            return ok ? .ok("[OK] zeroed first page of \(path)") : .fail("vzero: failed on \(path)")
        }
    }

    // MARK: - VFS Extended

    private static func registerVFSExtended() {
        let fs = OmegaFS.shared

        OmegaCore.register("vhex") { arg, mgr in
            guard mgr.vfsready else { return .fail("vhex: VFS not ready") }
            let path = fs.resolve(arg.trimmingCharacters(in: .whitespaces))
            guard let data = mgr.vfsread(path: path, maxSize: 4096) else {
                return .fail("vhex: cannot read \(path)")
            }
            return .ok(santanderfs.hexdump(data: data))
        }

        OmegaCore.register("vwrite") { arg, mgr in
            guard mgr.vfsready else { return .fail("vwrite: VFS not ready") }
            let parts = arg.split(separator: " ", maxSplits: 1).map { String($0) }
            guard parts.count == 2 else { return .fail("vwrite: usage: vwrite <path> <text>") }
            let path = fs.resolve(parts[0])
            guard let data = parts[1].data(using: .utf8) else {
                return .fail("vwrite: encoding error")
            }
            let ok = mgr.vfsoverwritewithdata(target: path, data: data)
            return ok ? .ok("[OK] wrote \(data.count) bytes to \(path)") : .fail("vwrite: failed on \(path)")
        }

        OmegaCore.register("vcopy") { arg, mgr in
            guard mgr.vfsready else { return .fail("vcopy: VFS not ready") }
            let parts = arg.split(separator: " ").map { String($0) }
            guard parts.count == 2 else { return .fail("vcopy: usage: vcopy <src> <dst>") }
            let src = fs.resolve(parts[0])
            let dst = parts[1]
            guard let data = mgr.vfsread(path: src) else {
                return .fail("vcopy: cannot read \(src)")
            }
            let ok = mgr.vfsoverwritewithdata(target: dst, data: data)
            return ok ? .ok("[OK] copied \(src) → \(dst) (\(data.count) bytes)") : .fail("vcopy: failed writing to \(dst)")
        }

        OmegaCore.register("vstat") { arg, mgr in
            guard mgr.vfsready else { return .fail("vstat: VFS not ready") }
            let path = fs.resolve(arg.trimmingCharacters(in: .whitespaces))
            let sz = mgr.vfssize(path: path)
            if sz < 0 { return .fail("vstat: cannot stat \(path)") }
            guard let entries = mgr.vfslistdir(path: (path as NSString).deletingLastPathComponent) else {
                return .ok("  path: \(path)\n  size: \(formatBytes(sz))")
            }
            let name = (path as NSString).lastPathComponent
            let entry = entries.first { $0.name == name }
            let kind = entry?.isDir == true ? "directory" : "regular file"
            return .ok("""
  path:  \(path)
  kind:  \(kind)
  size:  \(sz) bytes (\(formatBytes(sz)))
""")
        }
    }

    // MARK: - Apps

    private static func registerApps() {
        let fs = OmegaFS.shared
        let dataBase   = "/private/var/mobile/Containers/Data/Application"
        let bundleBase = "/private/var/containers/Bundle/Application"

        OmegaCore.register("apps") { arg, mgr in
            guard let list = mgr.getAppList(), !list.isEmpty else {
                return .fail("apps: unable to get app list")
            }
            let filter = arg.trimmingCharacters(in: .whitespaces).lowercased()
            var lines = [String(format: "  %-45@  %@", "Bundle ID" as NSString, "Name" as NSString)]
            lines.append("  " + String(repeating: "─", count: 70))
            for (bid, info) in list.sorted(by: { $0.key < $1.key }) {
                let name = info.displayName.isEmpty
                    ? (info.bundleName.isEmpty ? info.executable : info.bundleName)
                    : info.displayName
                if filter.isEmpty || bid.lowercased().contains(filter) || name.lowercased().contains(filter) {
                    lines.append(String(format: "  %-45@  %@", bid as NSString, name))
                }
            }
            if lines.count <= 2 { return .ok("no apps matched '\(filter)'") }
            return .ok(lines.joined(separator: "\n"))
        }

        OmegaCore.register("app-info") { arg, mgr in
            let bid = arg.trimmingCharacters(in: .whitespaces)
            guard !bid.isEmpty else { return .fail("app-info: usage: app-info <bundleId>") }
            guard let list = mgr.getAppList(), let info = list[bid] else {
                return .fail("app-info: '\(bid)' not found")
            }
            let name = info.displayName.isEmpty ? info.bundleName : info.displayName
            let dataPath   = info.dataFolder.isEmpty ? "(not found)" : "\(dataBase)/\(info.dataFolder)"
            let bundlePath = info.bundleFolder.isEmpty ? "(not found)" : "\(bundleBase)/\(info.bundleFolder)"
            let pid = findPidByBundleId(bid, mgr: mgr)
            let pidStr = pid.map { "\($0)" } ?? "(not running)"
            return .ok("""
  Bundle ID  : \(bid)
  Name       : \(name)
  Executable : \(info.executable)
  PID        : \(pidStr)
  Data       : \(dataPath)
  Bundle     : \(bundlePath)
""")
        }

        OmegaCore.register("app-data") { arg, mgr in
            let bid = arg.trimmingCharacters(in: .whitespaces)
            guard !bid.isEmpty else { return .fail("app-data: usage: app-data <bundleId>") }
            guard let list = mgr.getAppList(), let info = list[bid], !info.dataFolder.isEmpty else {
                return .fail("app-data: '\(bid)' not found")
            }
            return .result(fs.cd("\(dataBase)/\(info.dataFolder)"))
        }

        OmegaCore.register("app-bundle") { arg, mgr in
            let bid = arg.trimmingCharacters(in: .whitespaces)
            guard !bid.isEmpty else { return .fail("app-bundle: usage: app-bundle <bundleId>") }
            guard let list = mgr.getAppList(), let info = list[bid], !info.bundleFolder.isEmpty else {
                return .fail("app-bundle: '\(bid)' not found")
            }
            return .result(fs.cd("\(bundleBase)/\(info.bundleFolder)"))
        }

        OmegaCore.register("app-prefs") { arg, mgr in
            let bid = arg.trimmingCharacters(in: .whitespaces)
            guard !bid.isEmpty else { return .fail("app-prefs: usage: app-prefs <bundleId>") }
            let prefPath = "/var/mobile/Library/Preferences/\(bid).plist"
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: prefPath)) else {
                return .fail("app-prefs: no preferences for '\(bid)'\n(expected: \(prefPath))")
            }
            if let text = santanderfs.plisttext(data: data) { return .ok(text) }
            return .ok("(binary — \(data.count) bytes)")
        }

        OmegaCore.register("app-env") { arg, mgr in
            let bid = arg.trimmingCharacters(in: .whitespaces)
            guard !bid.isEmpty else { return .fail("app-env: usage: app-env <bundleId>") }
            guard let list = mgr.getAppList(), let info = list[bid], !info.bundleFolder.isEmpty else {
                return .fail("app-env: '\(bid)' not found")
            }
            let fm = FileManager.default
            let base = "\(bundleBase)/\(info.bundleFolder)"
            guard let contents = try? fm.contentsOfDirectory(atPath: base) else {
                return .fail("app-env: cannot read bundle folder")
            }
            let appDir = contents.first(where: { $0.hasSuffix(".app") }) ?? ""
            let envPath = "\(base)/\(appDir)/.com.apple.mobile_container_manager.metadata.plist"
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: envPath)) else {
                return .fail("app-env: no environment plist at \(envPath)")
            }
            if let text = santanderfs.plisttext(data: data) { return .ok(text) }
            return .ok("(binary — \(data.count) bytes)")
        }

        OmegaCore.register("app-entitlements") { arg, mgr in
            let bid = arg.trimmingCharacters(in: .whitespaces)
            guard !bid.isEmpty else { return .fail("app-entitlements: usage: app-entitlements <bundleId>") }
            guard let list = mgr.getAppList(), let info = list[bid], !info.bundleFolder.isEmpty else {
                return .fail("app-entitlements: '\(bid)' not found")
            }
            let fm = FileManager.default
            let base = "\(bundleBase)/\(info.bundleFolder)"
            guard let contents = try? fm.contentsOfDirectory(atPath: base) else {
                return .fail("app-entitlements: cannot read bundle")
            }
            let appDir = contents.first(where: { $0.hasSuffix(".app") }) ?? ""
            let binPath = "\(base)/\(appDir)/\(info.executable)"
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: binPath)) else {
                return .fail("app-entitlements: cannot read binary at \(binPath)")
            }
            if let entsRange = findEntitlements(in: data) {
                let entsData = data.subdata(in: entsRange)
                if let text = santanderfs.plisttext(data: entsData) ?? santanderfs.textdecode(data: entsData) {
                    return .ok("Entitlements for \(bid):\n\n\(text)")
                }
            }
            return .ok("app-entitlements: could not extract entitlements from \(binPath)\n(may require VFS read)")
        }

        OmegaCore.register("app-version") { arg, mgr in
            let bid = arg.trimmingCharacters(in: .whitespaces)
            guard !bid.isEmpty else { return .fail("app-version: usage: app-version <bundleId>") }
            guard let list = mgr.getAppList(), let info = list[bid], !info.bundleFolder.isEmpty else {
                return .fail("app-version: '\(bid)' not found")
            }
            let fm = FileManager.default
            let base = "\(bundleBase)/\(info.bundleFolder)"
            guard let contents = try? fm.contentsOfDirectory(atPath: base) else {
                return .fail("app-version: cannot read bundle")
            }
            let appDir = contents.first(where: { $0.hasSuffix(".app") }) ?? ""
            let infoPath = "\(base)/\(appDir)/Info.plist"
            guard let plist = NSDictionary(contentsOf: URL(fileURLWithPath: infoPath)) else {
                return .fail("app-version: cannot read Info.plist")
            }
            let ver   = plist["CFBundleShortVersionString"] as? String ?? "?"
            let build = plist["CFBundleVersion"] as? String ?? "?"
            let minOS = plist["MinimumOSVersion"] as? String ?? "?"
            let name  = (plist["CFBundleDisplayName"] as? String) ?? (plist["CFBundleName"] as? String) ?? bid
            return .ok("\(name)  v\(ver)  (build \(build))  minOS: \(minOS)")
        }

        OmegaCore.register("app-list-files") { arg, mgr in
            let bid = arg.trimmingCharacters(in: .whitespaces)
            guard !bid.isEmpty else { return .fail("app-list-files: usage: app-list-files <bundleId>") }
            guard let list = mgr.getAppList(), let info = list[bid] else {
                return .fail("app-list-files: '\(bid)' not found")
            }
            var lines: [String] = []
            let fm = FileManager.default
            if !info.dataFolder.isEmpty {
                let base = "\(dataBase)/\(info.dataFolder)"
                lines.append("=== Data Container: \(base) ===")
                if let items = try? fm.contentsOfDirectory(atPath: base) {
                    for item in items.sorted() {
                        var isDir: ObjCBool = false
                        fm.fileExists(atPath: "\(base)/\(item)", isDirectory: &isDir)
                        lines.append("  \(isDir.boolValue ? "d" : "-")  \(item)")
                    }
                }
            }
            if !info.bundleFolder.isEmpty {
                let base = "\(bundleBase)/\(info.bundleFolder)"
                lines.append("=== Bundle Container: \(base) ===")
                if let items = try? fm.contentsOfDirectory(atPath: base) {
                    for item in items.sorted() {
                        lines.append("  \(item)")
                    }
                }
            }
            return .ok(lines.joined(separator: "\n"))
        }

        OmegaCore.register("app-container") { arg, mgr in
            let bid = arg.trimmingCharacters(in: .whitespaces)
            guard !bid.isEmpty else { return .fail("app-container: usage: app-container <bundleId>") }
            guard let list = mgr.getAppList(), let info = list[bid] else {
                return .fail("app-container: '\(bid)' not found")
            }
            return .ok("""
  Bundle ID     : \(bid)
  Data UUID     : \(info.dataFolder.isEmpty ? "(none)" : info.dataFolder)
  Bundle UUID   : \(info.bundleFolder.isEmpty ? "(none)" : info.bundleFolder)
  Data Path     : \(info.dataFolder.isEmpty ? "(none)" : "\(dataBase)/\(info.dataFolder)")
  Bundle Path   : \(info.bundleFolder.isEmpty ? "(none)" : "\(bundleBase)/\(info.bundleFolder)")
""")
        }
    }

    // MARK: - Plist

    private static func registerPlist() {
        let fs = OmegaFS.shared

        OmegaCore.register("plist") { arg, _ in
            let path = fs.resolve(arg.trimmingCharacters(in: .whitespaces))
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
                return .fail("plist: cannot read \(path)")
            }
            guard let text = santanderfs.plisttext(data: data) else {
                return .fail("plist: \(path) is not a valid plist")
            }
            return .ok(text)
        }

        OmegaCore.register("plist-get") { arg, mgr in
            let parts = arg.split(separator: " ", maxSplits: 1).map { String($0) }
            guard parts.count == 2 else { return .fail("plist-get: usage: plist-get <path> <key>") }
            let path = fs.resolve(parts[0])
            let r = mgr.getplistvalue(path: path, key: parts[1])
            guard r.ok, let val = r.value else { return .fail("plist-get: \(r.message)") }
            return .ok("\(parts[1]) = \(val)")
        }

        OmegaCore.register("plist-set") { arg, mgr in
            let parts = arg.split(separator: " ", maxSplits: 3).map { String($0) }
            guard parts.count == 4 else {
                return .fail("plist-set: usage: plist-set <path> <key> <type> <value>\n  types: str | bool | int | float")
            }
            let path = fs.resolve(parts[0])
            let key  = parts[1]
            let rawVal = parts[3]

            let value: Any
            switch parts[2].lowercased() {
            case "str":   value = rawVal
            case "bool":  value = (rawVal == "true" || rawVal == "1" || rawVal == "yes")
            case "int":
                guard let i = Int(rawVal) else { return .fail("plist-set: invalid int '\(rawVal)'") }
                value = i
            case "float":
                guard let f = Double(rawVal) else { return .fail("plist-set: invalid float '\(rawVal)'") }
                value = f
            default:
                return .fail("plist-set: unknown type '\(parts[2])' — use: str | bool | int | float")
            }
            let r = mgr.setplistvalue(path: path, key: (key: key, value: value), force: true)
            return r.ok ? .ok("[OK] \(key) = \(rawVal) (\(parts[2])) in \(path)") : .fail("plist-set: \(r.message)")
        }

        OmegaCore.register("plist-del") { arg, mgr in
            let parts = arg.split(separator: " ", maxSplits: 1).map { String($0) }
            guard parts.count == 2 else { return .fail("plist-del: usage: plist-del <path> <key>") }
            let path = fs.resolve(parts[0])
            let r = mgr.setplistvalue(path: path, key: (key: parts[1], value: nil), force: false)
            return r.ok ? .ok("[OK] deleted '\(parts[1])' from \(path)") : .fail("plist-del: \(r.message)")
        }

        OmegaCore.register("plist-keys") { arg, _ in
            let path = fs.resolve(arg.trimmingCharacters(in: .whitespaces))
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                  let obj = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
                  let dict = obj as? NSDictionary else {
                return .fail("plist-keys: cannot read or parse \(path)")
            }
            let keys = (dict.allKeys as? [String] ?? []).sorted()
            return .ok("Keys in \(path):\n" + keys.map { "  \($0)" }.joined(separator: "\n"))
        }
    }

    // MARK: - Execution

    private static func registerExec() {

        OmegaCore.register("exec") { arg, _ in
            guard !arg.isEmpty else { return .fail("exec: usage: exec <binary> [args...]") }
            let parts = arg.split(separator: " ").map { String($0) }
            let raw = parts[0]
            let binary: String
            if raw.hasPrefix("/") {
                binary = raw
            } else {
                let paths = ["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin"]
                binary = paths.compactMap {
                    let p = "\($0)/\(raw)"
                    return FileManager.default.isExecutableFile(atPath: p) ? p : nil
                }.first ?? raw
            }

            var pipefd = [Int32](repeating: 0, count: 2)
            guard pipe(&pipefd) == 0 else { return .fail("exec: pipe() failed") }

            var pid: pid_t = 0
            var fa: posix_spawn_file_actions_t?
            posix_spawn_file_actions_init(&fa)
            posix_spawn_file_actions_adddup2(&fa, pipefd[1], STDOUT_FILENO)
            posix_spawn_file_actions_adddup2(&fa, pipefd[1], STDERR_FILENO)
            posix_spawn_file_actions_addclose(&fa, pipefd[0])

            var cargs = parts.map { strdup($0) }
            cargs[0] = strdup(binary)
            cargs.append(nil)

            let spawnResult = posix_spawn(&pid, binary, &fa, nil, &cargs, environ)
            cargs.compactMap { $0 }.forEach { free($0) }
            posix_spawn_file_actions_destroy(&fa)
            close(pipefd[1])

            guard spawnResult == 0 else {
                close(pipefd[0])
                return .fail("exec: \(binary): \(String(cString: strerror(spawnResult)))")
            }

            var output = ""
            var buf = [UInt8](repeating: 0, count: 4096)
            while true {
                let n = read(pipefd[0], &buf, 4095)
                if n <= 0 { break }
                buf[Int(n)] = 0
                output += String(cString: buf)
            }
            close(pipefd[0])

            var status: Int32 = 0
            waitpid(pid, &status, 0)
            let exit_code = WEXITSTATUS(status)

            let trimmed = output.trimmingCharacters(in: .newlines)
            if trimmed.isEmpty { return .ok("(exit \(exit_code), no output)") }
            return exit_code == 0 ? .ok(trimmed) : CommandResult(output: trimmed, isError: true)
        }

        OmegaCore.register("exec-bg") { arg, _ in
            guard !arg.isEmpty else { return .fail("exec-bg: usage: exec-bg <binary> [args...]") }
            let parts = arg.split(separator: " ").map { String($0) }
            let raw = parts[0]
            let binary: String
            if raw.hasPrefix("/") {
                binary = raw
            } else {
                let paths = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
                binary = paths.compactMap {
                    let p = "\($0)/\(raw)"
                    return FileManager.default.isExecutableFile(atPath: p) ? p : nil
                }.first ?? raw
            }
            var cargs = parts.map { strdup($0) }
            cargs[0] = strdup(binary)
            cargs.append(nil)
            var pid: pid_t = 0
            let r = posix_spawn(&pid, binary, nil, nil, &cargs, environ)
            cargs.compactMap { $0 }.forEach { free($0) }
            return r == 0 ? .ok("started \(binary) with pid \(pid)") : .fail("exec-bg: \(String(cString: strerror(r)))")
        }

        OmegaCore.register("sysctl") { arg, mgr in
            let tokens = arg.trimmingCharacters(in: .whitespaces)
                .split(separator: " ").map { String($0) }.filter { !$0.isEmpty }
            if tokens.isEmpty || tokens.contains("-a") || tokens.contains("-A") {
                return OmegaCore.execute("sysctl-all", context: mgr)
            }
            let keys = tokens.filter { !$0.hasPrefix("-") }
            guard !keys.isEmpty else {
                return .fail("sysctl: usage: sysctl [-a] <key> [key2 ...]")
            }
            var out = [String]()
            for key in keys {
                var strSz = 0
                if sysctlbyname(key, nil, &strSz, nil, 0) == 0, strSz > 1 {
                    var sb = [CChar](repeating: 0, count: strSz + 1)
                    if sysctlbyname(key, &sb, &strSz, nil, 0) == 0 {
                        let sv = String(cString: sb)
                        if !sv.isEmpty { out.append("\(key) = \(sv)"); continue }
                    }
                }
                var i64: Int64 = 0; var i64sz = MemoryLayout<Int64>.size
                if sysctlbyname(key, &i64, &i64sz, nil, 0) == 0, i64sz == MemoryLayout<Int64>.size {
                    out.append("\(key) = \(i64)"); continue
                }
                var i32: Int32 = 0; var i32sz = MemoryLayout<Int32>.size
                if sysctlbyname(key, &i32, &i32sz, nil, 0) == 0, i32sz == MemoryLayout<Int32>.size {
                    out.append("\(key) = \(i32)"); continue
                }
                out.append("\(key): (not found)")
            }
            return .ok(out.joined(separator: "\n"))
        }

        OmegaCore.register("sysctl-all") { _, _ in
            let keys = [
                "kern.version", "kern.osversion", "kern.hostname",
                "kern.maxproc", "kern.maxfiles", "kern.boottime",
                "hw.machine", "hw.model", "hw.ncpu", "hw.physmem",
                "hw.pagesize", "hw.cpufrequency_max",
                "vm.swapusage", "net.inet.tcp.delayed_ack"
            ]
            var lines: [String] = []
            for key in keys {
                var size = 0
                if sysctlbyname(key, nil, &size, nil, 0) == 0, size > 0 {
                    var buf = [CChar](repeating: 0, count: size + 1)
                    if sysctlbyname(key, &buf, &size, nil, 0) == 0 {
                        lines.append("  \(key) = \(String(cString: buf))")
                    }
                }
            }
            return .ok(lines.joined(separator: "\n"))
        }

        OmegaCore.register("notif") { arg, _ in
            let name = arg.trimmingCharacters(in: .whitespaces)
            guard !name.isEmpty else { return .fail("notif: usage: notif <darwin_notification_name>") }
            notify_post(name)
            return .ok("posted: \(name)")
        }

        OmegaCore.register("launchctl") { arg, _ in
            let parts = arg.split(separator: " ").map { String($0) }
            guard !parts.isEmpty else { return .fail("launchctl: usage: launchctl <kickstart|stop|list> [service]") }
            let binary = "/bin/launchctl"
            guard FileManager.default.isExecutableFile(atPath: binary) else {
                return .fail("launchctl: not found at /bin/launchctl")
            }
            var allArgs = [binary] + parts
            var pipefd = [Int32](repeating: 0, count: 2)
            guard pipe(&pipefd) == 0 else { return .fail("launchctl: pipe failed") }
            var pid: pid_t = 0
            var fa: posix_spawn_file_actions_t?
            posix_spawn_file_actions_init(&fa)
            posix_spawn_file_actions_adddup2(&fa, pipefd[1], STDOUT_FILENO)
            posix_spawn_file_actions_adddup2(&fa, pipefd[1], STDERR_FILENO)
            posix_spawn_file_actions_addclose(&fa, pipefd[0])
            var cargs = allArgs.map { strdup($0) }
            cargs.append(nil)
            let r = posix_spawn(&pid, binary, &fa, nil, &cargs, environ)
            cargs.compactMap { $0 }.forEach { free($0) }
            posix_spawn_file_actions_destroy(&fa)
            close(pipefd[1])
            guard r == 0 else { close(pipefd[0]); return .fail("launchctl: spawn failed: \(r)") }
            var out = ""; var buf = [UInt8](repeating: 0, count: 4096)
            while true { let n = Darwin.read(pipefd[0], &buf, 4095); if n <= 0 { break }; buf[Int(n)] = 0; out += String(cString: buf) }
            close(pipefd[0])
            var status: Int32 = 0; waitpid(pid, &status, 0)
            return .ok(out.trimmingCharacters(in: .newlines).isEmpty ? "(no output)" : out.trimmingCharacters(in: .newlines))
        }
    }

    // MARK: - File Tools

    private static func registerFileTools() {

        OmegaCore.register("hexdump") { arg, _ in
            let fs = OmegaFS.shared
            let parts = arg.split(separator: " ").map { String($0) }
            guard !parts.isEmpty else { return .fail("hexdump: usage: hexdump <path> [bytes]") }
            let path = fs.resolve(parts[0])
            let maxBytes = parts.count > 1 ? Int(parts[1]) ?? 256 : 256
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
                return .fail("hexdump: cannot read \(path)")
            }
            return .ok(santanderfs.hexdump(data: data.prefix(maxBytes)))
        }

        OmegaCore.register("grep") { arg, _ in
            let fs = OmegaFS.shared
            let parts = arg.split(separator: " ", maxSplits: 1).map { String($0) }
            guard !parts.isEmpty else { return .fail("grep: usage: grep <pattern> <file|-|path>") }
            let pattern = parts[0]

            let text: String
            if parts.count == 1 || parts[1] == "-" {
                guard let buf = OmegaCore.pipeBuffer else {
                    return .fail("grep: no file specified and no piped input")
                }
                text = buf
            } else {
                let path = fs.resolve(parts[1])
                guard let content = try? String(contentsOfFile: path, encoding: .utf8) else {
                    return .fail("grep: cannot read \(parts[1])")
                }
                text = content
            }

            let lines = text.components(separatedBy: "\n")
            let matches = lines.enumerated().filter { $0.element.range(of: pattern, options: [.regularExpression, .caseInsensitive]) != nil }
            if matches.isEmpty { return .ok("(no matches)") }
            return .ok(matches.map { "  \($0.offset + 1): \($0.element)" }.joined(separator: "\n"))
        }

        OmegaCore.register("strings") { arg, _ in
            let fs = OmegaFS.shared
            let parts = arg.split(separator: " ").map { String($0) }
            guard !parts.isEmpty else { return .fail("strings: usage: strings <path> [min_len]") }
            let path = fs.resolve(parts[0])
            let min = parts.count > 1 ? Int(parts[1]) ?? 4 : 4
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
                return .fail("strings: cannot read \(path)")
            }
            var results: [String] = []
            var current = ""
            for byte in data {
                if byte >= 0x20 && byte < 0x7F {
                    current.append(Character(UnicodeScalar(byte)))
                } else {
                    if current.count >= min { results.append(current) }
                    current = ""
                }
                if results.count > 500 { results.append("... (limited to 500)"); break }
            }
            if current.count >= min { results.append(current) }
            return .ok(results.isEmpty ? "(no strings found)" : results.joined(separator: "\n"))
        }

        OmegaCore.register("b64") { arg, _ in
            let fs = OmegaFS.shared
            let path = fs.resolve(arg.trimmingCharacters(in: .whitespaces))
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
                return .fail("b64: cannot read \(path)")
            }
            return .ok(data.base64EncodedString(options: [.lineLength76Characters]))
        }

        OmegaCore.register("b64d") { arg, _ in
            let fs = OmegaFS.shared
            let parts = arg.split(separator: " ", maxSplits: 1).map { String($0) }
            guard !parts.isEmpty else { return .fail("b64d: usage: b64d <outfile> <base64data>  OR  b64d <file_with_b64>") }
            if parts.count == 2 {
                guard let data = Data(base64Encoded: parts[1], options: .ignoreUnknownCharacters) else {
                    return .fail("b64d: invalid base64 input")
                }
                let dst = fs.resolve(parts[0])
                do { try data.write(to: URL(fileURLWithPath: dst)); return .ok("decoded \(data.count) bytes → \(dst)") }
                catch { return .fail("b64d: write failed: \(error.localizedDescription)") }
            }
            let path = fs.resolve(parts[0])
            guard let text = try? String(contentsOfFile: path, encoding: .utf8),
                  let data = Data(base64Encoded: text.trimmingCharacters(in: .whitespacesAndNewlines),
                                  options: .ignoreUnknownCharacters) else {
                return .fail("b64d: cannot decode \(path)")
            }
            return .ok(santanderfs.textdecode(data: data) ?? "(binary, \(data.count) bytes)")
        }

        OmegaCore.register("sha256") { arg, _ in
            let fs = OmegaFS.shared
            let path = fs.resolve(arg.trimmingCharacters(in: .whitespaces))
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
                return .fail("sha256: cannot read \(path)")
            }
            var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
            data.withUnsafeBytes { _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &digest) }
            let hex = digest.map { String(format: "%02x", $0) }.joined()
            return .ok("\(hex)  \(path)")
        }

        OmegaCore.register("wc") { arg, _ in
            let fs = OmegaFS.shared
            let text: String
            let label: String
            if arg == "-" || arg.isEmpty {
                guard let buf = OmegaCore.pipeBuffer else { return .fail("wc: no input") }
                text = buf; label = "-"
            } else {
                let path = fs.resolve(arg)
                guard let t = try? String(contentsOfFile: path, encoding: .utf8) else {
                    return .fail("wc: cannot read \(arg)")
                }
                text = t; label = arg
            }
            let lines = text.components(separatedBy: "\n").count
            let words = text.split { $0.isWhitespace }.count
            let bytes = text.utf8.count
            return .ok(String(format: "  %6d  %6d  %6d  %@", lines, words, bytes, label))
        }

        OmegaCore.register("sort") { arg, _ in
            let fs = OmegaFS.shared
            let parts = arg.split(separator: " ").map { String($0) }
            let rev = parts.contains("-r")
            let fileArg = parts.first { !$0.hasPrefix("-") }
            let text: String
            if fileArg == nil || fileArg == "-" {
                guard let buf = OmegaCore.pipeBuffer else { return .fail("sort: no input") }
                text = buf
            } else {
                let path = fs.resolve(fileArg!)
                guard let t = try? String(contentsOfFile: path, encoding: .utf8) else {
                    return .fail("sort: cannot read \(fileArg!)")
                }
                text = t
            }
            var lines = text.components(separatedBy: "\n")
            lines.sort { rev ? $0 > $1 : $0 < $1 }
            return .ok(lines.joined(separator: "\n"))
        }

        OmegaCore.register("uniq") { arg, _ in
            let fs = OmegaFS.shared
            let text: String
            if arg == "-" || arg.isEmpty {
                guard let buf = OmegaCore.pipeBuffer else { return .fail("uniq: no input") }
                text = buf
            } else {
                let path = fs.resolve(arg)
                guard let t = try? String(contentsOfFile: path, encoding: .utf8) else {
                    return .fail("uniq: cannot read \(arg)")
                }
                text = t
            }
            let lines = text.components(separatedBy: "\n")
            var out: [String] = []
            var prev: String? = nil
            for line in lines { if line != prev { out.append(line); prev = line } }
            return .ok(out.joined(separator: "\n"))
        }
    }

    // MARK: - Sandbox

    private static func registerSandbox() {
        OmegaCore.register("sbx-info") { _, mgr in
            let token = mgr.sbxgettokenstring(pid: getpid()) ?? "(unavailable)"
            return .ok("""
  sbx_ready     : \(mgr.sbxready)
  sbx_attempted : \(mgr.sbxattempted)
  sbx_failed    : \(mgr.sbxfailed)
  our_pid       : \(getpid())
  our_uid       : \(getuid())
  our_euid      : \(geteuid())
  sbx_token     : \(token.prefix(80))
  bundle_id     : \(Bundle.main.bundleIdentifier ?? "(unknown)")
""")
        }

        OmegaCore.register("sbx-token") { arg, mgr in
            guard let pid = Int32(arg.trimmingCharacters(in: .whitespaces)) else {
                return .fail("sbx-token: usage: sbx-token <pid>")
            }
            guard let addr = mgr.sbxgettoken(pid: pid) else {
                return .fail("sbx-token: failed for pid \(pid)")
            }
            return .ok(String(format: "sandbox token addr for pid \(pid): 0x%016llx", addr))
        }

        OmegaCore.register("sbx-token-str") { arg, mgr in
            guard let pid = Int32(arg.trimmingCharacters(in: .whitespaces)) else {
                return .fail("sbx-token-str: usage: sbx-token-str <pid>")
            }
            guard let tok = mgr.sbxgettokenstring(pid: pid) else {
                return .fail("sbx-token-str: failed for pid \(pid)")
            }
            return .ok("pid \(pid) sandbox token:\n\(tok)")
        }

        OmegaCore.register("sbx-issue") { arg, mgr in
            let parts = arg.split(separator: " ", maxSplits: 1).map { String($0) }
            guard parts.count == 2 else {
                return .fail("sbx-issue: usage: sbx-issue <extension_class> <path>\nexample: sbx-issue com.apple.security.application-groups /private/var")
            }
            guard let tok = mgr.sbxissuetoken(extClass: parts[0], path: parts[1]) else {
                return .fail("sbx-issue: failed to issue token for \(parts[0]) \(parts[1])")
            }
            return .ok("issued token:\n\(tok)")
        }

        OmegaCore.register("sbx-elevate") { _, mgr in
            guard mgr.sbxready else { return .fail("sbx-elevate: sandbox not escaped yet — run 'sbx' first") }
            mgr.sbxelevate()
            return .ok("[OK] sandbox elevated")
        }
    }

    // MARK: - MobileGestalt

    private static func registerGestalt() {
        OmegaCore.register("mg-info") { _, mgr in
            guard mgr.dsready else { return .fail("mg-info: exploit not ready") }
            let paths = [
                "/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist",
                "/private/var/MobileAsset/MobileGestalt.plist"
            ]
            for path in paths {
                if FileManager.default.fileExists(atPath: path) {
                    return .ok("gestalt path: \(path)")
                }
            }
            return .ok("gestalt file not found at known paths")
        }

        OmegaCore.register("mg-get") { arg, mgr in
            guard mgr.dsready else { return .fail("mg-get: exploit not ready") }
            let key = arg.trimmingCharacters(in: .whitespaces)
            guard !key.isEmpty else { return .fail("mg-get: usage: mg-get <key>") }
            let paths = [
                "/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist",
                "/private/var/MobileAsset/MobileGestalt.plist"
            ]
            for path in paths {
                let r = mgr.getplistvalue(path: path, key: key)
                if r.ok, let val = r.value {
                    return .ok("\(key) = \(val)")
                }
            }
            return .fail("mg-get: key '\(key)' not found in gestalt")
        }

        OmegaCore.register("mg-set") { arg, mgr in
            guard mgr.dsready else { return .fail("mg-set: exploit not ready") }
            let parts = arg.split(separator: " ", maxSplits: 1).map { String($0) }
            guard parts.count == 2 else { return .fail("mg-set: usage: mg-set <key> <value>") }
            let paths = [
                "/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist"
            ]
            for path in paths {
                if FileManager.default.fileExists(atPath: path) {
                    let r = mgr.setplistvalue(path: path, key: (key: parts[0], value: parts[1]), force: false)
                    return r.ok ? .ok("[OK] set \(parts[0]) = \(parts[1]) in gestalt") : .fail("mg-set: \(r.message)")
                }
            }
            return .fail("mg-set: gestalt file not found")
        }

        OmegaCore.register("mg-keys") { _, mgr in
            guard mgr.dsready else { return .fail("mg-keys: exploit not ready") }
            let paths = [
                "/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache/Library/Caches/com.apple.MobileGestalt.plist"
            ]
            for path in paths {
                guard FileManager.default.fileExists(atPath: path),
                      let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                      let obj = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
                      let dict = obj as? NSDictionary else { continue }
                let keys = (dict.allKeys as? [String] ?? []).sorted()
                return .ok("MobileGestalt keys (\(keys.count)):\n" + keys.map { "  \($0)" }.joined(separator: "\n"))
            }
            return .fail("mg-keys: gestalt file not found")
        }
    }

    // MARK: - Defaults

    private static func registerDefaults() {
        OmegaCore.register("defaults") { arg, _ in
            let parts = arg.split(separator: " ").map { String($0) }
            guard !parts.isEmpty else {
                return .fail("defaults: usage: defaults read|write|delete|domains <args>")
            }

            switch parts[0] {
            case "domains":
                let prefsPath = "/var/mobile/Library/Preferences"
                let fm = FileManager.default
                let files = (try? fm.contentsOfDirectory(atPath: prefsPath)) ?? []
                let domains = files
                    .filter { $0.hasSuffix(".plist") }
                    .map { ($0 as NSString).deletingPathExtension }
                    .sorted()
                return .ok(domains.map { "  \($0)" }.joined(separator: "\n"))

            case "read":
                guard parts.count >= 2 else {
                    return .fail("defaults read: usage: defaults read <domain> [key]")
                }
                let domain = parts[1]
                let path = domain.hasPrefix("/")
                    ? domain
                    : "/var/mobile/Library/Preferences/\(domain).plist"
                guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
                    return .fail("defaults read: domain '\(domain)' not found")
                }
                if parts.count >= 3 {
                    guard let obj = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
                          let dict = obj as? NSDictionary else {
                        return .fail("defaults read: cannot parse plist")
                    }
                    if let val = dict[parts[2]] {
                        return .ok("\(parts[2]) = \(val)")
                    }
                    return .fail("defaults read: key '\(parts[2])' not found in \(domain)")
                }
                if let text = santanderfs.plisttext(data: data) { return .ok(text) }
                return .ok("(binary, \(data.count) bytes)")

            case "write":
                guard parts.count >= 4 else {
                    return .fail("defaults write: usage: defaults write <domain> <key> <value>")
                }
                let domain = parts[1]
                let path = domain.hasPrefix("/")
                    ? domain
                    : "/var/mobile/Library/Preferences/\(domain).plist"
                let fm = FileManager.default
                var dict = NSMutableDictionary()
                if fm.fileExists(atPath: path),
                   let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                   let obj = try? PropertyListSerialization.propertyList(from: data, options: [.mutableContainersAndLeaves], format: nil),
                   let d = obj as? NSMutableDictionary {
                    dict = d
                }
                dict[parts[2]] = parts[3]
                guard let outData = try? PropertyListSerialization.data(fromPropertyList: dict, format: .binary, options: 0) else {
                    return .fail("defaults write: serialize failed")
                }
                do {
                    try outData.write(to: URL(fileURLWithPath: path), options: .atomic)
                    return .ok("[OK] \(parts[2]) = \(parts[3]) in \(domain)")
                } catch { return .fail("defaults write: \(error.localizedDescription)") }

            case "delete":
                guard parts.count >= 3 else {
                    return .fail("defaults delete: usage: defaults delete <domain> <key>")
                }
                let domain = parts[1]
                let path = domain.hasPrefix("/")
                    ? domain
                    : "/var/mobile/Library/Preferences/\(domain).plist"
                guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                      let obj = try? PropertyListSerialization.propertyList(from: data, options: [.mutableContainersAndLeaves], format: nil),
                      let dict = obj as? NSMutableDictionary else {
                    return .fail("defaults delete: cannot read '\(domain)'")
                }
                dict.removeObject(forKey: parts[2])
                guard let outData = try? PropertyListSerialization.data(fromPropertyList: dict, format: .binary, options: 0) else {
                    return .fail("defaults delete: serialize failed")
                }
                do {
                    try outData.write(to: URL(fileURLWithPath: path), options: .atomic)
                    return .ok("[OK] deleted '\(parts[2])' from \(domain)")
                } catch { return .fail("defaults delete: \(error.localizedDescription)") }

            default:
                return .fail("defaults: unknown subcommand '\(parts[0])' — use read|write|delete|domains")
            }
        }
    }

    // MARK: - Process Control

    private static func registerProcessControl() {

        OmegaCore.register("proc-kill") { arg, _ in
            guard let pid = Int32(arg.trimmingCharacters(in: .whitespaces)) else {
                return .fail("proc-kill: usage: proc-kill <pid>")
            }
            guard pid > 1 else { return .fail("proc-kill: refusing to kill pid \(pid)") }
            let r = kill(pid, SIGKILL)
            return r == 0 ? .ok("sent SIGKILL to \(pid)") : .fail("proc-kill: \(String(cString: strerror(errno)))")
        }

        OmegaCore.register("proc-signal") { arg, _ in
            let parts = arg.split(separator: " ").map { String($0) }
            guard parts.count == 2, let pid = Int32(parts[0]) else {
                return .fail("proc-signal: usage: proc-signal <pid> <signal>\ncommon: 1=HUP 2=INT 9=KILL 15=TERM 17=STOP 19=CONT")
            }
            let sigMap = ["HUP":1,"INT":2,"QUIT":3,"ILL":4,"TRAP":5,"ABRT":6,"KILL":9,"BUS":10,
                          "SEGV":11,"SYS":12,"PIPE":13,"ALRM":14,"TERM":15,"STOP":17,"TSTP":18,"CONT":19]
            let sigVal: Int32
            if let n = Int32(parts[1]) {
                sigVal = n
            } else if let s = sigMap[parts[1].uppercased()] {
                sigVal = Int32(s)
            } else {
                return .fail("proc-signal: unknown signal '\(parts[1])'")
            }
            let r = kill(pid, sigVal)
            return r == 0 ? .ok("sent signal \(sigVal) to \(pid)") : .fail("proc-signal: \(String(cString: strerror(errno)))")
        }

        OmegaCore.register("proc-suspend") { arg, _ in
            guard let pid = Int32(arg.trimmingCharacters(in: .whitespaces)) else {
                return .fail("proc-suspend: usage: proc-suspend <pid>")
            }
            let r = kill(pid, SIGSTOP)
            return r == 0 ? .ok("suspended pid \(pid)") : .fail("proc-suspend: \(String(cString: strerror(errno)))")
        }

        OmegaCore.register("proc-resume") { arg, _ in
            guard let pid = Int32(arg.trimmingCharacters(in: .whitespaces)) else {
                return .fail("proc-resume: usage: proc-resume <pid>")
            }
            let r = kill(pid, SIGCONT)
            return r == 0 ? .ok("resumed pid \(pid)") : .fail("proc-resume: \(String(cString: strerror(errno)))")
        }

        OmegaCore.register("proc-find") { arg, _ in
            let name = arg.trimmingCharacters(in: .whitespaces)
            guard !name.isEmpty else { return .fail("proc-find: usage: proc-find <name>") }
            let matches = ProcessLayer.shared.find(matching: name)
            if matches.isEmpty { return .ok("(no process matching '\(name)')") }
            var lines: [String] = [
                _col([7, 5, 3, 7, 7, 22], ["PID", "UID", "STA", "CLASS", "QUAL", "NAME"]),
                String(repeating: "-", count: 58),
            ]
            for p in matches {
                // Append block reason inline when iOS restricted — no hidden ??? values
                let nameField = p.blockedReason.isEmpty
                    ? p.name
                    : "\(p.name)  [\(p.blockedReason)]"
                lines.append(_col([7, 5, 3, 7, 7, 38],
                    [String(p.pid), String(p.uid), p.status.rawValue,
                     p.processClass.rawValue, p.quality.rawValue, nameField]))
            }
            return .ok(lines.joined(separator: "\n"))
        }


         OmegaCore.register("proc-cred") { arg, mgr in
             guard mgr.dsready else { return .fail("proc-cred: exploit not ready") }
             guard let pid = Int32(arg.trimmingCharacters(in: .whitespaces)) else {
                 return .fail("proc-cred: usage: proc-cred <pid>")
             }

             // Fast path: proc_pidinfo works for accessible (user) processes
             var info = proc_bsdinfo()
             if proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info,
                             Int32(MemoryLayout<proc_bsdinfo>.size)) > 0 {
                 return .ok("""
   pid   : \(pid)
   uid   : \(info.pbi_uid)
   gid   : \(info.pbi_gid)
   euid  : \(info.pbi_svuid)
   egid  : \(info.pbi_svgid)
   ppid  : \(info.pbi_ppid)
   [source: proc_pidinfo]
 """)
             }

             // ── SURGICAL FIX: Kernel fallback with dynamic offset probing ──
             guard mgr.hasOffsets else {
                 return .fail("proc-cred: proc_pidinfo blocked (iOS restriction); offsets not loaded")
             }
             let kaddr = procbypid(pid_t(pid))
             guard kaddr != 0 else {
                 return .fail("proc-cred: pid \(pid) not found in kernel allproc")
             }

             let procROOffsets:  [UInt64] = [0x18, 0x20, 0x28, 0x30]
             let ucredROOffsets: [UInt64] = [0x08, 0x10, 0x18, 0x20]
             let credBaseOffsets:[UInt64] = [0x18, 0x20]

             var bestProcRO: UInt64 = 0
             var bestUcred:  UInt64 = 0
             var bestBase:   UInt64 = 0x18
             var bestScore = -1

             for pro in procROOffsets {
                 let proc_ro = mgr.kread64(address: kaddr + pro)
                 guard proc_ro != 0 else { continue }
                 for uco in ucredROOffsets {
                     let ucred = mgr.kread64(address: proc_ro + uco)
                     guard ucred != 0 else { continue }
                     for cBase in credBaseOffsets {
                         let c_uid = mgr.kread32(address: ucred + cBase)
                         let c_gid = mgr.kread32(address: ucred + cBase + 0x0C)
                         let c_ng  = mgr.kread32(address: ucred + cBase + 0x18)
                         var score = 0
                         if c_uid  < 100_000 { score += 10 }
                         if c_gid  < 100_000 { score += 10 }
                         if c_ng <= 16       { score += 200 }
                         else if c_ng > 1000 { score -= 100 }
                         if score > bestScore {
                             bestScore = score; bestProcRO = proc_ro
                             bestUcred = ucred; bestBase = cBase
                         }
                     }
                 }
             }

             guard bestUcred != 0 else {
                 return .fail("proc-cred: could not locate valid ucred for pid \(pid)")
             }

             let ucred = bestUcred
             let b = bestBase
             let cr_uid   = mgr.kread32(address: ucred + b)
             let cr_ruid  = mgr.kread32(address: ucred + b + 0x04)
             let cr_svuid = mgr.kread32(address: ucred + b + 0x08)
             let cr_gid   = mgr.kread32(address: ucred + b + 0x0C)
             let cr_rgid  = mgr.kread32(address: ucred + b + 0x10)
             let cr_svgid = mgr.kread32(address: ucred + b + 0x14)

             return .ok("""
   pid   : \(pid)
   uid   : \(cr_uid) (effective)
   ruid  : \(cr_ruid) (real)
   svuid : \(cr_svuid) (saved)
   gid   : \(cr_gid) (effective)
   rgid  : \(cr_rgid) (real)
   svgid : \(cr_svgid) (saved)
   ucred : 0x\(String(format: "%016llx", ucred))
   layout: score=\(bestScore) (dynamic probe)
   [source: kernel ucred — iOS blocked proc_pidinfo]
 """)
         }

         OmegaCore.register("proc-entitlements") { arg, mgr in
            guard let pid = Int32(arg.trimmingCharacters(in: .whitespaces)) else {
                return .fail("proc-entitlements: usage: proc-entitlements <pid>")
            }

            // ── SURGICAL FIX: Get name from kernel (proc_name blocked on iOS 18 system procs)
            var name = ""
            if mgr.dsready && mgr.hasOffsets {
                let kaddr = procbypid(pid_t(pid))
                if kaddr != 0 {
                    for off: UInt64 in [0x268, 0x2d0, 0x56c] {
                        var buf = [UInt8](repeating: 0, count: 17)
                        ds_kreadbuf(kaddr + off, &buf, 16)
                        let s = String(bytes: buf.prefix(while: { $0 != 0 }), encoding: .utf8) ?? ""
                        if !s.isEmpty { name = s; break }
                    }
                }
            }
            if name.isEmpty {
                var nameBuf = [CChar](repeating: 0, count: 256)
                proc_name(pid, &nameBuf, 256)
                name = String(cString: nameBuf)
            }
            guard !name.isEmpty else {
                return .fail("proc-entitlements: no process with pid \(pid)")
            }

            // Try proc_pidpath first
            var pathBuf = [CChar](repeating: 0, count: Int(MAXPATHLEN))
            let pathLen = proc_pidpath(pid, &pathBuf, UInt32(MAXPATHLEN))

            if pathLen > 0 {
                let binPath = String(cString: pathBuf)
                let binData: Data? = (try? Data(contentsOf: URL(fileURLWithPath: binPath)))
                    ?? mgr.vfsread(path: binPath, maxSize: 8 * 1024 * 1024)
                if let data = binData, let range = findEntitlements(in: data) {
                    let entsData = data.subdata(in: range)
                    if let text = santanderfs.plisttext(data: entsData) ?? santanderfs.textdecode(data: entsData) {
                        return .ok("proc-entitlements: \(name) (\(pid)):\n\(binPath)\n\n\(text)")
                    }
                }
                return .ok("proc-entitlements: \(name) (\(pid))\nbinary: \(binPath)\n(no embedded entitlements — may use implicit entitlements)")
            }

            // ── Kernel fallback: csops CS_OPS_ENTITLEMENTS_BLOB ──
            var csBuf = [UInt8](repeating: 0, count: 65536)
            let csRet = csops(pid_t(pid), 7, &csBuf, 65536)
            if csRet == 0 {
                let data = Data(csBuf)
                if let text = santanderfs.plisttext(data: data) ?? santanderfs.textdecode(data: data) {
                    return .ok("proc-entitlements: \(name) (\(pid))\n[source: csops CS_OPS_ENTITLEMENTS_BLOB]\n\n\(text)")
                }
            }

            return .ok("proc-entitlements: \(name) (\(pid))\n(binary path not accessible — csops ret=\(csRet))")
        }

        OmegaCore.register("proc-open-files") { arg, _ in
            guard let pid = Int32(arg.trimmingCharacters(in: .whitespaces)) else {
                return .fail("proc-open-files: usage: proc-open-files <pid>")
            }
            var buf = [proc_fdinfo](repeating: proc_fdinfo(), count: 256)
            let n = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, &buf, Int32(MemoryLayout<proc_fdinfo>.size * 256))
            if n < 0 || (n == 0 && errno == EPERM) {
                var nb = [CChar](repeating: 0, count: 256)
                proc_name(pid, &nb, 256)
                let nm = String(cString: nb)
                return .ok("proc-open-files \(pid) [\(nm.isEmpty ? "unknown" : nm)]\n  iOS blocks PROC_PIDLISTFDS for system/daemon processes\n  (only accessible for processes owned by the current user)")
            }
            let count = Int(n) / MemoryLayout<proc_fdinfo>.size
            if count == 0 { return .ok("(no open file descriptors)") }
            var lines: [String] = ["  FD    TYPE"]
            for i in 0..<count {
                let fd = buf[i]
                let type_str: String
                switch fd.proc_fdtype {
                case PROX_FDTYPE_VNODE:  type_str = "vnode"
                case PROX_FDTYPE_SOCKET: type_str = "socket"
                case PROX_FDTYPE_PIPE:   type_str = "pipe"
                case PROX_FDTYPE_KQUEUE: type_str = "kqueue"
                default:                 type_str = "type:\(fd.proc_fdtype)"
                }
                lines.append("  \(fd.proc_fd)  \(type_str)")
            }
            return .ok(lines.joined(separator: "\n"))
        }

        OmegaCore.register("proc-mem-info") { arg, _ in
            guard let pid = Int32(arg.trimmingCharacters(in: .whitespaces)) else {
                return .fail("proc-mem-info: usage: proc-mem-info <pid>")
            }
            var info = proc_taskinfo()
            let r = proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &info, Int32(MemoryLayout<proc_taskinfo>.size))
            guard r > 0 else {
                var nb = [CChar](repeating: 0, count: 256)
                proc_name(pid, &nb, 256)
                let nm = String(cString: nb)
                var pb = [CChar](repeating: 0, count: Int(MAXPATHLEN))
                let pl = proc_pidpath(pid, &pb, UInt32(MAXPATHLEN))
                let bin = pl > 0 ? String(cString: pb) : "(path restricted)"
                return .ok("""
  proc-mem-info \(pid) [\(nm.isEmpty ? "unknown" : nm)]
  iOS restricts PROC_PIDTASKINFO for system/daemon processes.
  binary  : \(bin)
  hint    : try 'memory-info' for device-wide stats or 'kread' for raw kernel reads.
""")
            }
            return .ok("""
  pid             : \(pid)
  virtual_size    : \(formatBytes(Int(info.pti_virtual_size)))
  resident_size   : \(formatBytes(Int(info.pti_resident_size)))
  user_time       : \(info.pti_total_user) ns
  system_time     : \(info.pti_total_system) ns
  threads_count   : \(info.pti_threadnum)
  faults          : \(info.pti_faults)
  pageins         : \(info.pti_pageins)
  cow_faults      : \(info.pti_cow_faults)
""")
        }

        // proc-access — iOS restriction report (system limitation indicator)
        OmegaCore.register("proc-access") { _, _ in
            let meta  = ProcessLayer.shared.listAllWithMeta()
            let total = meta.entries.count
            let full  = meta.fullCount
            let part  = meta.partialCount
            let blk   = meta.blockedCount
            let rf    = meta.readFailCount
            let pct   = meta.completenessPercent
            let pf    = total > 0 ? "\(full * 100 / total)%" : "n/a"
            let pp    = total > 0 ? "\(part * 100 / total)%" : "n/a"
            let pb    = total > 0 ? "\(blk  * 100 / total)%" : "n/a"
            let pr    = total > 0 ? "\(rf   * 100 / total)%" : "n/a"
            let osVer = UIDevice.current.systemVersion
            let src   = meta.primarySource + (meta.fallbackUsed ? " (fallback)" : "")
            let lines: [String] = [
                "  iOS Access Report",
                "  " + String(repeating: "-", count: 40),
                _col([16, 24], ["source",       src]),
                _col([16, 24], ["total procs",  String(total)]),
                "  " + String(repeating: "-", count: 40),
                _col([16, 6, 5, 100], ["FULL",    String(full),  pf,  "proc_pidinfo succeeded"]),
                _col([16, 6, 5, 100], ["PARTIAL", String(part),  pp,  "kernel name ok; bsdinfo partial"]),
                _col([16, 6, 5, 100], ["BLOCKED", String(blk),   pb,  "iOS restriction (EPERM/EACCES)"]),
                _col([16, 6, 5, 100], ["RFAIL",   String(rf),    pr,  "kernel+bsdinfo both failed"]),
                "  " + String(repeating: "-", count: 40),
                _col([16, 24], ["iOS-access",   "\(pct)% complete"]),
                _col([16, 24], ["iOS version",  osVer]),
                _col([16, 24], ["exploit",      AppContext.shared.mgr.dsready ? "active" : "inactive"]),
                "  " + String(repeating: "-", count: 40),
                "  note: BLOCKED = iOS prevents proc_pidinfo (expected behavior).",
                "        Names are still read from kernel allproc (kernel access ok).",
            ]
            return .ok(lines.joined(separator: "\n"))
        }
    }

    // MARK: - App Control

    private static func registerAppControl() {
        OmegaCore.register("app-kill") { arg, mgr in
            let bid = arg.trimmingCharacters(in: .whitespaces)
            guard !bid.isEmpty else { return .fail("app-kill: usage: app-kill <bundleId>") }
            guard let pid = findPidByBundleId(bid, mgr: mgr) else {
                return .fail("app-kill: '\(bid)' is not running")
            }
            let r = kill(pid, SIGKILL)
            return r == 0 ? .ok("killed \(bid) (pid \(pid))") : .fail("app-kill: \(String(cString: strerror(errno)))")
        }

        OmegaCore.register("app-pid") { arg, mgr in
            let bid = arg.trimmingCharacters(in: .whitespaces)
            guard !bid.isEmpty else { return .fail("app-pid: usage: app-pid <bundleId>") }
            guard let pid = findPidByBundleId(bid, mgr: mgr) else {
                return .ok("\(bid): not running")
            }
            return .ok("\(bid): pid \(pid)")
        }

        OmegaCore.register("app-sandbox-escape") { arg, mgr in
            guard mgr.dsready else { return .fail("app-sandbox-escape: exploit not ready") }
            let bid = arg.trimmingCharacters(in: .whitespaces)
            guard !bid.isEmpty else { return .fail("app-sandbox-escape: usage: app-sandbox-escape <bundleId>") }
            guard let pid = findPidByBundleId(bid, mgr: mgr) else {
                return .fail("app-sandbox-escape: '\(bid)' is not running")
            }
            let procPtr = findKernelProc(pid: pid, mgr: mgr)
            guard procPtr != 0 else {
                return .fail("app-sandbox-escape: could not find kernel proc for pid \(pid)")
            }
            let r = sbx_escape(procPtr)
            return r == 0
                ? .ok("[OK] sandbox escaped for \(bid) (pid \(pid))")
                : .fail("app-sandbox-escape: sbx_escape returned \(r)")
        }

        OmegaCore.register("app-csflags") { arg, mgr in
            guard mgr.dsready else { return .fail("app-csflags: exploit not ready") }
            let bid = arg.trimmingCharacters(in: .whitespaces)
            guard !bid.isEmpty else { return .fail("app-csflags: usage: app-csflags <bundleId>") }
            guard let pid = findPidByBundleId(bid, mgr: mgr) else {
                return .fail("app-csflags: '\(bid)' is not running")
            }
            let flags = readCSFlags(pid: pid, mgr: mgr)
            return .ok(String(format: "%@ (pid %d)  cs_flags = 0x%08x  [%@]", bid, pid, flags, describeCSFlags(flags)))
        }

        OmegaCore.register("app-csflags-set") { arg, mgr in
            guard mgr.dsready else { return .fail("app-csflags-set: exploit not ready") }
            let parts = arg.split(separator: " ").map { String($0) }
            guard parts.count == 2, let flags = parseAddr(parts[1]) else {
                return .fail("app-csflags-set: usage: app-csflags-set <bundleId> <hex_flags>\nhint: 0x2600 = CS_VALID|CS_ADHOC|CS_GET_TASK_ALLOW (debuggable)")
            }
            let bid = parts[0]
            guard let pid = findPidByBundleId(bid, mgr: mgr) else {
                return .fail("app-csflags-set: '\(bid)' is not running")
            }
            let ok = writeCSFlags(pid: pid, flags: UInt32(flags & 0xFFFFFFFF), mgr: mgr)
            return ok
                ? .ok(String(format: "[OK] set cs_flags = 0x%08x on %@ (pid %d)", UInt32(flags), bid, pid))
                : .fail("app-csflags-set: failed to write flags")
        }
    }

    // MARK: - System Info

    private static func registerSystemInfo() {
        OmegaCore.register("device-info") { _, _ in
            let d = UIDevice.current
            var machine = ""; var size = 0
            sysctlbyname("hw.machine", nil, &size, nil, 0)
            if size > 0 { var buf = [CChar](repeating: 0, count: size); sysctlbyname("hw.machine", &buf, &size, nil, 0); machine = String(cString: buf) }
            var model = ""; size = 0
            sysctlbyname("hw.model", nil, &size, nil, 0)
            if size > 0 { var buf = [CChar](repeating: 0, count: size); sysctlbyname("hw.model", &buf, &size, nil, 0); model = String(cString: buf) }
            var ncpu: Int32 = 0; var ncpuSize = MemoryLayout<Int32>.size
            sysctlbyname("hw.ncpu", &ncpu, &ncpuSize, nil, 0)
            var memSize: UInt64 = 0; var memSz = MemoryLayout<UInt64>.size
            sysctlbyname("hw.memsize", &memSize, &memSz, nil, 0)
            return .ok("""
  name          : \(d.name)
  model         : \(d.model)
  system        : \(d.systemName) \(d.systemVersion)
  hw.machine    : \(machine)
  hw.model      : \(model)
  cpu_count     : \(ncpu)
  memory        : \(formatBytes(Int(memSize)))
  screen        : \(Int(UIScreen.main.bounds.width * UIScreen.main.scale))x\(Int(UIScreen.main.bounds.height * UIScreen.main.scale)) @\(Int(UIScreen.main.scale))x
  bundle_id     : \(Bundle.main.bundleIdentifier ?? "(unknown)")
  executable    : \(Bundle.main.executablePath ?? "(unknown)")
""")
        }

        OmegaCore.register("memory-info") { _, _ in
            var vmStats = vm_statistics64()
            var count = mach_msg_type_number_t(MemoryLayout<vm_statistics64>.size / MemoryLayout<integer_t>.size)
            withUnsafeMutablePointer(to: &vmStats) { ptr in
                ptr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { buf in
                    _ = host_statistics64(mach_host_self(), HOST_VM_INFO64, buf, &count)
                }
            }
            let pageSize = Int64(vm_page_size)
            let free     = Int64(vmStats.free_count)     * pageSize
            let active   = Int64(vmStats.active_count)   * pageSize
            let inactive = Int64(vmStats.inactive_count) * pageSize
            let wired    = Int64(vmStats.wire_count)      * pageSize
            let compressed = Int64(vmStats.compressor_page_count) * pageSize
            return .ok("""
  free        : \(formatBytes(free))
  active      : \(formatBytes(active))
  inactive    : \(formatBytes(inactive))
  wired       : \(formatBytes(wired))
  compressed  : \(formatBytes(compressed))
  page_size   : \(pageSize) bytes
  page_faults : \(vmStats.faults)
  pageins     : \(vmStats.pageins)
  pageouts    : \(vmStats.pageouts)
""")
        }

        OmegaCore.register("disk-info") { _, _ in
            let attrs = try? FileManager.default.attributesOfFileSystem(forPath: "/private/var")
            let total = attrs?[.systemSize] as? Int64 ?? 0
            let free  = attrs?[.systemFreeSize] as? Int64 ?? 0
            let used  = total - free
            let pct   = total > 0 ? Int(Double(used) / Double(total) * 100) : 0
            return .ok("""
  /private/var
  total : \(formatBytes(total))
  used  : \(formatBytes(used))  (\(pct)%)
  free  : \(formatBytes(free))
""")
        }

        OmegaCore.register("boot-args") { _, _ in
            let nvram_path = "/dev/nvram"
            if let data = try? Data(contentsOf: URL(fileURLWithPath: nvram_path)) {
                return .ok("nvram raw: \(data.count) bytes\n(parse with 'plist /dev/nvram')")
            }
            var buf = [CChar](repeating: 0, count: 4096)
            var size = 4096
            if sysctlbyname("kern.bootargs", &buf, &size, nil, 0) == 0 {
                return .ok("kern.bootargs = \(String(cString: buf))")
            }
            return .ok("boot-args: not accessible from user space on this device")
        }

        OmegaCore.register("bundle-id") { _, _ in
            return .ok(Bundle.main.bundleIdentifier ?? "(none)")
        }

        OmegaCore.register("jb-status") { _, mgr in
            return .ok("""
  ── DarkSword ───────────────────────────
  ds_running    : \(mgr.dsrunning)
  ds_ready      : \(mgr.dsready)
  ds_failed     : \(mgr.dsfailed)
  kernel_base   : \(mgr.dsready ? String(format: "0x%016llx", mgr.kernbase) : "(not ready)")
  kernel_slide  : \(mgr.dsready ? String(format: "0x%016llx", mgr.kernslide) : "(not ready)")

  ── VFS ─────────────────────────────────
  vfs_ready     : \(mgr.vfsready)
  vfs_attempted : \(mgr.vfsattempted)
  vfs_failed    : \(mgr.vfsfailed)

  ── Sandbox ─────────────────────────────
  sbx_ready     : \(mgr.sbxready)
  sbx_attempted : \(mgr.sbxattempted)
  sbx_failed    : \(mgr.sbxfailed)

  ── RemoteCall ──────────────────────────
  rc_ready      : \(mgr.rcready)
  rc_failed     : \(mgr.rcfailed)

  ── Offsets ─────────────────────────────
  has_offsets   : \(mgr.hasOffsets)
""")
        }

    }

    // MARK: - Lara

    private static func registerLara() {
        OmegaCore.register("status") { _, mgr in
            return .ok("""
  ds_ready  : \(mgr.dsready)
  vfs_ready : \(mgr.vfsready)
  sbx_ready : \(mgr.sbxready)
  rc_ready  : \(mgr.rcready)
  offsets   : \(mgr.hasOffsets)
""")
        }

        OmegaCore.register("run") { _, mgr in
            guard !mgr.dsready else { return .ok("exploit already running") }
            guard !mgr.dsrunning else { return .ok("exploit in progress...") }
            offsets_init()
            mgr.run()
            return .ok("exploit triggered — watch logs for progress")
        }

        OmegaCore.register("vfs") { _, mgr in
            guard mgr.dsready else { return .fail("vfs: exploit not ready — run 'run' first") }
            guard !mgr.vfsready else { return .ok("VFS already initialized") }
            mgr.vfsinit()
            return .ok("VFS init triggered — watch logs for progress")
        }

        OmegaCore.register("sbx") { _, mgr in
            guard mgr.dsready else { return .fail("sbx: exploit not ready — run 'run' first") }
            guard !mgr.sbxready else { return .ok("sandbox already escaped") }
            mgr.sbxescape()
            return .ok("sandbox escape triggered — watch logs for progress")
        }

        OmegaCore.register("rc") { _, mgr in
            guard mgr.dsready else { return .fail("rc: exploit not ready") }
            guard !mgr.rcready else { return .ok("RemoteCall already initialized") }
            mgr.rcinit(process: "SpringBoard", migbypass: false)
            return .ok("RemoteCall init triggered on SpringBoard")
        }

        OmegaCore.register("respring") { _, mgr in
            DispatchQueue.main.async { mgr.showrespring = true }
            return .ok("respringing...")
        }

        OmegaCore.register("logs") { _, mgr in
            let log = mgr.log.trimmingCharacters(in: .whitespacesAndNewlines)
            return .ok(log.isEmpty ? "(no logs)" : log)
        }

        OmegaCore.register("clear-logs") { _, mgr in
            DispatchQueue.main.async { mgr.log = "" }
            return .ok("logs cleared")
        }
        OmegaCore.register("cmdlog") { arg, _ in
            let n = Int(arg.trimmingCharacters(in: .whitespaces)) ?? 50
            return .ok(CommandLogger.shared.dump(last: n))
        }

        OmegaCore.register("cmdlog-clear") { _, _ in
            CommandLogger.shared.clear()
            return .ok("command log cleared")
        }


    }
}

// MARK: - Kernel proc/csflags helpers

private func findKernelProc(pid: pid_t, mgr: laramgr) -> UInt64 {
    guard mgr.dsready else { return 0 }
    // Require loaded offsets — same consistency guard used in proc-cred.
    guard mgr.hasOffsets else { return 0 }
    let nextOff = UInt64(off_proc_p_list_le_next)
    let pidOff  = UInt64(off_proc_p_pid)
    var proc_ptr = ds_get_our_proc()
    var seen = Set<UInt64>()
    for _ in 0..<512 {
        guard proc_ptr != 0, !seen.contains(proc_ptr) else { break }
        seen.insert(proc_ptr)
        let kpid = Int32(bitPattern: mgr.kread32(address: proc_ptr + pidOff))
        if kpid == pid { return proc_ptr }
        proc_ptr = mgr.kread64(address: proc_ptr + nextOff)
    }
    return 0
}

private func readCSFlags(pid: Int32, mgr: laramgr) -> UInt32 {
    let proc_ptr = findKernelProc(pid: pid, mgr: mgr)
    guard proc_ptr != 0 else { return 0 }
    // Probe multiple known p_csflags offsets — same multi-offset strategy used in proc-info
    // (OmegaExtendedE). iOS 16→18 layouts: 0x2c4, 0x2e0, 0x300.
    // Accept the first non-zero read across all candidates.
    for off: UInt64 in [0x300, 0x2c4, 0x2e0] {
        let v = mgr.kread32(address: proc_ptr + off)
        if v != 0 { return v }
    }
    return 0
}

private func writeCSFlags(pid: Int32, flags: UInt32, mgr: laramgr) -> Bool {
    let proc_ptr = findKernelProc(pid: pid, mgr: mgr)
    guard proc_ptr != 0 else { return false }
    // Write to the same offset that a non-zero read was found on.
    for off: UInt64 in [0x300, 0x2c4, 0x2e0] {
        let cur = mgr.kread32(address: proc_ptr + off)
        if cur != 0 || off == 0x300 {
            mgr.kwrite32(address: proc_ptr + off, value: flags)
            return true
        }
    }
    return false
}

private func describeCSFlags(_ flags: UInt32) -> String {
    var parts: [String] = []
    let map: [(UInt32, String)] = [
        (0x0001, "CS_VALID"),
        (0x0002, "CS_ADHOC"),
        (0x0004, "CS_GET_TASK_ALLOW"),
        (0x0008, "CS_INSTALLER"),
        (0x0010, "CS_FORCED_LV"),
        (0x0020, "CS_INVALID_ALLOWED"),
        (0x0040, "CS_HARD"),
        (0x0080, "CS_KILL"),
        (0x0100, "CS_CHECK_EXPIRATION"),
        (0x0200, "CS_RESTRICT"),
        (0x0400, "CS_ENFORCEMENT"),
        (0x0800, "CS_REQUIRE_LV"),
        (0x1000, "CS_ENTITLEMENTS_VALIDATED"),
        (0x2000, "CS_NO_UNTRUSTED_HELPERS"),
        (0x4000, "CS_ALLOWED_MACHO"),
        (0x10000, "CS_EXEC_SET_HARD"),
        (0x20000, "CS_EXEC_SET_KILL"),
        (0x40000, "CS_EXEC_SET_ENFORCEMENT"),
        (0x80000, "CS_EXEC_INHERIT_SIP"),
        (0x100000, "CS_KILLED"),
        (0x200000, "CS_DYLD_PLATFORM"),
        (0x400000, "CS_PLATFORM_BINARY"),
        (0x800000, "CS_PLATFORM_PATH"),
        (0x1000000, "CS_DEBUGGED"),
        (0x2000000, "CS_SIGNED"),
        (0x4000000, "CS_DEV_CODE"),
        (0x10000000, "CS_DATAVAULT_CONTROLLER"),
    ]
    for (bit, name) in map {
        if (flags & bit) != 0 { parts.append(name) }
    }
    return parts.isEmpty ? "none" : parts.joined(separator: "|")
}

private func findEntitlements(in data: Data) -> Range<Int>? {
    let magic = Data([0xFA, 0xDE, 0x71, 0x71])
    guard let magicRange = data.range(of: magic) else { return nil }
    let start = magicRange.lowerBound
    guard start + 8 <= data.count else { return nil }
    let length = Int(data[start+4]) << 24 | Int(data[start+5]) << 16 |
                 Int(data[start+6]) << 8  | Int(data[start+7])
    guard length > 8, start + length <= data.count else { return nil }
    return (start + 8)..<(start + length)
}

