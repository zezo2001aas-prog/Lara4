//
//  lara.swift
//  lara
//
//  Created by ruter on 23.03.26.
//

import SwiftUI
import UniformTypeIdentifiers

enum taboptions {
    case applying, tweaks, files, logs
}

let g_isunsupported: Bool = isunsupported()
var weonadebugbuild_pjbweouttahereexclamationmark: Bool = false

@main
struct lara: App {
    @StateObject private var mgr = laramgr.shared
    @StateObject private var iconthememgr = IconThemeManager.shared
    @State private var healthCheckTimer: Timer? = nil
    @Environment(\.scenePhase) var scenephase
    @AppStorage("selectedMethod") private var selectedMethod: method = .hybrid
    @AppStorage("keepAlive") private var keepalive: Bool = false
    @AppStorage("showFMInTabs") private var showfmintabs: Bool = true
    @AppStorage("logsdisplaymode") private var logsdisplaymode: logsdisplaymode = .toolbar
    @State private var selectedtab: taboptions = .applying
    
    init() {
        #if DEBUG
        weonadebugbuild_pjbweouttahereexclamationmark = true
        #endif
        
        // fix file picker
        let fixMethod = class_getInstanceMethod(UIDocumentPickerViewController.self, #selector(UIDocumentPickerViewController.fix_init(forOpeningContentTypes:asCopy:)))!
        let origMethod = class_getInstanceMethod(UIDocumentPickerViewController.self, #selector(UIDocumentPickerViewController.init(forOpeningContentTypes:asCopy:)))!
        method_exchangeImplementations(origMethod, fixMethod)
        
        if keepalive {
            toggleka()
        }
        
        globallogger.capture()
    }
    
    var body: some Scene {
        WindowGroup {
            TabView(selection: $selectedtab) {
                ContentView()
                    .tabItem {
                        Image(systemName: "wrench.and.screwdriver.fill")
                    }
                    .tag(taboptions.applying)
                
                // this has gotta fucking go
                TweaksView(mgr: mgr)
                    .tabItem {
                        Image(systemName: "ant.fill")
                    }
                    .tag(taboptions.tweaks)
                
                
                // i'm gonna strangle you root (the weight of your actions will crush you)
                if showfmintabs {
                    SantanderView(startPath: "/")
                        .tabItem {
                            Image(systemName: "folder.fill")
                        }
                        .tag(taboptions.files)
                }
                
                // this too
                if logsdisplaymode == .tabs {
                    LogsView(logger: globallogger)
                        .tabItem {
                            Image(systemName: "terminal")
                        }
                        .tag(taboptions.logs)
                }
            }
            .environmentObject(mgr)
            .overlay {
                if mgr.showrespring {
                    respringview()
                        .brightness(-1.0)
                        .ignoresSafeArea()
                }
            }
            .sheet(isPresented: Binding(
                get: { logsdisplaymode == .toolbar && mgr.showLogs },
                set: { mgr.showLogs = $0 }
            )) {
                LogsView(logger: globallogger)
            }
            .sheet(isPresented: $iconthememgr.showFixupSheet) {
                IconThemeFixupView()
            }
            .onAppear {
                startHealthCheckTimer()
                if !isunsupported() {
                    init_offsets()
                    offsets_init()
                    iconthememgr.startPendingFixupIfPossible()
                    // beautiful name root
                    // thanks
                    mgr.hasOffsets = emergencyfixfunctiontobereplacedlateronquestionmark()
                } else {
                    Alertinator.shared.alert(title: "This device is not supported!", body: "We apologize, but this device is currently not supported by Lara. Possible reasons: \n- You are on an unsupported iOS version (Supported: iOS 16.0 - iOS 18.7.1, iOS 26.0 - iOS 26.0.1) \n- Your device has MIE (A19+ or M5+) \n- A debugger is attached.", actionLabel: "Exit App", action: { exitinator() })
                }
            }
            .onChange(of: scenephase, perform: handleScenePhase)
            
              .onChange(of: mgr.dsready) { ready in
                  if ready {
                      startHealthCheckTimer()
                  } else {
                      stopHealthCheckTimer()
                  }
              }
              .onChange(of: mgr.sbxready) { ready in
                  if ready {
                      iconthememgr.startPendingFixupIfPossible()
                  }
              }
        }
    }
    
    private func handleScenePhase(_ phase: ScenePhase) {
        switch phase {
        case .inactive, .background:
            handlebg()
            globallogger.stopcapture()
            stopHealthCheckTimer()
            // FIX 6: Tell laramgr to stop its health timer — prevents socket()
            // syscalls from a suspended process (→ g_socket_broken=1 → session dead).
            mgr.handleEnterBackground()

        case .active:
            globallogger.capture()
            iconthememgr.startPendingFixupIfPossible()
            startHealthCheckTimer()
            // FIX 6: Notify laramgr — restarts health timer and warns user
            // if KRW session was lost while suspended.
            mgr.handleEnterForeground()

        @unknown default:
            break
        }
    }

    // MARK: ── Session Health Check Timer ─────────────────────────────────────
    // Periodic health check every 30 seconds to catch degradation early

    private func startHealthCheckTimer() {
        stopHealthCheckTimer()
        healthCheckTimer = Timer.scheduledTimer(withTimeInterval: 30.0, repeats: true) { _ in
            guard laramgr.shared.dsready else { return }
            let health = ds_session_health_score()
            if health < 50 && health > 0 {
                laramgr.shared.logmsg("(health) KRW health low: \(health)/100 — attempting auto-revive")
                let revived = laramgr.shared.reviveKRW()
                if !revived {
                    laramgr.shared.logmsg("(health) auto-revive failed — session needs manual re-exploit")
                }
            }
        }
    }

    private func stopHealthCheckTimer() {
        healthCheckTimer?.invalidate()
        healthCheckTimer = nil
    }

    private func handlebg() {
        guard mgr.rcready else { return }

        // FIX: do NOT tear down the RemoteCall session merely because the app
        // went to background. SpringBoard keeps running, so the hijacked thread
        // stays valid — destroying it here is what killed long shell sessions
        // ("destroying remote call session..." right after a screen lock / app
        // switch). Keep it alive by default; only tear down if the user opts in.
        // To restore the old eager-cleanup behavior, set the
        // "destroyRemoteCallOnBackground" default to true.
        let destroyOnBackground = UserDefaults.standard.bool(forKey: "destroyRemoteCallOnBackground")
        if !destroyOnBackground {
            return   // keep the session alive across background/foreground
        }

        var bgTask: UIBackgroundTaskIdentifier = .invalid

        bgTask = UIApplication.shared.beginBackgroundTask(withName: "RemoteCallCleanup") {
            endbgtask(&bgTask)
        }

        mgr.rcdestroy {
            self.endbgtask(&bgTask)
        }
    }

    private func endbgtask(_ task: inout UIBackgroundTaskIdentifier) {
        guard task != .invalid else { return }
        UIApplication.shared.endBackgroundTask(task)
        task = .invalid
    }
}

// file picker fixes
extension UIDocumentPickerViewController {
    @objc func fix_init(forOpeningContentTypes contentTypes: [UTType], asCopy: Bool) -> UIDocumentPickerViewController {
        return fix_init(forOpeningContentTypes: contentTypes, asCopy: true)
    }
}

// make strings compatible with errors
#if swift(>=6.0)
extension String: @retroactive Error {}
#else
extension String: Error {}
#endif
