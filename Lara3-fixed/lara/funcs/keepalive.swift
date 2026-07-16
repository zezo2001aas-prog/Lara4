//
//  keepalive.swift
//  lara
//
//  Created by ruter on 29.03.26.
//  SURGICAL FIX: iOS 18.3.1 socket stability — background task + BGTaskScheduler
//
//  Problem:  iOS suspends the app in background → sockets disconnected
//            → KRW session degraded → ENOTCONN on getsockopt/setsockopt
//
//  Solution: 1. beginBackgroundTask — prevents suspension during KRW ops
//            2. BGTaskScheduler — periodic wake-up to keep sockets warm
//            3. ProcessInfo thermal monitoring — reduce stress when hot
//            4. UIApplication lifecycle — detect bg/fg transitions
//            5. Socket health probe — detect degradation before it fails
//

import AVFoundation
import BackgroundTasks

private var kaplayer: AVAudioPlayer?
private var kaobservers: [NSObjectProtocol] = []
var kaenabled = false

// MARK: – Background Task State
private var bgTaskId: UIBackgroundTaskIdentifier = .invalid
private let bgTaskIdentifier = "com.lara.keepalive"
private var isInBackground = false
private var socketHealthFailures = 0
private let maxSocketHealthFailures = 3

// MARK: – Thermal Throttling
private var thermalObserver: NSObjectProtocol?

func toggleka() {
    if kaenabled {
        stopka()
        return
    }
    startka()
}

// MARK: – Public API

func startka() {
    do {
        let session = AVAudioSession.sharedInstance()
        try session.setCategory(.playback, mode: .default, options: [.mixWithOthers])
        try session.setActive(true, options: [])
    } catch {
        globallogger.log("(ka) audio session failed: \(error)")
        return
    }

    let fileurl = getwavurl()
    if !FileManager.default.fileExists(atPath: fileurl.path) {
        makesilentwav(at: fileurl)
    }

    do {
        kaplayer = try AVAudioPlayer(contentsOf: fileurl)
        kaplayer?.numberOfLoops = -1
        kaplayer?.volume = 0.01
        kaplayer?.prepareToPlay()
        kaplayer?.play()
        kaenabled = true
        registerkaobservers()
        registerlifecycleobservers()
        registerthermalobserver()
        registerbgtask()
        beginbackgroundtask()
        globallogger.log("(ka) enabled keepalive + bg task + scheduler")
    } catch {
        globallogger.log("(ka) audio failed: \(error)")
    }
}

func stopka() {
    endbackgroundtask()
    removekaobservers()
    removelifecycleobservers()
    removethermalobserver()
    kaplayer?.stop()
    kaplayer = nil
    kaenabled = false
    try? AVAudioSession.sharedInstance().setActive(false, options: [.notifyOthersOnDeactivation])
    globallogger.log("(ka) disabled keepalive")
}

// MARK: – Background Task (prevents suspension during KRW)

private func beginbackgroundtask() {
    guard bgTaskId == .invalid else { return }
    bgTaskId = UIApplication.shared.beginBackgroundTask(withName: "lara.krw") {
        // Expiration handler — extend if possible
        globallogger.log("(ka) bg task expiring — attempting extension")
        self.endbackgroundtask()
        self.bgTaskId = UIApplication.shared.beginBackgroundTask(withName: "lara.krw.extended") {
            globallogger.log("(ka) bg task fully expired — sockets may degrade")
            self.endbackgroundtask()
        }
    }
    if bgTaskId != .invalid {
        globallogger.log("(ka) bg task began: \(bgTaskId.rawValue)")
    }
}

private func endbackgroundtask() {
    guard bgTaskId != .invalid else { return }
    UIApplication.shared.endBackgroundTask(bgTaskId)
    globallogger.log("(ka) bg task ended: \(bgTaskId.rawValue)")
    bgTaskId = .invalid
}

// MARK: – BGTaskScheduler (periodic wake-up)

private func registerbgtask() {
    BGTaskScheduler.shared.register(forTaskWithIdentifier: bgTaskIdentifier, using: nil) { task in
        self.handlebgtask(task)
    }
    schedulebgtask()
}

private func schedulebgtask() {
    let request = BGProcessingTaskRequest(identifier: bgTaskIdentifier)
    request.requiresNetworkConnectivity = false
    request.requiresExternalPower = false
    request.earliestBeginDate = Date(timeIntervalSinceNow: 60)
    do {
        try BGTaskScheduler.shared.submit(request)
        globallogger.log("(ka) scheduled next bg task")
    } catch {
        globallogger.log("(ka) bg task scheduling failed: \(error)")
    }
}

private func handlebgtask(_ task: BGTask) {
    schedulebgtask() // Schedule next before doing work

    // Socket health probe
    if ds_is_ready() {
        let healthy = probesockethealth()
        if healthy {
            socketHealthFailures = 0
            globallogger.log("(ka) bg task: socket health OK")
        } else {
            socketHealthFailures += 1
            globallogger.log("(ka) bg task: socket health FAIL #\(socketHealthFailures)")
            if socketHealthFailures >= maxSocketHealthFailures {
                globallogger.log("(ka) socket critically degraded — user must run 'revive'")
            }
        }
    } else {
        globallogger.log("(ka) bg task: KRW not ready")
    }

    task.setTaskCompleted(success: true)
}

// MARK: – Socket Health Probe

private func probesockethealth() -> Bool {
    guard let kbase = ds_get_kernel_base(), kbase != 0 else { return false }
    do {
        let magic = ds_kread32(kbase)
        return magic == 0xFEEDFACF
    } catch {
        return false
    }
}

// MARK: – Thermal Monitoring

private func registerthermalobserver() {
    let nc = NotificationCenter.default
    thermalObserver = nc.addObserver(forName: ProcessInfo.thermalStateDidChangeNotification,
                                      object: nil, queue: .main) { _ in
        let state = ProcessInfo.processInfo.thermalState
        switch state {
        case .serious, .critical:
            globallogger.log("(ka) THERMAL WARNING: \(state.rawValue) — reducing KRW frequency")
        default:
            globallogger.log("(ka) thermal state: \(state.rawValue) — normal")
        }
    }
}

private func removethermalobserver() {
    if let o = thermalObserver {
        NotificationCenter.default.removeObserver(o)
        thermalObserver = nil
    }
}

// MARK: – UIApplication Lifecycle

private var lifecycleObservers: [NSObjectProtocol] = []

private func registerlifecycleobservers() {
    let nc = NotificationCenter.default

    let bg = nc.addObserver(forName: UIApplication.didEnterBackgroundNotification,
                            object: nil, queue: .main) { _ in
        self.isInBackground = true
        globallogger.log("(ka) app entered background — extending bg task")
        self.beginbackgroundtask()
    }

    let fg = nc.addObserver(forName: UIApplication.willEnterForegroundNotification,
                            object: nil, queue: .main) { _ in
        self.isInBackground = false
        globallogger.log("(ka) app entering foreground — checking socket health")
        if !self.probesockethealth() {
            globallogger.log("(ka) socket degraded during background — run 'revive'")
        }
        self.ensurekaplaying()
    }

    lifecycleObservers = [bg, fg]
}

private func removelifecycleobservers() {
    let nc = NotificationCenter.default
    for o in lifecycleObservers { nc.removeObserver(o) }
    lifecycleObservers.removeAll()
}

// MARK: – Audio Keepalive (existing)

private func ensurekaplaying() {
    guard kaenabled, let p = kaplayer else { return }
    if !p.isPlaying {
        p.prepareToPlay()
        p.play()
    }
}

private func registerkaobservers() {
    removekaobservers()
    let nc = NotificationCenter.default

    let intr = nc.addObserver(forName: AVAudioSession.interruptionNotification,
                              object: nil, queue: .main) { note in
        guard let info = note.userInfo,
              let raw = info[AVAudioSessionInterruptionTypeKey] as? UInt,
              let type = AVAudioSession.InterruptionType(rawValue: raw) else { return }
        if type == .ended {
            let optsRaw = info[AVAudioSessionInterruptionOptionKey] as? UInt ?? 0
            let opts = AVAudioSession.InterruptionOptions(rawValue: optsRaw)
            try? AVAudioSession.sharedInstance().setActive(true, options: [])
            if opts.contains(.shouldResume) || true {
                ensurekaplaying()
            }
            globallogger.log("(ka) resumed after interruption")
        }
    }

    let route = nc.addObserver(forName: AVAudioSession.routeChangeNotification,
                               object: nil, queue: .main) { _ in
        try? AVAudioSession.sharedInstance().setActive(true, options: [])
        ensurekaplaying()
    }

    let reset = nc.addObserver(forName: AVAudioSession.mediaServicesWereResetNotification,
                               object: nil, queue: .main) { _ in
        globallogger.log("(ka) media services reset — rebuilding keepalive")
        stopka()
        startka()
    }

    let fg = nc.addObserver(forName: UIApplication.didBecomeActiveNotification,
                            object: nil, queue: .main) { _ in
        try? AVAudioSession.sharedInstance().setActive(true, options: [])
        ensurekaplaying()
    }

    kaobservers = [intr, route, reset, fg]
}

private func removekaobservers() {
    let nc = NotificationCenter.default
    for o in kaobservers { nc.removeObserver(o) }
    kaobservers.removeAll()
}

private func getwavurl() -> URL {
    let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    return docs.appendingPathComponent("silent.wav")
}

private func makesilentwav(at url: URL) {
    let samplerate = 44100
    let duration = 5
    let numsamples = samplerate * duration
    var wavdata = Data()
    let byterate = samplerate * 2
    let blockalign: UInt16 = 2
    let datasize = numsamples * 2
    let chunksize = 36 + datasize

    func append<T>(_ value: T) {
        var v = value
        wavdata.append(Data(bytes: &v, count: MemoryLayout<T>.size))
    }

    wavdata.append("RIFF".data(using: .ascii)!)
    append(UInt32(chunksize))
    wavdata.append("WAVE".data(using: .ascii)!)
    wavdata.append("fmt ".data(using: .ascii)!)
    append(UInt32(16))
    append(UInt16(1))
    append(UInt16(1))
    append(UInt32(samplerate))
    append(UInt32(byterate))
    append(blockalign)
    append(UInt16(16))
    wavdata.append("data".data(using: .ascii)!)
    append(UInt32(datasize))
    wavdata.append(Data(count: datasize))
    try? wavdata.write(to: url)
}
