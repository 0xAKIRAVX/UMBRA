import SwiftUI

struct ScanView: View {
    @EnvironmentObject private var settings: SettingsStore
    @EnvironmentObject private var controller: ScanController
    @Environment(\.str) private var str

    @State private var params = ScanParams()
    @State private var customCidrText = ""
    @State private var loaded = false

    var body: some View {
        ZStack {
            UmbraTheme.bg.ignoresSafeArea()
            ScrollView {
                VStack(spacing: 14) {
                    if let crash = CrashGuard.pendingReason {
                        crashBanner(crash)
                    }
                    header
                    configPanel
                    actionButton
                    if controller.isRunning || controller.uiState.isDone {
                        statsGrid
                    }
                    if controller.isRunning {
                        liveEndpoints
                    }
                    if case .done(let summary) = controller.uiState {
                        donePanel(summary)
                    }
                    console
                }
                .padding(.horizontal, 16)
                .padding(.bottom, 24)
            }
        }
        .onAppear {
            if !loaded {
                loaded = true
                params = settings.loadParams()
                customCidrText = settings.customCidrs
                if params.mode == .CUSTOM {
                    params.cidrs = customCidrText
                        .split(separator: "\n").map(String.init).filter { !$0.isEmpty }
                }
            }
        }
    }

    // MARK: - sections

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline) {
                Text("UMBRA")
                    .font(UmbraTheme.display(30))
                    .foregroundColor(UmbraTheme.textPrimary)
                Spacer()
                statusPill
            }
            Text(str.brandTagline)
                .font(.system(size: 11))
                .foregroundColor(UmbraTheme.textMuted)
        }
    }

    private var statusPill: some View {
        let (label, color): (String, Color) = {
            if controller.isRunning {
                return (str.live, UmbraTheme.accent(settings.accent))
            }
            if case .done = controller.uiState {
                return (str.done, UmbraTheme.good)
            }
            return (str.idle, UmbraTheme.textSecondary)
        }()
        return HStack(spacing: 6) {
            Circle().fill(color).frame(width: 7, height: 7)
            Text(label)
                .font(.system(size: 10, weight: .bold, design: .monospaced))
                .foregroundColor(color)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 5)
        .background(Capsule().fill(UmbraTheme.surfaceHi))
    }

    private var configPanel: some View {
        VStack(alignment: .leading, spacing: 14) {
            // mode selector
            VStack(alignment: .leading, spacing: 8) {
                sectionLabel(str.mode)
                HStack(spacing: 8) {
                    ForEach(ScanMode.allCases, id: \.self) { m in
                        Chip(text: m.label, selected: params.mode == m) {
                            params.mode = m
                            params.port = Presets.defaultPort(for: m)
                            if m == .CUSTOM {
                                params.cidrs = customCidrText
                                    .split(separator: "\n").map(String.init).filter { !$0.isEmpty }
                            } else {
                                params.cidrs = Presets.cidrs(for: m, family: params.family)
                            }
                        }
                    }
                }
                Text(modeTagline)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(UmbraTheme.textMuted)
            }

            // family selector — ALWAYS visible (the v3.11 Android fix: a
            // hidden filter silently zeroed pasted CIDR lists)
            VStack(alignment: .leading, spacing: 8) {
                sectionLabel(str.family)
                HStack(spacing: 8) {
                    ForEach(NetFamily.allCases, id: \.self) { f in
                        Chip(text: familyLabel(f), selected: params.family == f) {
                            params.family = f
                            if params.mode != .CUSTOM {
                                params.cidrs = Presets.cidrs(for: params.mode, family: f)
                            }
                        }
                    }
                }
            }

            // port chips
            VStack(alignment: .leading, spacing: 8) {
                sectionLabel(str.portLabel)
                if params.mode == .ENDPOINT {
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 8) {
                            Chip(text: "\(str.randomPort) · \(Presets.warpPortsCount)",
                                 selected: params.port == 0) {
                                params.port = 0
                            }
                            ForEach(Presets.warpPorts, id: \.self) { p in
                                Chip(text: "\(p)", selected: params.port == p) {
                                    params.port = p
                                }
                            }
                        }
                    }
                } else if params.mode == .CF_EDGE {
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 8) {
                            ForEach(Presets.cfEdgePorts, id: \.self) { p in
                                Chip(text: "\(p)", selected: params.port == p) {
                                    params.port = p
                                }
                            }
                        }
                    }
                } else {
                    TextField("443", value: $params.port, format: .number.grouping(.never))
                        .keyboardType(.numberPad)
                        .font(.system(size: 13, design: .monospaced))
                        .foregroundColor(UmbraTheme.textPrimary)
                        .padding(10)
                        .background(RoundedRectangle(cornerRadius: 10).fill(UmbraTheme.surfaceHi))
                }
            }

            if params.mode == .CUSTOM {
                VStack(alignment: .leading, spacing: 8) {
                    sectionLabel(str.customCidrs)
                    TextEditor(text: $customCidrText)
                        .font(.system(size: 11, design: .monospaced))
                        .frame(height: 110)
                        .scrollContentBackground(.hidden)
                        .foregroundColor(UmbraTheme.textPrimary)
                        .padding(6)
                        .background(RoundedRectangle(cornerRadius: 10).fill(UmbraTheme.surfaceHi))
                        .onChange(of: customCidrText) { text in
                            params.cidrs = text
                                .split(separator: "\n").map(String.init).filter { !$0.isEmpty }
                            settings.saveCustomCidrs(text)
                        }
                }
            }

            // numeric knobs
            if params.mode == .ENDPOINT {
                sliderRow(str.endpointsCount, value: Binding(
                    get: { Double(params.endpointsCount) },
                    set: { params.endpointsCount = Int($0) }), range: 10...5000, step: 10, fmt: "%d")
                sliderRow(str.attempts, value: Binding(
                    get: { Double(params.warpAttempts) },
                    set: { params.warpAttempts = Int($0) }), range: 1...7, step: 1, fmt: "%d ×")
            } else {
                sliderRow(str.samplesPerPrefix, value: Binding(
                    get: { Double(params.samplesPerPrefix) },
                    set: { params.samplesPerPrefix = Int($0) }), range: 10...1000, step: 10, fmt: "%d")
                sliderRow(str.attempts, value: Binding(
                    get: { Double(params.tcpAttempts) },
                    set: { params.tcpAttempts = Int($0) }), range: 1...7, step: 1, fmt: "%d ×")
            }
            sliderRow(str.timeoutMs, value: Binding(
                get: { Double(params.tcpTimeoutMs) },
                set: { params.tcpTimeoutMs = Int($0) }), range: 500...6000, step: 100, fmt: "%d ms")
            sliderRow(str.concurrency, value: Binding(
                get: { Double(params.concurrency) },
                set: { params.concurrency = Int($0) }), range: 10...400, step: 10, fmt: "%d")

            // toggles
            if params.mode == .ENDPOINT {
                Toggle(isOn: $params.udpNoise) {
                    toggleLabel(str.udpNoise)
                }
                .toggleStyle(.switch)
                .tint(UmbraTheme.accent(settings.accent))
            } else {
                Toggle(isOn: $params.tlsVerify) {
                    toggleLabel(str.tlsVerify)
                }
                .toggleStyle(.switch)
                .tint(UmbraTheme.accent(settings.accent))
            }
            Toggle(isOn: $params.speedTest) {
                toggleLabel(str.speedTest)
            }
            .toggleStyle(.switch)
            .tint(UmbraTheme.accent(settings.accent))

            // estimate
            Text(estimateLine)
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(UmbraTheme.textMuted)
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 16).fill(UmbraTheme.surface))
        .disabled(controller.isRunning)
        .opacity(controller.isRunning ? 0.55 : 1.0)
    }

    private var actionButton: some View {
        Button {
            if controller.isRunning {
                controller.stop()
            } else {
                var p = params
                if p.mode == .CUSTOM {
                    p.cidrs = customCidrText
                        .split(separator: "\n").map(String.init).filter { !$0.isEmpty }
                }
                controller.start(params: p)
            }
        } label: {
            Text(controller.isRunning ? str.stopScan : str.startScan)
                .font(.system(size: 15, weight: .bold, design: .monospaced))
                .foregroundColor(.black)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
                .background(
                    RoundedRectangle(cornerRadius: 14)
                        .fill(controller.isRunning ? UmbraTheme.bad : UmbraTheme.accent(settings.accent)))
        }
        .buttonStyle(.plain)
    }

    private var statsGrid: some View {
        let s = controller.stats
        let cols = [GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible())]
        return LazyVGrid(columns: cols, spacing: 8) {
            StatCell(label: str.tested, value: "\(s.tested)/\(s.candidates)")
            StatCell(label: str.alive, value: "\(s.alive)", color: s.alive > 0 ? UmbraTheme.good : UmbraTheme.textPrimary)
            StatCell(label: str.rate, value: Fmt.str("%.1f/s", s.ratePerSec))
            StatCell(label: str.active, value: "\(s.active)")
            StatCell(label: str.elapsed, value: elapsedLabel)
            StatCell(label: str.eta, value: etaLabel)
        }
    }

    private var liveEndpoints: some View {
        VStack(alignment: .leading, spacing: 6) {
            let alive = controller.results.filter { $0.alive }.prefix(3)
            if !alive.isEmpty {
                ForEach(Array(alive), id: \.id) { r in
                    HStack {
                        Image(systemName: "checkmark.seal.fill")
                            .foregroundColor(UmbraTheme.good)
                            .font(.system(size: 11))
                        Text(r.id)
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundColor(UmbraTheme.textPrimary)
                        Spacer()
                        if let lat = r.latencyMs {
                            Text(Fmt.str("%.0f ms", lat))
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundColor(UmbraTheme.good)
                        }
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .background(RoundedRectangle(cornerRadius: 10).fill(UmbraTheme.surface))
                }
            }
        }
    }

    private func donePanel(_ summary: ScanSummary) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text(summary.cancelled ? str.scanStopped : str.scanComplete)
                    .font(UmbraTheme.display(16))
                    .foregroundColor(summary.cancelled ? UmbraTheme.warn : UmbraTheme.good)
                Spacer()
            }
            Text("\(summary.tested)/\(summary.candidates) · \(summary.alive) \(str.alive.lowercased()) · \(fmtDuration(summary.elapsedMs))")
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(UmbraTheme.textSecondary)
            if let best = summary.best {
                HStack(spacing: 8) {
                    Text("★ BEST")
                        .font(.system(size: 9, weight: .bold, design: .monospaced))
                        .foregroundColor(UmbraTheme.warn)
                    Text(best.id)
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundColor(UmbraTheme.textPrimary)
                    if let lat = best.latencyMs {
                        Text(Fmt.str("%.0fms", lat))
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(UmbraTheme.textSecondary)
                    }
                }
            }
            if let error = summary.error {
                Text(error)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(UmbraTheme.bad)
            }
            HStack(spacing: 10) {
                NavigationLink {
                    ResultsView()
                } label: {
                    panelButton(str.viewResults, tint: UmbraTheme.accent(settings.accent))
                }
                Button {
                    CrashGuard.clear()
                } label: {
                    panelButton(str.configureNewScan, tint: UmbraTheme.surfaceHi, fg: UmbraTheme.textSecondary)
                }
            }
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 16).fill(UmbraTheme.surface))
    }

    private var console: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(str.liveConsole)
                .font(.system(size: 10, weight: .semibold, design: .monospaced))
                .foregroundColor(UmbraTheme.textMuted)
                .kerning(1.2)
            if controller.logLines.isEmpty {
                Text("—")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(UmbraTheme.textMuted)
                    .frame(maxWidth: .infinity, minHeight: 90, alignment: .center)
                    .background(RoundedRectangle(cornerRadius: 12).fill(Color.black.opacity(0.35)))
            } else {
                LogConsole(lines: controller.logLines)
                    .frame(height: 240)
            }
        }
    }

    private func crashBanner(_ reason: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(str.lastCrash)
                .font(.system(size: 9, weight: .bold, design: .monospaced))
                .foregroundColor(UmbraTheme.warn)
            Text(reason)
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(UmbraTheme.textSecondary)
                .lineLimit(3)
            Button(str.dismiss) { CrashGuard.clear() }
                .font(.system(size: 10, weight: .bold))
                .foregroundColor(UmbraTheme.accent(settings.accent))
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 12).fill(UmbraTheme.warn.opacity(0.12)))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(UmbraTheme.warn.opacity(0.35)))
    }

    // MARK: - helpers

    private var modeTagline: String {
        switch params.mode {
        case .CF_EDGE: return ScanMode.CF_EDGE.tagline
        case .CUSTOM: return ScanMode.CUSTOM.tagline
        case .ENDPOINT: return ScanMode.ENDPOINT.tagline
        }
    }

    private func familyLabel(_ f: NetFamily) -> String {
        f == .BOTH ? str.allLabel : f.label
    }

    private var estimateLine: String {
        var probes = 0
        switch params.mode {
        case .ENDPOINT: probes = params.endpointsCount
        case .CF_EDGE, .CUSTOM:
            probes = IpGenerator.estimate(cidrs: params.cidrs, family: params.family,
                                          samplesPerPrefix: params.samplesPerPrefix)
        }
        return "\(str.estimatedProbes): ~\(probes)"
    }

    private var elapsedLabel: String {
        fmtDuration(controller.stats.elapsedMs)
    }

    private var etaLabel: String {
        if let eta = controller.stats.etaSec {
            return fmtDuration(Int64(eta * 1000))
        }
        return "—"
    }

    private func fmtDuration(_ ms: Int64) -> String {
        let total = Int(ms / 1000)
        if total >= 60 {
            return "\(total / 60)m \(total % 60)s"
        }
        if total >= 1 {
            return "\(total)s"
        }
        return "<1s"
    }

    private func sectionLabel(_ s: String) -> some View {
        Text(s)
            .font(.system(size: 9, weight: .semibold, design: .monospaced))
            .foregroundColor(UmbraTheme.textMuted)
            .kerning(1.2)
    }

    private func toggleLabel(_ s: String) -> some View {
        Text(s)
            .font(.system(size: 12, weight: .medium))
            .foregroundColor(UmbraTheme.textSecondary)
    }

    private func sliderRow(_ label: String, value: Binding<Double>, range: ClosedRange<Double>,
                           step: Double, fmt: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(label)
                    .font(.system(size: 9, weight: .semibold, design: .monospaced))
                    .foregroundColor(UmbraTheme.textMuted)
                    .kerning(1.2)
                Spacer()
                if fmt.hasSuffix("ms") {
                    Text("\(Int(value.wrappedValue)) ms")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(UmbraTheme.textPrimary)
                } else if fmt.hasSuffix("×") {
                    Text("\(Int(value.wrappedValue)) ×")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(UmbraTheme.textPrimary)
                } else {
                    Text("\(Int(value.wrappedValue))")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(UmbraTheme.textPrimary)
                }
            }
            Slider(value: value, in: range, step: step)
                .tint(UmbraTheme.accent(settings.accent))
        }
    }

    private func panelButton(_ text: String, tint: Color, fg: Color = .black) -> some View {
        Text(text)
            .font(.system(size: 12, weight: .bold, design: .monospaced))
            .foregroundColor(fg)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 10)
            .background(RoundedRectangle(cornerRadius: 10).fill(tint))
    }
}

extension ScanUiState {
    var isDone: Bool {
        if case .done = self { return true }
        return false
    }
}
