import SwiftUI

struct SettingsView: View {
    @EnvironmentObject private var settings: SettingsStore
    @Environment(\.str) private var str

    @State private var measuring = false
    @State private var measureLog: [String] = []

    var body: some View {
        ZStack {
            UmbraTheme.bg.ignoresSafeArea()
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    languageCard
                    appearanceCard
                    netsenseCard
                    dataCard
                    aboutCard
                }
                .padding(.horizontal, 16)
                .padding(.bottom, 24)
            }
        }
    }

    private var languageCard: some View {
        card {
            sectionLabel(str.languageLabel)
            HStack(spacing: 8) {
                Chip(text: str.english, selected: settings.language == 0) {
                    settings.language = 0
                }
                Chip(text: str.persian, selected: settings.language == 1) {
                    settings.language = 1
                }
            }
        }
    }

    private var appearanceCard: some View {
        card {
            sectionLabel(str.appearance)
            HStack(spacing: 10) {
                ForEach(0..<UmbraTheme.accents.count, id: \.self) { i in
                    Button {
                        settings.accent = i
                    } label: {
                        Circle()
                            .fill(UmbraTheme.accents[i])
                            .frame(width: 28, height: 28)
                            .overlay(
                                Circle().strokeBorder(
                                    settings.accent == i ? Color.white : Color.clear, lineWidth: 2))
                    }
                    .buttonStyle(.plain)
                }
            }
            Toggle(isOn: $settings.haptics) {
                Text(str.hapticsLabel)
                    .font(.system(size: 12))
                    .foregroundColor(UmbraTheme.textSecondary)
            }
            .toggleStyle(.switch)
            .tint(UmbraTheme.accent(settings.accent))
        }
    }

    private var netsenseCard: some View {
        card {
            sectionLabel(str.netsense)
            if let profile = settings.networkProfile {
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Text(str.gradeLabel(profile.grade))
                            .font(.system(size: 12, weight: .bold, design: .monospaced))
                            .foregroundColor(gradeColor(profile.grade))
                        Spacer()
                        Text(str.profileAge(profile.ageMinutes))
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundColor(UmbraTheme.textMuted)
                    }
                    HStack(spacing: 14) {
                        metricCell("PING", profile.latencyMs.map { Fmt.str("%.0fms", $0) } ?? "-")
                        metricCell("JIT", profile.jitterMs.map { Fmt.str("%.1fms", $0) } ?? "-")
                        metricCell("LOSS", "\(Int(profile.packetLoss * 100))%")
                        metricCell("DOWN", profile.downloadMbps.map { Fmt.str("%.1fM", $0) } ?? "-")
                        metricCell("V6", profile.v6Ok ? "OK" : "-")
                    }
                }
            }
            if !measureLog.isEmpty {
                Text(measureLog.joined(separator: "\n"))
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(UmbraTheme.textMuted)
            }
            Button {
                runMeasure()
            } label: {
                Text(measuring ? str.measuring : str.measureNow)
                    .font(.system(size: 12, weight: .bold, design: .monospaced))
                    .foregroundColor(.black)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
                    .background(RoundedRectangle(cornerRadius: 10)
                        .fill(UmbraTheme.accent(settings.accent)))
            }
            .buttonStyle(.plain)
            .disabled(measuring)
            .opacity(measuring ? 0.5 : 1)
        }
    }

    private var dataCard: some View {
        card {
            sectionLabel(str.dataSection)
            Button(role: .destructive) {
                settings.clearSavedResults()
            } label: {
                Text(str.clearSaved)
                    .font(.system(size: 12, weight: .bold))
                    .foregroundColor(UmbraTheme.bad)
            }
        }
    }

    private var aboutCard: some View {
        card {
            sectionLabel(str.aboutSection)
            Text(str.aboutText)
                .font(.system(size: 10))
                .foregroundColor(UmbraTheme.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
            if let url = URL(string: "https://github.com/0xAKIRAVX/UMBRA") {
                Link(destination: url) {
                    HStack(spacing: 6) {
                        Image(systemName: "chevron.left.forwardslash.chevron.right")
                            .font(.system(size: 10, weight: .bold))
                        Text(str.sourceLink)
                            .font(.system(size: 10, weight: .semibold, design: .monospaced))
                    }
                    .foregroundColor(UmbraTheme.accent(settings.accent))
                }
            }
            Text("v\(appVersion) · iOS")
                .font(.system(size: 9, design: .monospaced))
                .foregroundColor(UmbraTheme.textMuted)
        }
    }

    // MARK: - helpers

    private var appVersion: String {
        (Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String) ?? "3.11.0"
    }

    private func card<Content: View>(@ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            content()
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 16).fill(UmbraTheme.surface))
    }

    private func sectionLabel(_ s: String) -> some View {
        Text(s)
            .font(.system(size: 9, weight: .bold, design: .monospaced))
            .foregroundColor(UmbraTheme.textMuted)
            .kerning(1.2)
    }

    private func metricCell(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(label)
                .font(.system(size: 8, weight: .semibold, design: .monospaced))
                .foregroundColor(UmbraTheme.textMuted)
            Text(value)
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(UmbraTheme.textSecondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func gradeColor(_ g: NetGrade) -> Color {
        switch g {
        case .excellent: return UmbraTheme.good
        case .good: return UmbraTheme.good.opacity(0.8)
        case .fair: return UmbraTheme.warn
        case .poor: return UmbraTheme.bad
        }
    }

    private func runMeasure() {
        guard !measuring else { return }
        measuring = true
        measureLog = []
        let currentLog = measureLog
        Task { @MainActor in
            let profile = await NetQuality.measure { step in
                Task { @MainActor in
                    if !measureLog.contains(step) {
                        measureLog.append(step)
                    }
                }
            }
            _ = currentLog
            settings.setNetworkProfile(profile)
            measuring = false
        }
    }
}
