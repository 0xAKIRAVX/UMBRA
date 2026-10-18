import SwiftUI
import UIKit

struct ResultsView: View {
    @EnvironmentObject private var settings: SettingsStore
    @EnvironmentObject private var controller: ScanController
    @Environment(\.str) private var str

    @State private var sortKey: SortKey = .SMART
    @State private var toast: String? = nil
    @State private var shareItem: ShareText? = nil

    private struct ShareText: Identifiable {
        let id = UUID()
        let text: String
        let name: String
    }

    private var sorted: [ScanResult] {
        Ranking.sort(controller.results, key: sortKey)
    }

    private var aliveResults: [ScanResult] {
        controller.results.filter { $0.alive }
    }

    var body: some View {
        ZStack {
            UmbraTheme.bg.ignoresSafeArea()
            Group {
                if controller.results.isEmpty {
                    emptyState
                } else {
                    list
                }
            }
            .navigationTitle("")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Menu {
                        ForEach([("CSV", Exporters.csv(aliveResults)),
                                 ("TXT", Exporters.txt(aliveResults, summaryParams)),
                                 ("JSON", Exporters.json(aliveResults, summaryParams))], id: \.0) { item in
                            Button("Export \(item.0)") {
                                shareItem = ShareText(text: item.1, name: "umbra-results.\(item.0.lowercased())")
                            }
                        }
                        Button(role: .destructive, action: { controller.clearResults() }) {
                            Text(str.clearBoard)
                        }
                    } label: {
                        Image(systemName: "square.and.arrow.up")
                            .foregroundColor(UmbraTheme.textSecondary)
                    }
                }
            }
        }
        .sheet(item: $shareItem) { item in
            ActivityShareSheet(items: [item.text])
        }
        .overlay(alignment: .bottom) {
            if let toast = toast {
                Text(toast)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.black)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 8)
                    .background(Capsule().fill(UmbraTheme.good))
                    .padding(.bottom, 14)
                    .transition(.opacity)
                    .onAppear {
                        DispatchQueue.main.asyncAfter(deadline: .now() + 1.6) {
                            withAnimation { self.toast = nil }
                        }
                    }
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "tray")
                .font(.system(size: 40))
                .foregroundColor(UmbraTheme.textMuted)
            Text(str.noResultsYet)
                .font(.system(size: 12))
                .foregroundColor(UmbraTheme.textMuted)
                .multilineTextAlignment(.center)
        }
        .padding(40)
    }

    private var list: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                // sort chips
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(SortKey.allCases, id: \.self) { k in
                            Chip(text: sortChipLabel(k), selected: sortKey == k) {
                                sortKey = k
                            }
                        }
                    }
                    .padding(.horizontal, 16)
                }

                // smart picks
                if !aliveResults.isEmpty {
                    smartPicks
                }

                ForEach(sorted) { r in
                    resultRow(r)
                }
            }
            .padding(.vertical, 12)
            .padding(.bottom, 20)
        }
    }

    private var smartPicks: some View {
        let picks = SmartRanking.picks(controller.results, profile: settings.networkProfile)
        return VStack(alignment: .leading, spacing: 8) {
            Text(str.smartPicks)
                .font(.system(size: 9, weight: .bold, design: .monospaced))
                .foregroundColor(UmbraTheme.textMuted)
                .kerning(1.2)
                .padding(.horizontal, 16)
            let rows: [(String, ScanResult?)] = [
                (str.pickBest, picks.best),
                (str.pickPing, picks.ping),
                (str.pickStable, picks.stable),
                (str.pickFast, picks.fast),
            ]
            VStack(spacing: 6) {
                ForEach(Array(rows.enumerated()), id: \.offset) { i, row in
                    if let r = row.1 {
                        HStack(spacing: 10) {
                            Text(row.0)
                                .font(.system(size: 9, weight: .bold, design: .monospaced))
                                .foregroundColor(UmbraTheme.warn)
                                .frame(width: 110, alignment: .leading)
                            Text(r.id)
                                .font(.system(size: 12, design: .monospaced))
                                .foregroundColor(UmbraTheme.textPrimary)
                            Spacer()
                            if let lat = r.latencyMs {
                                Text(Fmt.str("%.0fms", lat))
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundColor(UmbraTheme.textSecondary)
                            }
                            copyButton(r)
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 9)
                        .background(RoundedRectangle(cornerRadius: 10).fill(UmbraTheme.surface))
                        .padding(.horizontal, 16)
                    }
                }
            }
        }
    }

    private func resultRow(_ r: ScanResult) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Circle()
                    .fill(r.alive ? UmbraTheme.good : UmbraTheme.bad.opacity(0.5))
                    .frame(width: 7, height: 7)
                Text(r.id)
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(r.alive ? UmbraTheme.textPrimary : UmbraTheme.textMuted)
                Spacer()
                HStack(spacing: 4) {
                    if r.wgHandshakes > 0 {
                        badge(str.wgBadge, UmbraTheme.good)
                    }
                    if r.tlsSuccess {
                        badge(str.tlsBadge, UmbraTheme.accent(settings.accent))
                    }
                }
                copyButton(r)
            }
            HStack(spacing: 12) {
                metricCell("LAT", r.latencyMs.map { Fmt.str("%.0fms", $0) } ?? "-")
                metricCell("JIT", r.jitterMs.map { Fmt.str("%.1fms", $0) } ?? "-")
                metricCell(str.loss, "\(r.lossPct)%")
                metricCell("SPD", r.speedMbps.map { Fmt.str("%.1fM", $0) } ?? "-")
                metricCell("SCORE", Fmt.str("%.0f", Ranking.scoreOf(r)))
            }
            if let err = r.error, !r.alive {
                Text(err)
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(UmbraTheme.bad.opacity(0.8))
                    .lineLimit(2)
            }
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 12).fill(UmbraTheme.surface))
        .padding(.horizontal, 16)
    }

    private func badge(_ text: String, _ color: Color) -> some View {
        Text(text)
            .font(.system(size: 8, weight: .bold, design: .monospaced))
            .foregroundColor(.black)
            .padding(.horizontal, 5)
            .padding(.vertical, 2)
            .background(RoundedRectangle(cornerRadius: 4).fill(color))
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

    private func copyButton(_ r: ScanResult) -> some View {
        Button {
            UIPasteboard.general.string = r.id
            withAnimation { toast = str.copied }
        } label: {
            Image(systemName: "doc.on.doc")
                .font(.system(size: 12))
                .foregroundColor(UmbraTheme.textSecondary)
        }
        .buttonStyle(.plain)
    }

    private func sortChipLabel(_ k: SortKey) -> String {
        switch k {
        case .SMART: return str.sortSmart
        case .SCORE: return str.sortScore
        case .LATENCY: return str.sortLatency
        case .JITTER: return str.sortJitter
        case .LOSS: return str.sortLoss
        case .SPEED: return str.sortSpeed
        }
    }

    private var summaryParams: ScanParams? {
        controller.lastSummary?.params
    }
}

/// UIActivityViewController wrapper (share sheet).
struct ActivityShareSheet: UIViewControllerRepresentable {
    let items: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}
