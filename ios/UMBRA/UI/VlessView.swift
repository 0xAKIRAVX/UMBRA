import SwiftUI
import UIKit

struct VlessView: View {
    @EnvironmentObject private var settings: SettingsStore
    @EnvironmentObject private var controller: ScanController
    @Environment(\.str) private var str

    @State private var uuid: String = VlessGenerator.randomUuid()
    @State private var host: String = ""
    @State private var port: String = "443"
    @State private var sni: String = ""
    @State private var wsPath: String = "/"
    @State private var remark: String = "UMBRA-node"
    @State private var link: String? = nil
    @State private var toast: String? = nil

    var body: some View {
        ZStack {
            UmbraTheme.bg.ignoresSafeArea()
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    header
                    form
                    if let link = link {
                        linkPreview(link)
                        qrCard(link)
                    }
                }
                .padding(.horizontal, 16)
                .padding(.bottom, 24)
            }
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
        .onAppear(perform: prefillBestEndpoint)
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(str.vlessTitle)
                .font(UmbraTheme.display(20))
                .foregroundColor(UmbraTheme.textPrimary)
            Text(str.vlessHint)
                .font(.system(size: 10))
                .foregroundColor(UmbraTheme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var form: some View {
        VStack(alignment: .leading, spacing: 12) {
            fieldRow(str.vlessUuid, text: $uuid, mono: true) {
                Button(str.randomUuid) {
                    uuid = VlessGenerator.randomUuid()
                }
                .font(.system(size: 10, weight: .bold))
                .foregroundColor(UmbraTheme.accent(settings.accent))
            }
            fieldRow(str.vlessHost, text: $host, mono: true) {
                Button(str.useBestEndpoint) {
                    prefillBestEndpoint()
                }
                .font(.system(size: 10, weight: .bold))
                .foregroundColor(UmbraTheme.accent(settings.accent))
            }
            fieldRow(str.vlessPort, text: $port, mono: true) { EmptyView() }
            fieldRow(str.vlessSni, text: $sni, mono: false) { EmptyView() }
            fieldRow(str.vlessPath, text: $wsPath, mono: true) { EmptyView() }
            fieldRow(str.vlessRemark, text: $remark, mono: false) { EmptyView() }

            if VlessGenerator.isTestOnlySni(sni) {
                Text(str.testOnlySniWarning)
                    .font(.system(size: 10))
                    .foregroundColor(UmbraTheme.warn)
            }

            Button {
                let cfg = VlessGenerator.Config(
                    uuid: uuid,
                    host: host,
                    port: Int(port) ?? 443,
                    sni: sni,
                    wsPath: wsPath,
                    remark: remark)
                link = VlessGenerator.buildLink(cfg)
            } label: {
                Text(str.generate)
                    .font(.system(size: 13, weight: .bold, design: .monospaced))
                    .foregroundColor(.black)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
                    .background(RoundedRectangle(cornerRadius: 12)
                        .fill(UmbraTheme.accent(settings.accent)))
            }
            .buttonStyle(.plain)
            .disabled(!VlessGenerator.isValidUuid(uuid) || host.isEmpty)
            .opacity((!VlessGenerator.isValidUuid(uuid) || host.isEmpty) ? 0.4 : 1)
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 16).fill(UmbraTheme.surface))
    }

    private func linkPreview(_ link: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(str.linkPreview)
                .font(.system(size: 9, weight: .semibold, design: .monospaced))
                .foregroundColor(UmbraTheme.textMuted)
                .kerning(1.2)
            Text(link)
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(UmbraTheme.textSecondary)
                .textSelection(.enabled)
                .lineLimit(6)
            Button {
                UIPasteboard.general.string = link
                withAnimation { toast = str.copied }
            } label: {
                HStack {
                    Image(systemName: "doc.on.doc")
                    Text(str.copyLink)
                }
                .font(.system(size: 11, weight: .bold, design: .monospaced))
                .foregroundColor(.black)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 9)
                .background(RoundedRectangle(cornerRadius: 10).fill(UmbraTheme.good))
            }
            .buttonStyle(.plain)
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 16).fill(UmbraTheme.surface))
    }

    private func qrCard(_ link: String) -> some View {
        VStack(spacing: 10) {
            if let ui = QrGen.qrImage(for: link) {
                Image(uiImage: ui)
                    .interpolation(.none)
                    .resizable()
                    .scaledToFit()
                    .frame(width: 190, height: 190)
                    .background(Color.white)
                    .cornerRadius(12)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 16).fill(UmbraTheme.surface))
    }

    private func fieldRow<Trailing: View>(_ label: String, text: Binding<String>,
                                          mono: Bool, @ViewBuilder trailing: () -> Trailing) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(label)
                    .font(.system(size: 9, weight: .semibold, design: .monospaced))
                    .foregroundColor(UmbraTheme.textMuted)
                    .kerning(1.2)
                Spacer()
                trailing()
            }
            TextField("", text: text)
                .font(mono ? .system(size: 12, design: .monospaced) : .system(size: 12))
                .foregroundColor(UmbraTheme.textPrimary)
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
                .padding(10)
                .background(RoundedRectangle(cornerRadius: 10).fill(UmbraTheme.surfaceHi))
        }
    }

    private func prefillBestEndpoint() {
        guard host.isEmpty else { return }
        let pool = controller.results.filter { $0.alive }
        let best = pool.max { Ranking.scoreOf($0) < Ranking.scoreOf($1) }
            ?? settings.savedEndpointResults.max { Ranking.scoreOf($0) < Ranking.scoreOf($1) }
        if let best = best {
            host = best.ip
            port = "\(best.port)"
        }
    }
}
