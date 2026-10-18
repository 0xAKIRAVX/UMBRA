import SwiftUI

/// UMBRA dark theme — mirrors the Android app's palette.
enum UmbraTheme {

    static let bg = Color(red: 0.031, green: 0.043, blue: 0.055)          // #080B0E
    static let surface = Color(red: 0.071, green: 0.086, blue: 0.106)     // #12162B ~
    static let surfaceHi = Color(red: 0.10, green: 0.12, blue: 0.15)
    static let stroke = Color.white.opacity(0.08)
    static let textPrimary = Color.white
    static let textSecondary = Color.white.opacity(0.62)
    static let textMuted = Color.white.opacity(0.38)
    static let good = Color(red: 0.20, green: 0.83, blue: 0.48)           // #34d399
    static let warn = Color(red: 0.98, green: 0.72, blue: 0.16)           // #f5b841
    static let bad = Color(red: 1.0, green: 0.23, blue: 0.29)             // #ff3b4a

    static let accents: [Color] = [
        Color(red: 1.0, green: 0.231, blue: 0.29),   // signature red
        Color(red: 0.25, green: 0.84, blue: 0.96),   // cyan
        Color(red: 0.61, green: 0.35, blue: 0.99),   // violet
        Color(red: 0.30, green: 0.94, blue: 0.42),   // green
        Color(red: 0.98, green: 0.75, blue: 0.18),   // amber
    ]

    static func accent(_ index: Int) -> Color {
        accents[index % accents.count]
    }

    /// Display font (latin) — falls back to system when the custom family
    /// is unavailable.
    static func display(_ size: CGFloat) -> Font {
        .custom("Chakra Petch", size: size).weight(.semibold)
    }

    static func mono(_ size: CGFloat) -> Font {
        .custom("Chakra Petch", size: size)
    }

    /// Body font for the current language.
    static func body(_ isFa: Bool, _ size: CGFloat) -> Font {
        isFa ? .custom("Vazirmatn", size: size) : .system(size: size)
    }
}

/// A stat cell for the scan header grid.
struct StatCell: View {
    let label: String
    let value: String
    var color: Color = UmbraTheme.textPrimary

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label)
                .font(.system(size: 9, weight: .semibold, design: .monospaced))
                .foregroundColor(UmbraTheme.textMuted)
                .kerning(1.2)
            Text(value)
                .font(.system(size: 16, weight: .bold, design: .monospaced))
                .foregroundColor(color)
                .lineLimit(1)
                .minimumScaleFactor(0.6)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 10).fill(UmbraTheme.surface))
    }
}

/// Small pill chip.
struct Chip: View {
    let text: String
    var selected: Bool = false
    var tint: Color = UmbraTheme.accent(0)
    var action: (() -> Void)? = nil

    var body: some View {
        Button(action: { action?() }) {
            Text(text)
                .font(.system(size: 11, weight: .semibold, design: .monospaced))
                .foregroundColor(selected ? Color.black : UmbraTheme.textSecondary)
                .padding(.horizontal, 12)
                .padding(.vertical, 7)
                .background(
                    Capsule().fill(selected ? tint : UmbraTheme.surfaceHi))
        }
        .buttonStyle(.plain)
    }
}

/// Scan log console (auto-scrolling mono text).
struct LogConsole: View {
    let lines: [String]

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 3) {
                    ForEach(Array(lines.enumerated()), id: \.offset) { i, line in
                        Text(line)
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundColor(colorFor(line))
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .id(i)
                    }
                }
                .padding(10)
            }
            .onChange(of: lines.count) { _ in
                if let last = lines.indices.last {
                    proxy.scrollTo(last, anchor: .bottom)
                }
            }
        }
        .background(RoundedRectangle(cornerRadius: 12).fill(Color.black.opacity(0.35)))
        .overlay(
            RoundedRectangle(cornerRadius: 12).strokeBorder(UmbraTheme.stroke, lineWidth: 1))
    }

    private func colorFor(_ line: String) -> Color {
        if line.contains("validated of") || line.contains("answered · udp path live") {
            return UmbraTheme.good
        }
        if line.contains("aborted") || line.contains("failed") || line.contains("0/") {
            return UmbraTheme.bad
        }
        if line.contains("recovery") || line.contains("re-aimed") || line.contains("sweep") {
            return UmbraTheme.warn
        }
        return UmbraTheme.textSecondary
    }
}
