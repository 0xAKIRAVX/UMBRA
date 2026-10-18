import Foundation

/// Locale-safe number formatting for logs, metrics and exports.
///
/// The v4.0.1 Android lesson (locale hardening): default-locale formatting
/// garbles the ASCII engine log on fa/ar devices (Persian/Arabic-Indic
/// digits), flips decimal separators on European locales, and lowercases
/// labels on Turkish. Every number that lands in an ASCII context (log
/// lines, CSV/TXT/JSON exports, stat cells) goes through here with a fixed
/// en_US_POSIX locale.
enum Fmt {
    private static let posix = Locale(identifier: "en_US_POSIX")

    static func str(_ format: String, _ args: CVarArg...) -> String {
        String(format: format, locale: posix, arguments: args)
    }
}
