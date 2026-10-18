import Foundation
import SwiftUI

/// UMBRA i18n — English + فارسی. Technical tokens (IP, TLS, WG, WARP, VLESS,
/// UUID, SNI, CSV …) stay Latin in both languages, exactly like the Android
/// app — that is how Persian networking tools present them.
enum AppLanguage {
    static func defaultForSystem() -> Int {
        Locale.current.language.languageCode?.identifier == "fa" ? 1 : 0
    }
}

struct Str {
    let isFa: Bool

    init(language: Int) {
        isFa = language == 1
    }

    private var l: (_ en: String, _ fa: String) -> String {
        { isFa ? $1 : $0 }
    }

    // brand / status
    var brandTagline: String { l("Cloudflare & WARP endpoint intelligence", "هوش اندپوینت Cloudflare و WARP") }
    var live: String { l("LIVE", "زنده") }
    var done: String { l("DONE", "پایان") }
    var idle: String { l("IDLE", "آماده") }

    // nav
    var navScan: String { l("Scan", "اسکن") }
    var navResults: String { l("Results", "نتایج") }
    var navVless: String { l("VLESS", "VLESS") }
    var navSystem: String { l("Settings", "تنظیمات") }

    // scan screen
    var tested: String { l("TESTED", "تست‌شده") }
    var alive: String { l("ALIVE", "زنده") }
    var rate: String { l("RATE", "سرعت") }
    var active: String { l("ACTIVE", "فعال") }
    var elapsed: String { l("ELAPSED", "گذشته") }
    var eta: String { l("ETA", "باقی‌مانده") }
    var stopScan: String { l("STOP SCAN", "توقف اسکن") }
    var startScan: String { l("START SCAN", "شروع اسکن") }
    var scanComplete: String { l("SCAN COMPLETE", "اسکن کامل شد") }
    var scanStopped: String { l("SCAN STOPPED", "اسکن متوقف شد") }
    var viewResults: String { l("VIEW RESULTS", "مشاهده نتایج") }
    var configureNewScan: String { l("CONFIGURE NEW SCAN", "اسکن جدید") }
    var liveConsole: String { l("LIVE CONSOLE", "کنسول زنده") }
    var noResultsYet: String { l("no scan results yet — run a scan first", "هنوز نتیجه‌ای نیست — اول یک اسکن اجرا کن") }

    // config panel
    var mode: String { l("MODE", "حالت") }
    var family: String { l("IP FAMILY", "خانواده IP") }
    var allLabel: String { l("ALL", "همه") }
    var portLabel: String { l("PORT", "پورت") }
    var randomPort: String { l("RANDOM", "تصادفی") }
    var endpointsCount: String { l("ENDPOINTS", "تعداد اندپوینت") }
    var samplesPerPrefix: String { l("SAMPLES / PREFIX", "نمونه در بازه") }
    var attempts: String { l("ATTEMPTS", "تلاش") }
    var timeoutMs: String { l("TIMEOUT (MS)", "تایم‌اوت (میلی‌ثانیه)") }
    var concurrency: String { l("CONCURRENCY", "همزمانی") }
    var udpNoise: String { l("UDP ANTI-DPI NOISE", "نویز UDP ضد DPI") }
    var tlsVerify: String { l("TLS VERIFICATION", "تأیید TLS") }
    var speedTest: String { l("SPEED TEST", "تست سرعت") }
    var customCidrs: String { l("CUSTOM CIDR LIST (ONE PER LINE)", "لیست CIDR دلخواه (هر خط یک بازه)") }
    var cidrPlaceholder: String { l("104.16.0.0/13\n162.159.192.0/24\n…", "104.16.0.0/13\n162.159.192.0/24\n…") }
    var estimatedProbes: String { l("estimated probes", "برآورد پروب‌ها") }

    // results
    var sortSmart: String { l("SMART", "هوشمند") }
    var sortScore: String { l("SCORE", "امتیاز") }
    var sortLatency: String { l("LATENCY", "تأخیر") }
    var sortJitter: String { l("JITTER", "جیتر") }
    var sortLoss: String { l("LOSS", "اتلاف") }
    var sortSpeed: String { l("SPEED", "سرعت") }
    var copyEndpoint: String { l("Copy endpoint", "کپی اندپوینت") }
    var copied: String { l("Copied", "کپی شد") }
    var exportShare: String { l("Export / Share", "خروجی / اشتراک") }
    var smartPicks: String { l("SMART PICKS · FOR YOUR LINE", "انتخاب هوشمند · برای خط اینترنت تو") }
    var pickBest: String { l("BEST OVERALL", "بهترین کلی") }
    var pickPing: String { l("LOWEST PING", "کم‌ترین پینگ") }
    var pickStable: String { l("MOST STABLE", "پایدارترین") }
    var pickFast: String { l("FASTEST", "پرسرعت‌ترین") }
    var clearBoard: String { l("Clear board", "پاک کردن") }
    var wgBadge: String { l("WG", "WG") }
    var tlsBadge: String { l("TLS", "TLS") }
    var loss: String { l("LOSS", "اتلاف") }

    // vless
    var vlessTitle: String { l("VLESS CONFIG BUILDER", "سازنده کانفیگ VLESS") }
    var vlessHint: String {
        l("SNI must be your own Cloudflare-fronted domain (worker / panel) — it drives both the TLS SNI and the WebSocket host. With a test SNI the link never proxies anything.",
          "SNI باید دامنهٔ خودت روی Cloudflare باشد (ورکر یا پنل) — هم روی TLS SNI و هم روی WebSocket host اعمال می‌شود. با SNI آزمایشی لینک هیچ‌وقت پروکسی نمی‌کند.")
    }
    var vlessUuid: String { l("UUID", "UUID") }
    var vlessHost: String { l("ENDPOINT (IP OR HOST)", "اندپوینت (IP یا هاست)") }
    var vlessPort: String { l("PORT", "پورت") }
    var vlessSni: String { l("SNI (YOUR DOMAIN)", "SNI (دامنهٔ شما)") }
    var vlessPath: String { l("WS PATH", "مسیر WS") }
    var vlessRemark: String { l("REMARK", "نام") }
    var generate: String { l("Generate link", "ساخت لینک") }
    var useBestEndpoint: String { l("Use best endpoint", "استفاده از بهترین اندپوینت") }
    var randomUuid: String { l("Random UUID", "UUID تصادفی") }
    var linkPreview: String { l("LINK", "لینک") }
    var copyLink: String { l("Copy link", "کپی لینک") }
    var testOnlySniWarning: String { l("⚠ this SNI is test-only — the link will not proxy", "⚠ این SNI فقط آزمایشی است — لینک پروکسی نمی‌شود") }

    // settings
    var languageLabel: String { l("LANGUAGE", "زبان") }
    var english: String { l("English", "English") }
    var persian: String { l("فارسی", "فارسی") }
    var appearance: String { l("APPEARANCE", "ظاهر") }
    var accentColor: String { l("ACCENT COLOR", "رنگ اصلی") }
    var hapticsLabel: String { l("HAPTICS", "لرزش") }
    var netsense: String { l("NETSENSE · MEASURE YOUR LINE", "NETSENSE · اندازه‌گیری خط اینترنت") }
    var measureNow: String { l("Measure now", "اندازه‌گیری") }
    var measuring: String { l("measuring…", "در حال اندازه‌گیری…") }
    var profileAge: (Int) -> String { { l("measured \($0) min ago", "\($0) دقیقه پیش اندازه‌گیری شد") } }
    var gradeLabel: (NetGrade) -> String {
        { g in
            switch g {
            case .excellent: return l("EXCELLENT", "عالی")
            case .good: return l("GOOD", "خوب")
            case .fair: return l("FAIR", "متوسط")
            case .poor: return l("POOR", "ضعیف")
            }
        }
    }
    var dataSection: String { l("DATA", "داده‌ها") }
    var clearSaved: String { l("Clear saved results", "پاک کردن نتایج ذخیره‌شده") }
    var aboutSection: String { l("ABOUT", "درباره") }
    var aboutText: String {
        l("UMBRA scans Cloudflare and WARP address ranges from your device, validates endpoints with a REAL WireGuard handshake, ranks them for your own line and turns winners into VLESS configs.\n\niOS sibling of the Android app — same engine logic, same honest verdicts, byte-identical crypto verified against shared test vectors.",
          "UMBRA از دستگاه خودت بازه‌های IP کلادفلر و WARP را اسکن می‌کند، اندپوینت‌ها را با هندشیک واقعی WireGuard تأیید می‌کند، برای خط اینترنت خودت رتبه‌بندی می‌کند و بهترین‌ها را به کانفیگ VLESS تبدیل می‌کند.\n\nنسخهٔ خواهر iOS اپ اندروید — منطق موتور یکسان، وردیق‌های صادقانه، رمزنگاری بایت‌به‌بایت یکسان که با وکتورهای تست مشترک تأیید شده.")
    }
    var sourceLink: String { l("Source · github.com/0xAKIRAVX/UMBRA", "سورس · github.com/0xAKIRAVX/UMBRA") }

    // misc
    var ok: String { l("OK", "باشه") }
    var lastCrash: String { l("LAST SCAN ENDED WITH A VERDICT", "اسکن قبلی با یک وردیکت تمام شد") }
    var dismiss: String { l("Dismiss", "رد کردن") }
}

/// Language-aware environment key.
private struct StrKey: EnvironmentKey {
    static let defaultValue = Str(language: AppLanguage.defaultForSystem())
}

extension EnvironmentValues {
    var str: Str {
        get { self[StrKey.self] }
        set { self[StrKey.self] = newValue }
    }
}

extension View {
    /// Applies right-to-left layout + Persian font when the app language is FA.
    func localized(language: Int) -> some View {
        environment(\.str, Str(language: language))
            .environment(\.layoutDirection, language == 1 ? .rightToLeft : .leftToRight)
    }
}
