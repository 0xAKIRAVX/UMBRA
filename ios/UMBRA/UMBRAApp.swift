import SwiftUI

@main
struct UMBRAApp: App {
    @StateObject private var settings = SettingsStore.shared
    @StateObject private var controller = ScanController()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(settings)
                .environmentObject(controller)
                .localized(language: settings.language)
                .preferredColorScheme(.dark)
                .tint(UmbraTheme.accent(settings.accent))
        }
    }
}
