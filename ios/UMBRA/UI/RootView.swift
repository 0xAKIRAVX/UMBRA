import SwiftUI

struct RootView: View {
    @EnvironmentObject private var settings: SettingsStore
    @EnvironmentObject private var controller: ScanController
    @Environment(\.str) private var str

    var body: some View {
        TabView {
            NavigationStack {
                ScanView()
            }
            .tabItem { Label(str.navScan, systemImage: "dot.radiowaves.left.and.right") }
            NavigationStack {
                ResultsView()
            }
            .tabItem { Label(str.navResults, systemImage: "list.bullet.rectangle") }
            NavigationStack {
                VlessView()
            }
            .tabItem { Label(str.navVless, systemImage: "link") }
            NavigationStack {
                SettingsView()
            }
            .tabItem { Label(str.navSystem, systemImage: "gearshape") }
        }
    }
}
