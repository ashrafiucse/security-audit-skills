// Fixture: secrets in UserDefaults. FAKE data only.
import UIKit

@main
class AppDelegate: UIResponder, UIApplicationDelegate {
    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        // SEC-09: auth token stored in UserDefaults (plaintext plist, rides backups)
        UserDefaults.standard.set("tok_FakeTokenForEvalFixtures12345", forKey: "auth_token")
        return true
    }
}
