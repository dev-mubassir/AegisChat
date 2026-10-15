import Flutter
import UIKit

@main
@objc class AppDelegate: FlutterAppDelegate, FlutterImplicitEngineDelegate {
  private var blurView: UIVisualEffectView?

  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    excludeDocumentsFromBackup()
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  func didInitializeImplicitFlutterEngine(_ engineBridge: FlutterImplicitEngineBridge) {
    GeneratedPluginRegistrant.register(with: engineBridge.pluginRegistry)
  }

  override func applicationWillResignActive(_ application: UIApplication) {
    super.applicationWillResignActive(application)
    addAppSwitcherBlur()
  }

  override func applicationDidBecomeActive(_ application: UIApplication) {
    super.applicationDidBecomeActive(application)
    removeAppSwitcherBlur()
  }

  private func addAppSwitcherBlur() {
    guard let window = self.window, blurView == nil else { return }
    let blurEffect = UIBlurEffect(style: .extraLight)
    let view = UIVisualEffectView(effect: blurEffect)
    view.frame = window.bounds
    view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
    window.addSubview(view)
    self.blurView = view
  }

  private func removeAppSwitcherBlur() {
    blurView?.removeFromSuperview()
    blurView = nil
  }

  private func excludeDocumentsFromBackup() {
    guard let docsUrl = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else { return }
    var url = docsUrl
    var resourceValues = URLResourceValues()
    resourceValues.isExcludedFromBackup = true
    try? url.setResourceValues(resourceValues)
  }
}
