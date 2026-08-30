import Cocoa

@main
final class LegionInstaller: NSObject, NSApplicationDelegate {
  private let fileManager = FileManager.default

  func applicationDidFinishLaunching(_ notification: Notification) {
    do {
      try install()
      show(title: "Legion installed", message: "Legion is ready in ~/Library/Application Support/Legion.", style: .informational)
    } catch {
      show(title: "Legion installation failed", message: error.localizedDescription, style: .critical)
    }
    NSApp.terminate(nil)
  }

  private func install() throws {
    let resources = Bundle.main.resourceURL!
    let payload = resources.appendingPathComponent("payload", isDirectory: true)
    let versionFile = resources.appendingPathComponent("version.txt")
    let version = try String(contentsOf: versionFile, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
    guard !version.isEmpty, !version.contains("/") else { throw InstallerError.invalidVersion }
    let home = fileManager.homeDirectoryForCurrentUser
    let root = home.appendingPathComponent("Library/Application Support/Legion", isDirectory: true)
    let versions = root.appendingPathComponent("versions", isDirectory: true)
    let final = versions.appendingPathComponent(version, isDirectory: true)
    let temporary = versions.appendingPathComponent(".install-\(version)-\(UUID().uuidString)", isDirectory: true)
    try fileManager.createDirectory(at: versions, withIntermediateDirectories: true)
    if !fileManager.fileExists(atPath: final.path) {
      try fileManager.copyItem(at: payload, to: temporary)
      try fileManager.moveItem(at: temporary, to: final)
    }
    let current = root.appendingPathComponent("current")
    let replacement = root.appendingPathComponent(".current-\(UUID().uuidString)")
    try? fileManager.removeItem(at: replacement)
    try fileManager.createSymbolicLink(at: replacement, withDestinationURL: URL(fileURLWithPath: "versions/\(version)", relativeTo: root))
    try? fileManager.removeItem(at: current)
    try fileManager.moveItem(at: replacement, to: current)

    let localBin = home.appendingPathComponent(".local/bin", isDirectory: true)
    try fileManager.createDirectory(at: localBin, withIntermediateDirectories: true)
    for executable in ["legion", "legion-hook", "legion-mcp"] {
      let link = localBin.appendingPathComponent(executable)
      let replacementLink = localBin.appendingPathComponent(".\(executable)-\(UUID().uuidString)")
      try? fileManager.removeItem(at: replacementLink)
      try fileManager.createSymbolicLink(at: replacementLink, withDestinationURL: URL(fileURLWithPath: "../../Library/Application Support/Legion/current/bin/\(executable)", relativeTo: localBin))
      try? fileManager.removeItem(at: link)
      try fileManager.moveItem(at: replacementLink, to: link)
    }
    try runSetupRepair(binary: current.appendingPathComponent("bin/legion"))
  }

  private func runSetupRepair(binary: URL) throws {
    let task = Process()
    task.executableURL = binary
    task.arguments = ["doctor"]
    try task.run()
    task.waitUntilExit()
    if task.terminationStatus != 0 { throw InstallerError.repairFailed(task.terminationStatus) }
  }

  private func show(title: String, message: String, style: NSAlert.Style) {
    let alert = NSAlert()
    alert.messageText = title
    alert.informativeText = message
    alert.alertStyle = style
    alert.runModal()
  }

  enum InstallerError: LocalizedError {
    case invalidVersion
    case repairFailed(Int32)
    var errorDescription: String? {
      switch self {
      case .invalidVersion: return "Installer contains an invalid version."
      case .repairFailed(let status): return "Legion setup repair exited with status \(status)."
      }
    }
  }
}
