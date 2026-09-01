import Cocoa
import Darwin

@main
final class LegionInstaller: NSObject, NSApplicationDelegate {
  private let fileManager = FileManager.default
  private let commandTimeout: TimeInterval = 60

  func applicationDidFinishLaunching(_ notification: Notification) {
    do {
      try install()
      show(title: "Legion installed", message: "Legion is ready in ~/Library/Application Support/Orthic Labs/Legion.", style: .informational)
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
    let root = home.appendingPathComponent("Library/Application Support/Orthic Labs/Legion", isDirectory: true)
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
      try fileManager.createSymbolicLink(at: replacementLink, withDestinationURL: URL(fileURLWithPath: "../../Library/Application Support/Orthic Labs/Legion/current/bin/\(executable)", relativeTo: localBin))
      try? fileManager.removeItem(at: link)
      try fileManager.moveItem(at: replacementLink, to: link)
    }
    let binary = current.appendingPathComponent("bin/legion")
    try runInstalledStep(binary: binary, arguments: ["setup", "repair", "--confirm"], label: "setup repair")
    try runInstalledStep(binary: binary, arguments: ["setup", "status"], label: "setup status")
    try runInstalledStep(binary: binary, arguments: ["doctor"], label: "doctor")
  }

  private func runInstalledStep(binary: URL, arguments: [String], label: String) throws {
    let token = UUID().uuidString
    let stdoutURL = fileManager.temporaryDirectory.appendingPathComponent("legion-installer-\(token).stdout")
    let stderrURL = fileManager.temporaryDirectory.appendingPathComponent("legion-installer-\(token).stderr")
    fileManager.createFile(atPath: stdoutURL.path, contents: nil)
    fileManager.createFile(atPath: stderrURL.path, contents: nil)
    defer {
      try? fileManager.removeItem(at: stdoutURL)
      try? fileManager.removeItem(at: stderrURL)
    }
    let stdout = try FileHandle(forWritingTo: stdoutURL)
    let stderr = try FileHandle(forWritingTo: stderrURL)
    defer {
      try? stdout.close()
      try? stderr.close()
    }
    let task = Process()
    task.executableURL = binary
    task.arguments = arguments
    task.standardOutput = stdout
    task.standardError = stderr
    let completed = DispatchSemaphore(value: 0)
    task.terminationHandler = { _ in completed.signal() }
    log("starting \(label): \(binary.path) \(arguments.joined(separator: " "))")
    try task.run()
    if completed.wait(timeout: .now() + commandTimeout) == .timedOut {
      task.terminate()
      if completed.wait(timeout: .now() + 2) == .timedOut {
        kill(task.processIdentifier, SIGKILL)
        _ = completed.wait(timeout: .now() + 2)
      }
      try? stdout.synchronize()
      try? stderr.synchronize()
      let output = diagnostics(stdoutURL: stdoutURL, stderrURL: stderrURL)
      log("timed out \(label) after \(Int(commandTimeout))s\(output)")
      throw InstallerError.commandTimedOut(label, Int(commandTimeout), output)
    }
    try? stdout.synchronize()
    try? stderr.synchronize()
    let output = diagnostics(stdoutURL: stdoutURL, stderrURL: stderrURL)
    guard task.terminationStatus == 0 else {
      log("failed \(label) with status \(task.terminationStatus)\(output)")
      throw InstallerError.commandFailed(label, task.terminationStatus, output)
    }
    log("completed \(label)")
  }

  private func diagnostics(stdoutURL: URL, stderrURL: URL) -> String {
    let stdout = (try? String(contentsOf: stdoutURL, encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    let stderr = (try? String(contentsOf: stderrURL, encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    let combined = [stdout.isEmpty ? nil : "stdout:\n\(stdout)", stderr.isEmpty ? nil : "stderr:\n\(stderr)"].compactMap { $0 }.joined(separator: "\n")
    guard !combined.isEmpty else { return "\n(no command output)" }
    return "\n" + String(combined.suffix(4000))
  }

  private func log(_ message: String) {
    FileHandle.standardError.write(Data("[legion-installer] \(message)\n".utf8))
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
    case commandFailed(String, Int32, String)
    case commandTimedOut(String, Int, String)
    var errorDescription: String? {
      switch self {
      case .invalidVersion: return "Installer contains an invalid version."
      case .commandFailed(let label, let status, let output): return "Legion \(label) exited with status \(status).\(output)"
      case .commandTimedOut(let label, let seconds, let output): return "Legion \(label) timed out after \(seconds) seconds.\(output)"
      }
    }
  }
}
