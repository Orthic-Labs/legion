import Cocoa
import CryptoKit
import Darwin

@main
final class LegionInstaller: NSObject, NSApplicationDelegate {
  private struct LegacyCodexSnapshot {
    let target: URL
    let installRoot: URL
    let ledger: URL
    let savedRoot: URL
    let savedLedger: URL
    let ledgerBytes: Data
    let digests: [String: String]
    let links: [String: String]
  }
  private struct CodexDisabledIntent {
    let config: URL
    let outside: String
    let block: [String]
  }

  private let fileManager = FileManager.default
  private let commandTimeout: TimeInterval = 300
  private var headless: Bool { CommandLine.arguments.contains("--headless") }

  static func main() {
    let installer = LegionInstaller()
    if installer.headless {
      installer.completeInstallation()
      return
    }
    let app = NSApplication.shared
    app.delegate = installer
    withExtendedLifetime(installer) { app.run() }
  }

  func applicationDidFinishLaunching(_ notification: Notification) {
    completeInstallation()
  }

  private func completeInstallation() {
    do {
      try install()
      if headless { log("installation complete"); exit(0) }
      show(title: "Legion installed", message: "Legion is ready in ~/Library/Application Support/Orthic Labs/Legion.", style: .informational)
    } catch {
      if headless { log(error.localizedDescription); exit(1) }
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
    let versionBackup = versions.appendingPathComponent(".previous-\(version)-\(UUID().uuidString)", isDirectory: true)
    let current = root.appendingPathComponent("current")
    let currentBackup = root.appendingPathComponent(".previous-current-\(UUID().uuidString)")
    let priorCurrentSupportsMarketplace: Bool = {
      let metadataURL = current.appendingPathComponent("share/legion/release.json")
      guard let data = try? Data(contentsOf: metadataURL),
            let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return false }
      return value["nativeMarketplaces"] != nil
    }()
    try fileManager.createDirectory(at: versions, withIntermediateDirectories: true)
    var candidateVersionInstalled = false
    var candidateCurrentInstalled = false
    var priorVersionBackedUp = false
    var priorCurrentBackedUp = false
    var legacyCodexSnapshot: LegacyCodexSnapshot?
    var codexDisabledIntent: CodexDisabledIntent?
    let replacement = root.appendingPathComponent(".current-\(UUID().uuidString)")
    do {
      codexDisabledIntent = try captureCodexDisabledIntent(home: home)
      legacyCodexSnapshot = try captureLegacyCodexProjection(home: home, installRoot: root)
      // Development installers can carry a newer candidate with the same version.
      // Keep the installed generation until setup migration and status both pass.
      try fileManager.copyItem(at: payload, to: temporary)
      // Preserve the stable pointer before moving a same-version directory;
      // otherwise current briefly becomes a dangling symlink and cannot be
      // recovered if candidate validation fails.
      let hasCurrent = fileManager.fileExists(atPath: current.path)
        || (try? fileManager.destinationOfSymbolicLink(atPath: current.path)) != nil
      if hasCurrent {
        try fileManager.moveItem(at: current, to: currentBackup)
        priorCurrentBackedUp = true
      }
      if fileManager.fileExists(atPath: final.path) {
        try fileManager.moveItem(at: final, to: versionBackup)
        priorVersionBackedUp = true
      }
      try fileManager.moveItem(at: temporary, to: final)
      candidateVersionInstalled = true

      try fileManager.createSymbolicLink(at: replacement, withDestinationURL: URL(fileURLWithPath: "versions/\(version)", relativeTo: root))
      try fileManager.moveItem(at: replacement, to: current)
      candidateCurrentInstalled = true

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

      if priorCurrentBackedUp { try? fileManager.removeItem(at: currentBackup) }
      if priorVersionBackedUp { try? fileManager.removeItem(at: versionBackup) }
      if let snapshot = legacyCodexSnapshot { try? fileManager.removeItem(at: snapshot.savedRoot.deletingLastPathComponent()) }
    } catch {
      let installError = error
      var rollbackErrors: [String] = []
      try? fileManager.removeItem(at: replacement)
      if !priorCurrentSupportsMarketplace, candidateCurrentInstalled {
        do {
          try runInstalledStep(binary: current.appendingPathComponent("bin/legion"), arguments: ["setup", "remove", "--confirm"], label: "rollback setup remove")
        } catch {
          rollbackErrors.append("remove candidate native registrations: \(error.localizedDescription)")
        }
      }
      // Keep candidate current & payload intact when native cleanup could not
      // be proven; its local marketplace source must remain available for retry.
      if rollbackErrors.contains(where: { $0.hasPrefix("remove candidate native registrations:") }) {
        throw InstallerError.transactionFailed("\(installError.localizedDescription) Rollback incomplete: \(rollbackErrors.joined(separator: "; "))")
      }
      if candidateCurrentInstalled {
        do { try fileManager.removeItem(at: current) }
        catch { rollbackErrors.append("remove candidate current: \(error.localizedDescription)") }
      }
      if candidateVersionInstalled {
        do { try fileManager.removeItem(at: final) }
        catch { rollbackErrors.append("remove candidate version: \(error.localizedDescription)") }
      }
      if priorVersionBackedUp {
        do { try fileManager.moveItem(at: versionBackup, to: final) }
        catch { rollbackErrors.append("restore prior version: \(error.localizedDescription)") }
      }
      if priorCurrentBackedUp {
        do { try fileManager.moveItem(at: currentBackup, to: current) }
        catch { rollbackErrors.append("restore prior current: \(error.localizedDescription)") }
      }
      try? fileManager.removeItem(at: temporary)

      if rollbackErrors.isEmpty, candidateCurrentInstalled, let snapshot = legacyCodexSnapshot {
        do { try restoreLegacyCodexProjection(snapshot) }
        catch { rollbackErrors.append("restore prior owned Codex projection: \(error.localizedDescription)") }
      }
      if rollbackErrors.isEmpty, candidateCurrentInstalled, let intent = codexDisabledIntent {
        do { try restoreCodexDisabledIntent(intent) }
        catch { rollbackErrors.append("restore prior Codex disabled choice: \(error.localizedDescription)") }
      }
      if rollbackErrors.isEmpty, priorCurrentBackedUp, fileManager.fileExists(atPath: current.path) {
        do {
          try runInstalledStep(binary: current.appendingPathComponent("bin/legion"), arguments: ["setup", "repair", "--confirm"], label: "rollback setup repair")
        } catch {
          rollbackErrors.append("restore native client registrations: \(error.localizedDescription)")
        }
      }
      if rollbackErrors.isEmpty, !candidateCurrentInstalled, let snapshot = legacyCodexSnapshot {
        try? fileManager.removeItem(at: snapshot.savedRoot.deletingLastPathComponent())
      }
      if rollbackErrors.isEmpty { throw installError }
      throw InstallerError.transactionFailed("\(installError.localizedDescription) Rollback issues: \(rollbackErrors.joined(separator: "; "))")
    }
  }

  private func captureLegacyCodexProjection(home: URL, installRoot: URL) throws -> LegacyCodexSnapshot? {
    let environment = ProcessInfo.processInfo.environment
    let stateRoot: URL
    if let configured = environment["LEGION_STATE_ROOT"], !configured.isEmpty {
      guard configured.hasPrefix("/") else { return nil }
      stateRoot = URL(fileURLWithPath: configured, isDirectory: true).standardizedFileURL
    } else {
      stateRoot = home.appendingPathComponent("Library/Application Support/Legion", isDirectory: true)
    }
    let target = home.appendingPathComponent(".codex/plugins/legion", isDirectory: true).standardizedFileURL
    let ledger = stateRoot.appendingPathComponent("integrations/projections/codex.json")
    guard fileManager.fileExists(atPath: ledger.path), fileManager.fileExists(atPath: target.path) else { return nil }
    guard try stateRoot.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink != true,
          try ledger.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink != true else { return nil }
    guard let ledgerValues = try? JSONSerialization.jsonObject(with: Data(contentsOf: ledger)) as? [String: Any],
          (ledgerValues["schemaVersion"] as? Int) == 1,
          ledgerValues["owner"] as? String == "legion-client-projection-v1",
          ledgerValues["clientId"] as? String == "codex",
          ledgerValues["projection"] as? String == "agent-plugins-with-explicit-sidecar",
          ledgerValues["origin"] as? String == "installed",
          ledgerValues["createdRoot"] as? Bool == true,
          let ledgerInstallRoot = ledgerValues["installRoot"] as? String,
          URL(fileURLWithPath: ledgerInstallRoot, isDirectory: true).standardizedFileURL.path == installRoot.standardizedFileURL.path,
          let targetValue = ledgerValues["targetRoot"] as? String,
          URL(fileURLWithPath: targetValue, isDirectory: true).standardizedFileURL.path == target.path,
          let rawDigests = ledgerValues["files"] as? [String: String],
          !rawDigests.isEmpty,
          rawDigests.values.allSatisfy({ $0.hasPrefix("sha256:") }) else { return nil }
    let digests = rawDigests.mapValues { value in
      value.hasPrefix("sha256:") ? String(value.dropFirst("sha256:".count)) : value
    }
    guard let links = try inspectLegacyCodexTree(target, installRoot: installRoot, digests: digests) else {
      throw InstallerError.transactionFailed("verified Codex ownership ledger has modified or unsupported content; preserving prior projection")
    }

    let backupRoot = installRoot.appendingPathComponent(".rollback-codex-\(UUID().uuidString)", isDirectory: true)
    let savedRoot = backupRoot.appendingPathComponent("codex-plugin", isDirectory: true)
    let savedLedger = backupRoot.appendingPathComponent("codex-projection-ledger.json")
    let ledgerBytes = try Data(contentsOf: ledger)
    do {
      try fileManager.createDirectory(at: backupRoot, withIntermediateDirectories: true)
      try copyLegacyCodexTree(from: target, to: savedRoot, links: links)
      try ledgerBytes.write(to: savedLedger, options: .atomic)
    } catch {
      try? fileManager.removeItem(at: backupRoot)
      throw error
    }
    return LegacyCodexSnapshot(target: target, installRoot: installRoot, ledger: ledger, savedRoot: savedRoot, savedLedger: savedLedger, ledgerBytes: ledgerBytes, digests: digests, links: links)
  }

  private func captureCodexDisabledIntent(home: URL) throws -> CodexDisabledIntent? {
    let environment = ProcessInfo.processInfo.environment
    let codexHome: URL
    if let configured = environment["CODEX_HOME"], configured.hasPrefix("/") {
      codexHome = URL(fileURLWithPath: configured, isDirectory: true).standardizedFileURL
    } else {
      codexHome = home.appendingPathComponent(".codex", isDirectory: true)
    }
    let config = codexHome.appendingPathComponent("config.toml")
    guard fileManager.fileExists(atPath: config.path),
          (try? config.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) != true,
          let text = try? String(contentsOf: config, encoding: .utf8),
          let parsed = codexPluginConfig(text), parsed.valid, parsed.state == "false" else { return nil }
    return CodexDisabledIntent(config: config, outside: parsed.outside, block: parsed.block)
  }

  private func codexPluginConfig(_ text: String) -> (valid: Bool, state: String, outside: String, block: [String])? {
    let lines = text.components(separatedBy: .newlines)
    let headers = lines.indices.filter {
      let line = lines[$0].trimmingCharacters(in: .whitespaces)
      guard let expression = try? NSRegularExpression(
        pattern: #"^\[\s*plugins\s*\.\s*(?:\"legion@legion-installed\"|legion@legion-installed)\s*\]$"#
      ) else { return false }
      let range = NSRange(line.startIndex..<line.endIndex, in: line)
      return expression.firstMatch(in: line, range: range) != nil
    }
    guard headers.count <= 1 else { return (false, "invalid", "", []) }
    guard let start = headers.first else { return (true, "absent", lines.joined(separator: "\n"), []) }
    let end = lines.indices.dropFirst(start + 1).first(where: {
      lines[$0].trimmingCharacters(in: .whitespaces).hasPrefix("[")
    }) ?? lines.count
    var enabled: [String] = []
    if start + 1 < end {
      for line in lines[(start + 1)..<end] {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard trimmed.range(of: #"^enabled\s*="#, options: .regularExpression) != nil else { continue }
        let assignment = trimmed.split(separator: "=", maxSplits: 1).map(String.init)
        guard assignment.count == 2 else { return (false, "invalid", "", []) }
        let value = assignment[1].split(separator: "#", maxSplits: 1).first?.trimmingCharacters(in: .whitespaces) ?? ""
        guard value == "true" || value == "false" else { return (false, "invalid", "", []) }
        enabled.append(value)
      }
    }
    guard enabled.count <= 1 else { return (false, "invalid", "", []) }
    let outside = lines.enumerated().filter { $0.offset < start || $0.offset >= end }.map(\.element).joined(separator: "\n")
    return (true, enabled.first ?? "absent", outside, Array(lines[start..<end]))
  }

  private func restoreCodexDisabledIntent(_ intent: CodexDisabledIntent) throws {
    guard fileManager.fileExists(atPath: intent.config.path),
          let text = try? String(contentsOf: intent.config, encoding: .utf8),
          let parsed = codexPluginConfig(text), parsed.valid else {
      throw InstallerError.transactionFailed("Codex plugin config is unavailable or ambiguous; preserving it")
    }
    if parsed.state == "false" { return }
    guard parsed.state == "absent", parsed.outside == intent.outside else {
      throw InstallerError.transactionFailed("Codex plugin enablement or unrelated config changed during activation; preserving current host state")
    }
    let newline = text.contains("\r\n") ? "\r\n" : "\n"
    let separator = text.isEmpty || text.hasSuffix("\n") ? "" : newline
    let updated = text + separator + intent.block.joined(separator: newline) + newline
    var attributes = try fileManager.attributesOfItem(atPath: intent.config.path)
    let temporary = intent.config.deletingLastPathComponent().appendingPathComponent(".config.toml.legion-rollback-\(UUID().uuidString)")
    try Data(updated.utf8).write(to: temporary, options: .atomic)
    attributes.removeValue(forKey: .type)
    try fileManager.setAttributes(attributes, ofItemAtPath: temporary.path)
    let fresh = try String(contentsOf: intent.config, encoding: .utf8)
    guard fresh == text else {
      try? fileManager.removeItem(at: temporary)
      throw InstallerError.transactionFailed("Codex config changed during rollback; preserving it")
    }
    _ = try fileManager.replaceItemAt(intent.config, withItemAt: temporary)
  }

  private func inspectLegacyCodexTree(_ root: URL, installRoot: URL, digests: [String: String]) throws -> [String: String]? {
    let rootValues = try root.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
    guard rootValues.isDirectory == true, rootValues.isSymbolicLink != true else { return nil }
    var seen = Set<String>()
    var links: [String: String] = [:]
    func visit(_ path: URL, relative: String, linkedSkillRoot: String? = nil) throws -> Bool {
      let values = try path.resourceValues(forKeys: [.isRegularFileKey, .isDirectoryKey, .isSymbolicLinkKey])
      if values.isSymbolicLink == true {
        guard linkedSkillRoot == nil,
              relative.split(separator: "/").count == 2,
              relative.hasPrefix("skills/") else { return false }
        let skillId = String(relative.dropFirst("skills/".count))
        guard !skillId.isEmpty, !skillId.contains("/") else { return false }
        let rawTarget = try fileManager.destinationOfSymbolicLink(atPath: path.path)
        let targetURL = URL(fileURLWithPath: rawTarget, relativeTo: path.deletingLastPathComponent()).standardizedFileURL
        let allowedCurrent = installRoot.appendingPathComponent("current/plugin/skills/\(skillId)").standardizedFileURL
        guard targetURL.path == allowedCurrent.path,
              fileManager.fileExists(atPath: targetURL.path),
              try targetURL.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey]).isDirectory == true else { return false }
        links[relative] = rawTarget
        return try visit(targetURL, relative: relative, linkedSkillRoot: relative)
      }
      if values.isDirectory == true {
        guard let children = try? fileManager.contentsOfDirectory(at: path, includingPropertiesForKeys: [.isRegularFileKey, .isDirectoryKey, .isSymbolicLinkKey]) else { return false }
        for child in children {
          let name = child.lastPathComponent
          if name == "." || name == ".." || name.contains("/") || name.contains("\\") { return false }
          if try visit(child, relative: relative.isEmpty ? name : "\(relative)/\(name)", linkedSkillRoot: linkedSkillRoot) == false { return false }
        }
        return true
      }
      guard values.isRegularFile == true,
            !relative.contains("\\"),
            !relative.split(separator: "/", omittingEmptySubsequences: false).contains(where: { $0 == "." || $0 == ".." }),
            let expected = digests[relative], seen.insert(relative).inserted else { return false }
      let actual = SHA256.hash(data: try Data(contentsOf: path)).map { String(format: "%02x", $0) }.joined()
      return actual == expected.lowercased()
    }
    guard try visit(root, relative: "") else { return nil }
    for relative in digests.keys {
      if relative.hasPrefix("/") || relative.contains("\\") || relative.split(separator: "/", omittingEmptySubsequences: false).contains(where: { $0 == "." || $0 == ".." }) { return nil }
      let candidate = root.appendingPathComponent(relative).standardizedFileURL
      if !candidate.path.hasPrefix(root.path + "/") { return nil }
    }
    return seen.count == digests.count ? links : nil
  }

  private func copyLegacyCodexTree(from source: URL, to destination: URL, links: [String: String]) throws {
    try fileManager.createDirectory(at: destination, withIntermediateDirectories: true)
    func copy(_ current: URL, relative: String) throws {
      if let target = links[relative] {
        try fileManager.createSymbolicLink(atPath: destination.appendingPathComponent(relative).path, withDestinationPath: target)
        return
      }
      let entries = try fileManager.contentsOfDirectory(at: current, includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey])
      for entry in entries {
        let childRelative = relative.isEmpty ? entry.lastPathComponent : "\(relative)/\(entry.lastPathComponent)"
        let childDestination = destination.appendingPathComponent(childRelative)
        let values = try entry.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        if values.isDirectory == true && values.isSymbolicLink != true {
          try fileManager.createDirectory(at: childDestination, withIntermediateDirectories: true)
          try copy(entry, relative: childRelative)
        } else {
          try fileManager.copyItem(at: entry, to: childDestination)
        }
      }
    }
    try copy(source, relative: "")
  }

  private func restoreLegacyCodexProjection(_ snapshot: LegacyCodexSnapshot) throws {
    let ledgerExists = fileManager.fileExists(atPath: snapshot.ledger.path)
    if ledgerExists, try Data(contentsOf: snapshot.ledger) != snapshot.ledgerBytes {
      throw InstallerError.transactionFailed("Codex projection ledger changed during candidate activation; preserving it")
    }
    if fileManager.fileExists(atPath: snapshot.target.path) {
      guard try inspectLegacyCodexTree(snapshot.target, installRoot: snapshot.installRoot, digests: snapshot.digests) == snapshot.links else {
        throw InstallerError.transactionFailed("Codex plugin root changed during candidate activation; preserving it")
      }
    } else {
      try fileManager.createDirectory(at: snapshot.target.deletingLastPathComponent(), withIntermediateDirectories: true)
      try copyLegacyCodexTree(from: snapshot.savedRoot, to: snapshot.target, links: snapshot.links)
    }
    if !ledgerExists {
      try fileManager.createDirectory(at: snapshot.ledger.deletingLastPathComponent(), withIntermediateDirectories: true)
      try snapshot.ledgerBytes.write(to: snapshot.ledger, options: .atomic)
    }
    guard try inspectLegacyCodexTree(snapshot.target, installRoot: snapshot.installRoot, digests: snapshot.digests) == snapshot.links,
          try Data(contentsOf: snapshot.ledger) == snapshot.ledgerBytes else {
      throw InstallerError.transactionFailed("Prior Codex projection restore did not verify")
    }
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
    case transactionFailed(String)
    case commandFailed(String, Int32, String)
    case commandTimedOut(String, Int, String)
    var errorDescription: String? {
      switch self {
      case .invalidVersion: return "Installer contains an invalid version."
      case .transactionFailed(let message): return "Legion installation failed: \(message)"
      case .commandFailed(let label, let status, let output): return "Legion \(label) exited with status \(status).\(output)"
      case .commandTimedOut(let label, let seconds, let output): return "Legion \(label) timed out after \(seconds) seconds.\(output)"
      }
    }
  }
}
