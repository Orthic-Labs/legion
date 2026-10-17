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
  private let commandTimeout: TimeInterval = 600
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
    let current = root.appendingPathComponent("current")
    let previous = root.appendingPathComponent("current.previous", isDirectory: true)
    // Staging is never an executable installation root. Both activation &
    // rollback execute exclusively through the real, fixed current directory.
    let temporary = root.appendingPathComponent(".install-\(UUID().uuidString)", isDirectory: true)
    let candidate = temporary.appendingPathComponent("candidate", isDirectory: true)
    let priorCopy = temporary.appendingPathComponent("prior", isDirectory: true)
    let displacedCurrent = temporary.appendingPathComponent("displaced-current")
    let displacedPrevious = temporary.appendingPathComponent("displaced-previous")
    try fileManager.createDirectory(at: root, withIntermediateDirectories: true)
    guard try root.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink != true else {
      throw InstallerError.transactionFailed("installation root must be a real directory")
    }
    let lock = open(root.appendingPathComponent(".install.lock").path, O_CREAT | O_RDWR | O_NOFOLLOW, 0o600)
    guard lock >= 0 else { throw InstallerError.transactionFailed("cannot open installation lock") }
    defer { close(lock) }
    guard flock(lock, LOCK_EX | LOCK_NB) == 0 else {
      throw InstallerError.transactionFailed("another installation is already running")
    }
    let priorRoot = try installedPayloadRoot(current: current, root: root)
    let priorManifest = try priorRoot.map { try payloadManifest(at: $0) }
    let expectedManifest = try payloadManifest(at: payload)
    if itemExists(previous) { _ = try payloadManifest(at: previous) }
    let priorCurrentSupportsMarketplace: Bool = {
      let metadataURL = current.appendingPathComponent("share/legion/release.json")
      guard let data = try? Data(contentsOf: metadataURL),
            let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return false }
      return value["nativeMarketplaces"] != nil
    }()
    var candidateCurrentInstalled = false
    var candidateRegistrationAttempted = false
    var priorCurrentDetached = false
    var priorCopyPublished = false
    var previousDisplaced = false
    var legacyCodexSnapshot: LegacyCodexSnapshot?
    var codexDisabledIntent: CodexDisabledIntent?
    do {
      try fileManager.createDirectory(at: temporary, withIntermediateDirectories: false)
      codexDisabledIntent = try captureCodexDisabledIntent(home: home)
      legacyCodexSnapshot = try captureLegacyCodexProjection(home: home, installRoot: root, stagingRoot: temporary)
      try fileManager.copyItem(at: payload, to: candidate)
      try requirePayload(at: candidate, matching: expectedManifest)
      if let priorRoot, let priorManifest {
        // Copy the resolved legacy payload, never its current symlink. Keep
        // historical versions untouched; unknown files are not migration debris.
        try fileManager.copyItem(at: priorRoot, to: priorCopy)
        try requirePayload(at: priorCopy, matching: priorManifest)
        try requirePayload(at: priorRoot, matching: priorManifest)
        if itemExists(previous) {
          try fileManager.moveItem(at: previous, to: displacedPrevious)
          previousDisplaced = true
        }
        try fileManager.moveItem(at: priorCopy, to: previous)
        priorCopyPublished = true
        try fileManager.moveItem(at: current, to: displacedCurrent)
        priorCurrentDetached = true
      }
      try fileManager.moveItem(at: candidate, to: current)
      candidateCurrentInstalled = true
      try requirePayload(at: current, matching: expectedManifest)

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
      candidateRegistrationAttempted = true
      try runInstalledStep(binary: binary, arguments: ["setup", "repair", "--confirm"], label: "setup repair")
      try runInstalledStep(binary: binary, arguments: ["setup", "status"], label: "setup status")
      try runInstalledStep(binary: binary, arguments: ["doctor"], label: "doctor")
      try requirePayload(at: current, matching: expectedManifest)

      try? fileManager.removeItem(at: temporary)
    } catch {
      let installError = error
      var rollbackErrors: [String] = []
      if !priorCurrentSupportsMarketplace, candidateRegistrationAttempted {
        do {
          try runInstalledStep(binary: current.appendingPathComponent("bin/legion"), arguments: ["setup", "remove", "--confirm"], label: "rollback setup remove")
        } catch {
          rollbackErrors.append("remove candidate native registrations: \(error.localizedDescription)")
        }
      }
      // Keep candidate current & payload intact when native cleanup could not
      // be proven; its local marketplace source must remain available for retry.
      if rollbackErrors.contains(where: { $0.hasPrefix("remove candidate native registrations:") }) {
        if legacyCodexSnapshot == nil { try? fileManager.removeItem(at: temporary) }
        throw InstallerError.transactionFailed("\(installError.localizedDescription) Rollback incomplete: \(rollbackErrors.joined(separator: "; "))")
      }
      if candidateCurrentInstalled {
        do { try fileManager.removeItem(at: current) }
        catch { rollbackErrors.append("remove candidate current: \(error.localizedDescription)") }
      }
      if rollbackErrors.isEmpty, priorCurrentDetached, let priorManifest {
        do {
          // Recreate the prior real payload at current before restoring any
          // registrations. Never run a binary from current.previous or staging.
          let restored = temporary.appendingPathComponent("restored-current", isDirectory: true)
          try requirePayload(at: previous, matching: priorManifest)
          try fileManager.copyItem(at: previous, to: restored)
          try requirePayload(at: restored, matching: priorManifest)
          try fileManager.moveItem(at: restored, to: current)
          try requirePayload(at: current, matching: priorManifest)
        } catch { rollbackErrors.append("restore prior current: \(error.localizedDescription)") }
      } else if !priorCurrentDetached {
        // Nothing ran or changed at current. Undo only backup rotation.
        if priorCopyPublished {
          do { try fileManager.removeItem(at: previous) }
          catch { rollbackErrors.append("remove unactivated prior copy: \(error.localizedDescription)") }
        }
        if rollbackErrors.isEmpty, previousDisplaced {
          do { try fileManager.moveItem(at: displacedPrevious, to: previous) }
          catch { rollbackErrors.append("restore prior backup: \(error.localizedDescription)") }
        }
      }
      if rollbackErrors.isEmpty, candidateCurrentInstalled, let snapshot = legacyCodexSnapshot {
        do { try restoreLegacyCodexProjection(snapshot) }
        catch { rollbackErrors.append("restore prior owned Codex projection: \(error.localizedDescription)") }
      }
      if rollbackErrors.isEmpty, candidateCurrentInstalled, let intent = codexDisabledIntent {
        do { try restoreCodexDisabledIntent(intent) }
        catch { rollbackErrors.append("restore prior Codex disabled choice: \(error.localizedDescription)") }
      }
      if rollbackErrors.isEmpty, priorCurrentDetached, fileManager.fileExists(atPath: current.path) {
        do {
          try runInstalledStep(binary: current.appendingPathComponent("bin/legion"), arguments: ["setup", "repair", "--confirm"], label: "rollback setup repair")
        } catch {
          rollbackErrors.append("restore native client registrations: \(error.localizedDescription)")
        }
      }
      if rollbackErrors.isEmpty { try? fileManager.removeItem(at: temporary) }
      if rollbackErrors.isEmpty { throw installError }
      throw InstallerError.transactionFailed("\(installError.localizedDescription) Rollback issues: \(rollbackErrors.joined(separator: "; "))")
    }
  }

  private func itemExists(_ path: URL) -> Bool {
    fileManager.fileExists(atPath: path.path)
      || (try? fileManager.destinationOfSymbolicLink(atPath: path.path)) != nil
  }

  private func installedPayloadRoot(current: URL, root: URL) throws -> URL? {
    guard itemExists(current) else { return nil }
    guard try current.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink == true else { return current }
    let destination = try fileManager.destinationOfSymbolicLink(atPath: current.path)
    let legacy = URL(fileURLWithPath: destination, relativeTo: root).standardizedFileURL
    let versions = root.appendingPathComponent("versions", isDirectory: true).standardizedFileURL
    guard legacy.deletingLastPathComponent().path == versions.path,
          legacy.resolvingSymlinksInPath().path == legacy.path else {
      throw InstallerError.transactionFailed("current points outside an owned legacy version directory; preserving it")
    }
    return legacy
  }

  // Include directories, bytes & modes so same-version replacements, truncated
  // copies, unexpected files & unsafe links cannot silently pass activation.
  private func payloadManifest(at root: URL) throws -> [String: String] {
    var manifest: [String: String] = [:]
    func visit(_ path: URL, relative: String) throws {
      let attributes = try fileManager.attributesOfItem(atPath: path.path)
      let kind = attributes[.type] as? FileAttributeType
      let mode = (attributes[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
      if kind == .typeDirectory {
        manifest[relative] = "directory:\(mode)"
        for child in try fileManager.contentsOfDirectory(at: path, includingPropertiesForKeys: nil) {
          try visit(child, relative: relative.isEmpty ? child.lastPathComponent : "\(relative)/\(child.lastPathComponent)")
        }
      } else if kind == .typeRegular {
        let digest = SHA256.hash(data: try Data(contentsOf: path, options: .mappedIfSafe)).map { String(format: "%02x", $0) }.joined()
        manifest[relative] = "file:\(mode):\(digest)"
      } else {
        throw InstallerError.transactionFailed("payload contains an unsupported file or symbolic link: \(path.path)")
      }
    }
    try visit(root, relative: "")
    for directory in ["", "bin", "plugin", "share"] {
      guard manifest[directory]?.hasPrefix("directory:") == true else {
        throw InstallerError.transactionFailed("payload is missing directory \(directory)")
      }
    }
    for executable in ["legion", "legion-hook", "legion-mcp"] {
      guard manifest["bin/\(executable)"]?.hasPrefix("file:") == true,
            fileManager.isExecutableFile(atPath: root.appendingPathComponent("bin/\(executable)").path) else {
        throw InstallerError.transactionFailed("payload is missing executable bin/\(executable)")
      }
    }
    return manifest
  }

  private func requirePayload(at root: URL, matching manifest: [String: String]) throws {
    guard try payloadManifest(at: root) == manifest else {
      throw InstallerError.transactionFailed("payload changed or copy did not verify: \(root.path)")
    }
  }

  private func captureLegacyCodexProjection(home: URL, installRoot: URL, stagingRoot: URL) throws -> LegacyCodexSnapshot? {
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

    let backupRoot = stagingRoot.appendingPathComponent("codex-snapshot", isDirectory: true)
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
      let bytes = try Data(contentsOf: path)
      let canonicalBytes = "[" + bytes.map { String($0) }.joined(separator: ",") + "]"
      let actual = SHA256.hash(data: Data(canonicalBytes.utf8)).map { String(format: "%02x", $0) }.joined()
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
