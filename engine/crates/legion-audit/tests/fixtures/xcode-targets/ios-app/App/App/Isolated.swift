import Foundation

@MainActor
final class Counter {
    private(set) var count = 0
    func bump() { count += 1 }
}

actor Ledger {
    private var total = 0
    func add(_ value: Int) { total += value }
}
