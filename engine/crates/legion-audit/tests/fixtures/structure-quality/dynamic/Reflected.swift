import Foundation

final class ReflectedController: NSObject {
    @objc func selectorTarget() -> Int {
        return 7
    }

    func register() -> Selector {
        return #selector(selectorTarget)
    }
}
