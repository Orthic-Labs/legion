import XCTest

final class AppTests: XCTestCase {
    func testCounterStartsAtZero() async {
        let counter = await Counter()
        let value = await counter.count
        XCTAssertEqual(value, 0)
    }
}
