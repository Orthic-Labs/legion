#import <Foundation/Foundation.h>

NSInteger BridgeTotal(NSArray<NSNumber *> *prices) { return [[prices valueForKeyPath:@"@sum.self"] integerValue]; }
