#import <Foundation/Foundation.h>
#include <vector>

NSInteger BridgeTotalCpp(const std::vector<int> &prices) { NSInteger sum = 0; for (int p : prices) sum += p; return sum; }
