#include <numeric>
#include <vector>

int total(const std::vector<int> &prices) { return std::accumulate(prices.begin(), prices.end(), 0); }
