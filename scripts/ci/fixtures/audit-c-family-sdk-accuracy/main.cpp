#include "common.h"
#include "detail.hpp"
int main() {
  if (c_value() != 10) return 1;
  if (cc_value() != 11) return 2;
  if (cxx_value() != 12) return 3;
  if (detail_value() != 13) return 4;
  return 0;
}
