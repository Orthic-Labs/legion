#include "buffer.h"

size_t buffer_len(const char *text) { return text ? strlen(text) : 0; }
