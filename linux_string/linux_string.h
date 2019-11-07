#include <stddef.h>

#ifndef LINUX_STRING
#define LINUX_STRING 1
size_t strlcat(char *dst, const char *src, size_t dsize);
size_t strlcpy(char *dst, const char *src, size_t dsize);
#endif
