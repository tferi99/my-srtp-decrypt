#include <stdio.h>
#include <stdarg.h>

#include "debug.h"

static int debugLevel = 0;

void increaseDebugLevel() {
    debugLevel++;
}

void disableDebug() {
    debugLevel = 0;
}

void debugLog(int level, const char* fmt, ...)
{
    if (debugLevel < level) {
        return;
    }
    va_list args;
    va_start(args, fmt);

    fprintf(stderr, DEBUG_PREFIX);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");

    va_end(args);
    fflush(stderr);
}

int isDebugLevel(int level) {
    return debugLevel >= level ? 1 : 0;
}
