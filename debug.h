#ifndef DEBUG_H
# define DEBUG_H

#define DEBUG_PREFIX    "### "

void increaseDebugLevel();
void disableDebug();
void debugLog(int level, const char* fmt, ...);
int isDebugLevel(int level);

#endif
