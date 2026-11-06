#ifndef LOG_H
#define LOG_H
#include <stdio.h>
extern int g_verbose;
#define LOGI(...) do { fprintf(stderr, "[secgw] "); fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } while (0)
#define LOGE(...) do { fprintf(stderr, "[secgw][ERROR] "); fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } while (0)
#define LOGD(...) do { if (g_verbose) { fprintf(stderr, "[secgw][dbg] "); fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } } while (0)
#endif
