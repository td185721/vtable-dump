// term.hpp — optional ANSI colors for terminal output.
//
// Colors are only used when stdout is a terminal (or --color=always), and
// never when NO_COLOR is set, so piped output and scripts see plain text.
// On Windows the console's virtual terminal mode is switched on; the few
// kernel32 functions needed are declared here so <windows.h> stays out.

#pragma once

#include <cstdio>
#include <cstdlib>
#include <cstring>

#if defined(_WIN32)
#include <io.h>
extern "C" {
__declspec(dllimport) void* __stdcall GetStdHandle(unsigned long std_handle);
__declspec(dllimport) int __stdcall GetConsoleMode(void* console, unsigned long* mode);
__declspec(dllimport) int __stdcall SetConsoleMode(void* console, unsigned long mode);
__declspec(dllimport) unsigned int __stdcall GetConsoleOutputCP(void);
__declspec(dllimport) int __stdcall SetConsoleOutputCP(unsigned int code_page);
}
#else
#include <unistd.h>
#endif

namespace term {

enum class Mode { Auto, Always, Never };

inline bool g_enabled = false;

inline bool stdout_is_terminal() {
#if defined(_WIN32)
    return _isatty(_fileno(stdout)) != 0;
#else
    return isatty(fileno(stdout)) != 0;
#endif
}

// Windows 10+ consoles interpret ANSI sequences once virtual terminal
// processing is enabled. Returns false if stdout is not a console.
inline bool enable_vt() {
#if defined(_WIN32)
    void* out = GetStdHandle(static_cast<unsigned long>(-11));  // STD_OUTPUT_HANDLE
    unsigned long mode = 0;
    if (!GetConsoleMode(out, &mode)) return false;
    return SetConsoleMode(out, mode | 0x0004) != 0;  // ENABLE_VIRTUAL_TERMINAL_PROCESSING
#else
    return true;
#endif
}

// True if the environment variable is set to a non-empty value.
inline bool env_set(const char* name) {
#if defined(_MSC_VER)
    char* value = nullptr;
    std::size_t len = 0;
    if (_dupenv_s(&value, &len, name) != 0 || !value) return false;
    const bool set = *value != 0;
    std::free(value);
    return set;
#else
    const char* value = std::getenv(name);
    return value && *value;
#endif
}

inline void init(Mode mode) {
    if (mode == Mode::Never) {
        g_enabled = false;
    } else if (mode == Mode::Always) {
        enable_vt();
        g_enabled = true;
    } else {
        g_enabled = stdout_is_terminal() && !env_set("NO_COLOR") && enable_vt();
    }
}

// Output that uses UTF-8 (e.g. box-drawing characters) needs the UTF-8
// code page on a Windows console; the previous one is restored at exit.
inline void utf8_console() {
#if defined(_WIN32)
    static unsigned int saved = 0;
    if (saved || !stdout_is_terminal()) return;
    saved = GetConsoleOutputCP();
    if (saved != 65001 && SetConsoleOutputCP(65001)) {
        std::atexit([] { SetConsoleOutputCP(saved); });
    }
#endif
}

// Recognizes "--color WHEN" and "--color=WHEN". Returns 1 if argv[i] was the
// flag (advancing i past a separate value), 0 if not, -1 on a bad value.
inline int parse_flag(int argc, char** argv, int& i, Mode& mode) {
    const char* value = nullptr;
    if (std::strcmp(argv[i], "--color") == 0) {
        if (i + 1 >= argc) return -1;
        value = argv[++i];
    } else if (std::strncmp(argv[i], "--color=", 8) == 0) {
        value = argv[i] + 8;
    } else {
        return 0;
    }
    if (std::strcmp(value, "auto") == 0) mode = Mode::Auto;
    else if (std::strcmp(value, "always") == 0) mode = Mode::Always;
    else if (std::strcmp(value, "never") == 0) mode = Mode::Never;
    else return -1;
    return 1;
}

// SGR sequences; each returns "" when colors are off.
inline const char* sgr(const char* seq) { return g_enabled ? seq : ""; }
inline const char* reset()   { return sgr("\x1b[0m"); }
inline const char* bold()    { return sgr("\x1b[1m"); }
inline const char* dim()     { return sgr("\x1b[2m"); }
inline const char* red()     { return sgr("\x1b[31m"); }
inline const char* green()   { return sgr("\x1b[32m"); }
inline const char* yellow()  { return sgr("\x1b[33m"); }
inline const char* blue()    { return sgr("\x1b[34m"); }
inline const char* magenta() { return sgr("\x1b[35m"); }
inline const char* cyan()    { return sgr("\x1b[36m"); }

}  // namespace term
