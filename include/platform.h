#ifndef PLATFORM_H
#define PLATFORM_H

// Platform-specific utilities and abstraction

#ifdef _WIN32
#define PLATFORM_WINDOWS
#else
#define PLATFORM_POSIX
#endif

#endif // PLATFORM_H
