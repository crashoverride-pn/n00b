/**
 * @file platform.h
 * @brief Cross-platform abstractions for the base library.
 *
 * Centralizes platform detection and provides portable types/functions
 * for threads, TLS, sleep, clock, and sockets.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
// ============================================================================
// Platform detection
// ============================================================================

#if defined(_WIN32) || defined(_WIN64)
#define BASE_PLATFORM_WINDOWS 1  /**< Defined when targeting Windows. */
#elif defined(__APPLE__) && defined(__MACH__)
#define BASE_PLATFORM_MACOS   1  /**< Defined when targeting macOS. */
#elifdef __linux__
#define BASE_PLATFORM_LINUX   1  /**< Defined when targeting Linux. */
#else
#error "Unsupported platform"
#endif

#if defined(__aarch64__) || defined(_M_ARM64)
#define BASE_ARCH_ARM64  1  /**< Defined when targeting ARM64 (AArch64). */
#elif defined(__x86_64__) || defined(_M_X64)
#define BASE_ARCH_X86_64 1  /**< Defined when targeting x86-64. */
#else
#error "Unsupported architecture"
#endif

/** @brief Default memory alignment (16 bytes). */
#define BASE_ALIGN 16

#ifdef BASE_PLATFORM_WINDOWS

// ============================================================================
// Windows
// ============================================================================

// Keep Windows SDK headers out of public n00b headers. The ncc parser sees
// preprocessed headers, and windows.h pulls in compiler intrinsic headers that
// are not part of n00b's supported source grammar. The declarations below cover
// the small Win32 surface used by inline runtime helpers.
typedef unsigned long DWORD;
typedef unsigned long ULONG;
typedef long          LONG;
typedef unsigned short USHORT;
typedef unsigned char  BOOLEAN;
typedef int           BOOL;
typedef void         *HANDLE;
typedef void         *PVOID;
typedef uintptr_t     UINT_PTR;
typedef uintptr_t     ULONG_PTR;
typedef size_t        SIZE_T;

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif
#ifndef INFINITE
#define INFINITE 0xffffffffUL
#endif
#ifndef ERROR_TIMEOUT
#define ERROR_TIMEOUT 1460L
#endif

#define MEM_COMMIT              0x00001000UL
#define MEM_RESERVE             0x00002000UL
#define MEM_RELEASE             0x00008000UL
#define PAGE_NOACCESS           0x01UL
#define PAGE_READONLY           0x02UL
#define PAGE_READWRITE          0x04UL
#define PAGE_WRITECOPY          0x08UL
#define PAGE_EXECUTE            0x10UL
#define PAGE_EXECUTE_READ       0x20UL
#define PAGE_EXECUTE_READWRITE  0x40UL
#define PAGE_EXECUTE_WRITECOPY  0x80UL

typedef union _LARGE_INTEGER {
    struct {
        DWORD LowPart;
        long  HighPart;
    };
    long long QuadPart;
} LARGE_INTEGER;

typedef struct _SYSTEM_INFO {
    union {
        DWORD dwOemId;
        struct {
            unsigned short wProcessorArchitecture;
            unsigned short wReserved;
        };
    };
    DWORD     dwPageSize;
    void     *lpMinimumApplicationAddress;
    void     *lpMaximumApplicationAddress;
    ULONG_PTR dwActiveProcessorMask;
    DWORD     dwNumberOfProcessors;
    DWORD     dwProcessorType;
    DWORD     dwAllocationGranularity;
    unsigned short wProcessorLevel;
    unsigned short wProcessorRevision;
} SYSTEM_INFO;

typedef struct _MEMORY_BASIC_INFORMATION {
    void  *BaseAddress;
    void  *AllocationBase;
    DWORD  AllocationProtect;
    SIZE_T RegionSize;
    DWORD  State;
    DWORD  Protect;
    DWORD  Type;
} MEMORY_BASIC_INFORMATION;

typedef struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} FILETIME;

typedef struct _NT_TIB {
    void           *ExceptionList;
    void           *StackBase;
    void           *StackLimit;
    void           *SubSystemTib;
    void           *FiberData;
    void           *ArbitraryUserPointer;
    struct _NT_TIB *Self;
} NT_TIB;

void   *VirtualAlloc(void *addr, SIZE_T size, DWORD allocation_type, DWORD protect);
BOOL    VirtualFree(void *addr, SIZE_T size, DWORD free_type);
SIZE_T  VirtualQuery(const void *addr, MEMORY_BASIC_INFORMATION *buffer, SIZE_T len);
void    GetSystemInfo(SYSTEM_INFO *info);
DWORD   GetCurrentThreadId(void);
DWORD   GetCurrentProcessId(void);
DWORD   FlsAlloc(void *callback);
void   *FlsGetValue(DWORD key);
BOOL    FlsSetValue(DWORD key, void *value);
void    Sleep(DWORD ms);
unsigned long long GetTickCount64(void);
void    GetSystemTimeAsFileTime(FILETIME *time);
BOOL    QueryPerformanceFrequency(LARGE_INTEGER *freq);
BOOL    QueryPerformanceCounter(LARGE_INTEGER *count);
BOOL    WaitOnAddress(volatile void *address, void *compare_address, SIZE_T address_size, DWORD ms);
void    WakeByAddressAll(void *address);
void    WakeByAddressSingle(void *address);
DWORD   GetLastError(void);
BOOLEAN SystemFunction036(void *buffer, ULONG len);

#define RtlGenRandom SystemFunction036

#if defined(__x86_64__) || defined(_M_X64)
static inline NT_TIB *
NtCurrentTeb(void)
{
    void *teb;
    __asm__ volatile("movq %%gs:0x30, %0" : "=r"(teb));
    return (NT_TIB *)teb;
}
#endif

typedef intptr_t ssize_t;

/** @brief Thread identifier type (Windows). */
typedef DWORD  base_thread_id_t;

/** @brief Thread handle type (Windows). */
typedef HANDLE base_thread_handle_t;

/** @brief Thread-local storage key type (Windows FLS). */
typedef DWORD base_tls_key_t;

/**
 * @brief Retrieve the value stored in a TLS slot.
 *
 * @param key  TLS key created by the platform TLS API.
 * @return Pointer to the thread-local value, or @c nullptr if not set.
 */
static inline void *
base_tls_get(base_tls_key_t key)
{
    return FlsGetValue(key);
}

/**
 * @brief Store a value in a TLS slot.
 *
 * @param key    TLS key created by the platform TLS API.
 * @param value  Pointer to store as the thread-local value.
 */
static inline void
base_tls_set(base_tls_key_t key, void *value)
{
    FlsSetValue(key, value);
}

/** @brief One-time initialization type (Windows). */
typedef void *base_once_t;

/** @brief Static initializer for @ref base_once_t. */
#define BASE_ONCE_INIT nullptr

/** @brief Process identifier type (Windows). */
typedef DWORD base_pid_t;

/**
 * @brief Sleep for the specified number of nanoseconds.
 *
 * On Windows the actual granularity is milliseconds.
 *
 * @param ns  Duration in nanoseconds.
 */
static inline void
base_nanosleep_ns(uint64_t ns)
{
    Sleep((DWORD)(ns / 1000000));
}

/**
 * @brief Get a monotonic timestamp in milliseconds.
 *
 * @return Monotonic time in milliseconds.
 */
static inline uint64_t
base_monotonic_ms(void)
{
    return GetTickCount64();
}

/**
 * @brief Get a monotonic timestamp in nanoseconds.
 *
 * @return Monotonic time in nanoseconds.
 */
static inline uint64_t
base_monotonic_ns(void)
{
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (uint64_t)((double)count.QuadPart / freq.QuadPart * 1000000000.0);
}

/** @brief Socket descriptor type (matches Windows SOCKET = UINT_PTR). */
typedef UINT_PTR base_socket_t;

/** @brief Invalid socket sentinel value (matches INVALID_SOCKET). */
#define BASE_INVALID_SOCKET ((base_socket_t)~0)

/**
 * @brief Close a socket descriptor.
 *
 * Calls the Winsock closesocket() function. Callers using sockets
 * must link against ws2_32.
 *
 * @param s  Socket to close.
 * @return 0 on success, or a socket error code.
 */
int __attribute__((__stdcall__)) closesocket(base_socket_t);

static inline int
base_closesocket(base_socket_t s)
{
    return closesocket(s);
}

#else

// ============================================================================
// POSIX (Linux + macOS)
// ============================================================================

#include <pthread.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/* WP-001 Phase 3 / D-021 co-fix (amends D-011): on a raw OS worker the
 * thread-pointer register holds n00b's minimal TSD block, not a real
 * libpthread `pthread_t`, so `pthread_self()` faults — on macOS arm64 it
 * loads a pointer-authenticated self pointer at `[TPIDRRO_EL0 - 0xE0]` and
 * `brk`s when the PAC check fails, which a minimal TCB cannot satisfy
 * without standing up libpthread.  The conduit publisher reaches
 * `base_current_thread_id()` on the IO worker, so the identifier must be
 * obtainable WITHOUT touching libpthread/TSD-PAC.  We therefore make the
 * id an OS-native, TSD-free kernel thread id (a small integer token used
 * only for equality), replacing the `pthread_t`/`pthread_self()` pair.
 * This also advances D-011's tracked removal of these wrappers. */
typedef uint64_t base_thread_id_t;

/** @brief Thread handle type (POSIX). */
typedef pthread_t base_thread_handle_t;

/** @brief Thread-local storage key type (POSIX). */
typedef pthread_key_t base_tls_key_t;

/**
 * @brief Retrieve the value stored in a TLS slot.
 *
 * @param key  TLS key created via @c pthread_key_create.
 * @return Pointer to the thread-local value, or @c nullptr if not set.
 */
static inline void *
base_tls_get(base_tls_key_t key)
{
    return pthread_getspecific(key);
}

/**
 * @brief Store a value in a TLS slot.
 *
 * @param key    TLS key created via @c pthread_key_create.
 * @param value  Pointer to store as the thread-local value.
 */
static inline void
base_tls_set(base_tls_key_t key, void *value)
{
    pthread_setspecific(key, value);
}

/** @brief One-time initialization type (POSIX). */
typedef pthread_once_t base_once_t;

/** @brief Static initializer for @ref base_once_t. */
#define BASE_ONCE_INIT PTHREAD_ONCE_INIT

/** @brief Process identifier type (POSIX). */
typedef pid_t base_pid_t;

/**
 * @brief Sleep for the specified number of nanoseconds.
 *
 * @param ns  Duration in nanoseconds.
 */
static inline void
base_nanosleep_ns(uint64_t ns)
{
    struct timespec ts = {
        .tv_sec  = (time_t)(ns / 1000000000ULL),
        .tv_nsec = (long)(ns % 1000000000ULL),
    };
    nanosleep(&ts, nullptr);
}

/**
 * @brief Get a monotonic timestamp in milliseconds.
 *
 * @return Monotonic time in milliseconds.
 */
static inline uint64_t
base_monotonic_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/**
 * @brief Get a monotonic timestamp in nanoseconds.
 *
 * @return Monotonic time in nanoseconds.
 */
static inline uint64_t
base_monotonic_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/** @brief Socket descriptor type (POSIX file descriptor). */
typedef int base_socket_t;

/** @brief Invalid socket sentinel value. */
#define BASE_INVALID_SOCKET (-1)

/**
 * @brief Close a socket descriptor.
 *
 * @param s  Socket file descriptor to close.
 * @return 0 on success, -1 on error.
 */
static inline int
base_closesocket(base_socket_t s)
{
    return close(s);
}

#endif // _WIN32

// ============================================================================
// Common thread helpers
// ============================================================================

/**
 * @brief Get the current thread's identifier.
 *
 * @return The calling thread's ID.
 */
static inline base_thread_id_t
base_current_thread_id(void)
{
#ifdef BASE_PLATFORM_WINDOWS
    return (base_thread_id_t)GetCurrentThreadId();
#else
    // OS-native, TSD-free kernel thread id (D-021 co-fix; see the typedef).
    // A raw worker has no libpthread TCB, so pthread_self() faults; the
    // kernel thread-id syscall reads nothing through the thread pointer and
    // yields a unique, equality-comparable token on every thread (main +
    // raw workers).  macOS: thread_selfid; Linux/other POSIX: gettid.
#if defined(BASE_PLATFORM_MACOS)
    return (base_thread_id_t)syscall(SYS_thread_selfid);
#else
    return (base_thread_id_t)syscall(SYS_gettid);
#endif
#endif
}

/**
 * @brief Compare two thread identifiers for equality.
 *
 * @param a  First thread ID.
 * @param b  Second thread ID.
 * @return @c true if the IDs refer to the same thread.
 */
static inline bool
base_thread_id_equal(base_thread_id_t a, base_thread_id_t b)
{
    // base_thread_id_t is now an integer kernel thread-id token on every
    // platform (D-021 co-fix), so equality is a plain integer compare —
    // no pthread_equal (which would dereference a libpthread TCB a raw
    // worker does not have).
    return a == b;
}

// ============================================================================
// Page size
// ============================================================================

/**
 * @brief Get the system memory page size.
 *
 * @return Page size in bytes.
 */
static inline size_t
base_page_size(void)
{
#ifdef BASE_PLATFORM_WINDOWS
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwPageSize;
#else
    return (size_t)sysconf(_SC_PAGESIZE);
#endif
}
