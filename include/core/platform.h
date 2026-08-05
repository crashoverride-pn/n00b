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

#if defined(_WINDOWS)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif
#ifndef NOMINMAX
#define NOMINMAX 1
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#ifndef RtlGenRandom
BOOLEAN SystemFunction036(PVOID buffer, ULONG len);
#define RtlGenRandom SystemFunction036
#endif

#else

// Keep Windows SDK headers out of public n00b headers. The ncc parser sees
// preprocessed headers, and windows.h pulls in compiler intrinsic headers that
// are not part of n00b's supported source grammar. The declarations below cover
// the small Win32 surface used by inline runtime helpers.
typedef unsigned long DWORD;
typedef unsigned long ULONG;
typedef long          LONG;
typedef unsigned short USHORT;
typedef unsigned short WORD;
typedef unsigned char  BOOLEAN;
typedef int           BOOL;
typedef unsigned int  UINT;
typedef LONG          HRESULT;
typedef void         *HANDLE;
typedef HANDLE        HMODULE;
typedef void         *LPVOID;
typedef void         *PVOID;
typedef void         *FARPROC;
typedef uintptr_t     UINT_PTR;
typedef uintptr_t     ULONG_PTR;
typedef uintptr_t     DWORD_PTR;
typedef uint64_t      DWORD64;
typedef size_t        SIZE_T;

#ifndef WINAPI
#define WINAPI __stdcall
#endif

typedef DWORD(WINAPI *LPTHREAD_START_ROUTINE)(LPVOID);

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif
#ifndef INFINITE
#define INFINITE 0xffffffffUL
#endif
#ifndef WAIT_OBJECT_0
#define WAIT_OBJECT_0 0UL
#endif
#ifndef ERROR_TIMEOUT
#define ERROR_TIMEOUT 1460L
#endif
#ifndef CP_UTF8
#define CP_UTF8 65001u
#endif
#ifndef THREAD_PRIORITY_IDLE
#define THREAD_PRIORITY_IDLE -15
#endif
#ifndef THREAD_PRIORITY_BELOW_NORMAL
#define THREAD_PRIORITY_BELOW_NORMAL -1
#endif
#ifndef THREAD_PRIORITY_NORMAL
#define THREAD_PRIORITY_NORMAL 0
#endif
#ifndef THREAD_PRIORITY_ABOVE_NORMAL
#define THREAD_PRIORITY_ABOVE_NORMAL 1
#endif
#ifndef THREAD_PRIORITY_TIME_CRITICAL
#define THREAD_PRIORITY_TIME_CRITICAL 15
#endif
#ifndef THREAD_GET_CONTEXT
#define THREAD_GET_CONTEXT 0x0008UL
#endif
#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME 0x0002UL
#endif
#ifndef CREATE_SUSPENDED
#define CREATE_SUSPENDED 0x00000004UL
#endif

#if defined(__x86_64__) || defined(_M_X64)
#ifndef CONTEXT_AMD64
#define CONTEXT_AMD64 0x00100000UL
#endif
#ifndef CONTEXT_CONTROL
#define CONTEXT_CONTROL (CONTEXT_AMD64 | 0x00000001UL)
#endif
#ifndef CONTEXT_INTEGER
#define CONTEXT_INTEGER (CONTEXT_AMD64 | 0x00000002UL)
#endif
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

#if defined(__x86_64__) || defined(_M_X64)
typedef struct _CONTEXT {
    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;
    DWORD   ContextFlags;
    DWORD   MxCsr;
    WORD    SegCs;
    WORD    SegDs;
    WORD    SegEs;
    WORD    SegFs;
    WORD    SegGs;
    WORD    SegSs;
    DWORD   EFlags;
    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;
    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;
    DWORD64 Rip;
} CONTEXT;
#endif

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
BOOL    VirtualProtect(void *addr, SIZE_T size, DWORD new_protect, DWORD *old_protect);
void    GetSystemInfo(SYSTEM_INFO *info);
HANDLE  GetCurrentThread(void);
DWORD   GetCurrentThreadId(void);
DWORD   GetCurrentProcessId(void);
HMODULE LoadLibraryA(const char *file_name);
BOOL    FreeLibrary(HMODULE module);
FARPROC GetProcAddress(HMODULE module, const char *proc_name);
HANDLE  OpenThread(DWORD desired_access, BOOL inherit_handle, DWORD thread_id);
DWORD   SuspendThread(HANDLE thread);
DWORD   ResumeThread(HANDLE thread);
BOOL    GetThreadContext(HANDLE thread, CONTEXT *context);
HANDLE  CreateThread(void *attributes, SIZE_T stack_size, LPTHREAD_START_ROUTINE start,
                     void *parameter, DWORD creation_flags, DWORD *thread_id);
void    ExitThread(DWORD exit_code);
DWORD   WaitForSingleObject(HANDLE handle, DWORD milliseconds);
BOOL    CloseHandle(HANDLE object);
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
int     MultiByteToWideChar(UINT code_page, DWORD flags, const char *mbstr, int cb_mb,
                            wchar_t *wstr, int cch_wstr);
HRESULT SetThreadDescription(HANDLE thread, const wchar_t *description);
BOOL    SetThreadPriority(HANDLE thread, int priority);
DWORD_PTR SetThreadAffinityMask(HANDLE thread, DWORD_PTR mask);
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

#endif

#ifndef N00B_SSIZE_T_DEFINED
typedef intptr_t ssize_t;
#define N00B_SSIZE_T_DEFINED 1
#endif

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
// Defined in src/core/thread.c.  Backed by the n00b futex abstraction
// (WaitOnAddress on Windows), NOT a raw sleep.
void base_nanosleep_ns(uint64_t ns);

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
#if !defined(_WINDOWS)
int __attribute__((__stdcall__)) closesocket(base_socket_t);
#endif

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
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "core/syscall.h"

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
// Defined in src/core/thread.c.  Backed by the n00b futex abstraction, NOT libc
// nanosleep: nanosleep is a pthread cancellation point that derefs the thread's
// libpthread TSD, which n00b's raw-OS-thread workers do not have -> SIGSEGV.
void base_nanosleep_ns(uint64_t ns);

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
    // syscall(2) is deprecated on macOS; call the underlying libsystem_kernel
    // stub directly.  It's a bare syscall wrapper that touches no thread-local
    // state, so it stays safe for raw workers with no libpthread TCB.
    extern uint64_t __thread_selfid(void);
    return (base_thread_id_t)__thread_selfid();
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
