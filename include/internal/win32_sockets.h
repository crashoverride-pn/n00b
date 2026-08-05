/**
 * @file win32_sockets.h
 * @brief Minimal Winsock declarations used by Windows-only n00b sources.
 *
 * Full Windows SDK headers pull in compiler intrinsic headers that ncc does
 * not parse.  This header declares the small ABI surface needed by the WSA
 * conduit backend and its Windows smoke test.
 */
#pragma once

#if defined(_WIN32)

#if defined(_WINDOWS)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif
#ifndef NOMINMAX
#define NOMINMAX 1
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <afunix.h>
#include <windows.h>
#include <io.h>

#ifndef N00B_SOCKLEN_T_DEFINED
#define N00B_SOCKLEN_T_DEFINED
typedef int socklen_t;
#endif

#ifndef gai_strerror
#define gai_strerror gai_strerrorA
#endif

#else

#include "core/platform.h"

#include <stddef.h>
#include <stdint.h>

intptr_t __attribute__((__cdecl__)) _get_osfhandle(int file_handle);
wchar_t *__attribute__((__cdecl__)) wcsncpy(wchar_t *dest,
                                            const wchar_t *src,
                                            size_t count);
wchar_t *__attribute__((__cdecl__)) wcsrchr(const wchar_t *str, wchar_t ch);
size_t __attribute__((__cdecl__)) wcslen(const wchar_t *str);
unsigned short __attribute__((__cdecl__)) towlower(unsigned short c);

typedef unsigned char  u_char;
typedef unsigned short u_short;
typedef unsigned int   u_int;
typedef unsigned long  u_long;
typedef unsigned short WORD;
typedef LONG           HRESULT;
typedef ULONG_PTR      DWORD_PTR;

typedef UINT_PTR SOCKET;

#ifndef N00B_SOCKLEN_T_DEFINED
#define N00B_SOCKLEN_T_DEFINED
typedef int socklen_t;
#endif

#define INVALID_SOCKET ((SOCKET)(~(UINT_PTR)0))
#define SOCKET_ERROR   (-1)

#define AF_UNSPEC   0
#define AF_UNIX     1
#define AF_INET     2
#define AF_INET6    23
#define SOCK_STREAM 1
#define SOCK_DGRAM  2
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define INADDR_LOOPBACK 0x7f000001UL
#define INADDR_ANY      0x00000000UL

#define FIONBIO 0x8004667eUL

#define SOL_SOCKET   0xffff
#define SO_REUSEADDR 0x0004
#define SO_RCVTIMEO  0x1006
#define SO_ERROR     0x1007
#define SO_TYPE      0x1008

#define WSAEINVAL       10022
#define WSAEINTR        10004
#define WSAEACCES       10013
#define WSAEWOULDBLOCK  10035
#define WSAEINPROGRESS  10036
#define WSAESOCKTNOSUPPORT 10044
#define WSAEAFNOSUPPORT 10047
#define WSAEADDRINUSE   10048
#define WSAECONNRESET   10054
#define WSAETIMEDOUT    10060
#define WSAECONNREFUSED 10061
#define WSAHOST_NOT_FOUND 11001
#define WSATRY_AGAIN     11002
#define WSANO_RECOVERY   11003
#define WSANO_DATA       11004
#define WSATYPE_NOT_FOUND 10109
#define WSA_NOT_ENOUGH_MEMORY 8

#ifndef EAI_AGAIN
#define EAI_AGAIN WSATRY_AGAIN
#endif
#ifndef EAI_BADFLAGS
#define EAI_BADFLAGS WSAEINVAL
#endif
#ifndef EAI_FAIL
#define EAI_FAIL WSANO_RECOVERY
#endif
#ifndef EAI_FAMILY
#define EAI_FAMILY WSAEAFNOSUPPORT
#endif
#ifndef EAI_MEMORY
#define EAI_MEMORY WSA_NOT_ENOUGH_MEMORY
#endif
#ifndef EAI_NONAME
#define EAI_NONAME WSAHOST_NOT_FOUND
#endif
#ifndef EAI_NODATA
#define EAI_NODATA WSANO_DATA
#endif
#ifndef EAI_SERVICE
#define EAI_SERVICE WSATYPE_NOT_FOUND
#endif
#ifndef EAI_SOCKTYPE
#define EAI_SOCKTYPE WSAESOCKTNOSUPPORT
#endif
#ifndef EAI_SYSTEM
#define EAI_SYSTEM -11
#endif
#ifndef EAI_OVERFLOW
#define EAI_OVERFLOW -12
#endif

#ifndef AI_PASSIVE
#define AI_PASSIVE 0x00000001
#endif
#ifndef AI_CANONNAME
#define AI_CANONNAME 0x00000002
#endif
#ifndef AI_NUMERICHOST
#define AI_NUMERICHOST 0x00000004
#endif
#ifndef AI_ADDRCONFIG
#define AI_ADDRCONFIG 0x00000400
#endif

#define POLLRDNORM 0x0100
#define POLLRDBAND 0x0200
#define POLLIN     (POLLRDNORM | POLLRDBAND)
#define POLLWRNORM 0x0010
#define POLLOUT    POLLWRNORM
#define POLLERR    0x0001
#define POLLHUP    0x0002
#define POLLNVAL   0x0004

#ifndef WAIT_OBJECT_0
#define WAIT_OBJECT_0 0
#endif

#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)

#define SYNCHRONIZE                       0x00100000UL
#define PROCESS_QUERY_LIMITED_INFORMATION 0x00001000UL
#define WT_EXECUTEONLYONCE                0x00000008UL

#define STARTF_USESTDHANDLES 0x00000100UL

#define EXTENDED_STARTUPINFO_PRESENT       0x00080000UL
#define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE 0x00020016UL

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

#define FILE_NAME_NORMALIZED          0x00000000UL
#define INVALID_FILE_ATTRIBUTES       ((DWORD)0xffffffffUL)
#define FILE_ATTRIBUTE_DIRECTORY      0x00000010UL
#define FILE_ATTRIBUTE_NORMAL         0x00000080UL
#define FILE_ATTRIBUTE_REPARSE_POINT  0x00000400UL
#define FILE_LIST_DIRECTORY           0x00000001UL
#define FILE_SHARE_READ               0x00000001UL
#define FILE_SHARE_WRITE              0x00000002UL
#define FILE_SHARE_DELETE             0x00000004UL
#define GENERIC_READ                  0x80000000UL
#define OPEN_EXISTING                 3UL
#define FILE_FLAG_BACKUP_SEMANTICS    0x02000000UL
#define FILE_FLAG_OVERLAPPED          0x40000000UL
#define FILE_NOTIFY_CHANGE_FILE_NAME  0x00000001UL
#define FILE_NOTIFY_CHANGE_DIR_NAME   0x00000002UL
#define FILE_NOTIFY_CHANGE_ATTRIBUTES 0x00000004UL
#define FILE_NOTIFY_CHANGE_SIZE       0x00000008UL
#define FILE_NOTIFY_CHANGE_LAST_WRITE 0x00000010UL
#define FILE_ACTION_ADDED             0x00000001UL
#define FILE_ACTION_REMOVED           0x00000002UL
#define FILE_ACTION_MODIFIED          0x00000003UL
#define FILE_ACTION_RENAMED_OLD_NAME  0x00000004UL
#define FILE_ACTION_RENAMED_NEW_NAME  0x00000005UL

#ifndef IO_REPARSE_TAG_AF_UNIX
#define IO_REPARSE_TAG_AF_UNIX 0x80000023UL
#endif

#define ERROR_INVALID_HANDLE     6UL
#define ERROR_HANDLE_EOF         38UL
#define ERROR_BROKEN_PIPE        109UL
#define ERROR_NO_DATA            232UL
#define ERROR_PIPE_NOT_CONNECTED 233UL

#define HANDLE_FLAG_INHERIT 0x00000001UL
#define STILL_ACTIVE        259UL
#define DUPLICATE_SAME_ACCESS 0x00000002UL

#define STD_INPUT_HANDLE  ((DWORD)-10)
#define STD_OUTPUT_HANDLE ((DWORD)-11)
#define STD_ERROR_HANDLE  ((DWORD)-12)

#ifndef CALLBACK
#define CALLBACK __attribute__((__stdcall__))
#endif

typedef void VOID;
typedef HANDLE *PHANDLE;
typedef HANDLE HMODULE;
typedef HANDLE HPCON;
typedef void  *FARPROC;
typedef void  *LPPROC_THREAD_ATTRIBUTE_LIST;
typedef VOID(CALLBACK *WAITORTIMERCALLBACK)(PVOID, BOOLEAN);

#define MAKEWORD(a, b) ((WORD)((((WORD)(a)) & 0xffu) | ((((WORD)(b)) & 0xffu) << 8)))

struct in_addr {
    union {
        struct {
            u_char s_b1;
            u_char s_b2;
            u_char s_b3;
            u_char s_b4;
        } S_un_b;
        struct {
            u_short s_w1;
            u_short s_w2;
        } S_un_w;
        u_long S_addr;
    } S_un;
};

#define s_addr S_un.S_addr

struct sockaddr {
    u_short sa_family;
    char    sa_data[14];
};

struct sockaddr_storage {
    short   ss_family;
    char    __ss_pad1[6];
    int64_t __ss_align;
    char    __ss_pad2[112];
};

struct sockaddr_in {
    short          sin_family;
    u_short        sin_port;
    struct in_addr sin_addr;
    char           sin_zero[8];
};

struct sockaddr_un {
    u_short sun_family;
    char    sun_path[108];
};

struct addrinfo {
    int              ai_flags;
    int              ai_family;
    int              ai_socktype;
    int              ai_protocol;
    size_t           ai_addrlen;
    char            *ai_canonname;
    struct sockaddr *ai_addr;
    struct addrinfo *ai_next;
};

#define WSADESCRIPTION_LEN 256
#define WSASYS_STATUS_LEN  128

typedef struct WSAData {
    WORD           wVersion;
    WORD           wHighVersion;
    unsigned short iMaxSockets;
    unsigned short iMaxUdpDg;
    char          *lpVendorInfo;
    char           szDescription[WSADESCRIPTION_LEN + 1];
    char           szSystemStatus[WSASYS_STATUS_LEN + 1];
} WSADATA;

typedef struct pollfd {
    SOCKET fd;
    short  events;
    short  revents;
} WSAPOLLFD;

typedef struct _STARTUPINFOA {
    DWORD  cb;
    char  *lpReserved;
    char  *lpDesktop;
    char  *lpTitle;
    DWORD  dwX;
    DWORD  dwY;
    DWORD  dwXSize;
    DWORD  dwYSize;
    DWORD  dwXCountChars;
    DWORD  dwYCountChars;
    DWORD  dwFillAttribute;
    DWORD  dwFlags;
    USHORT wShowWindow;
    USHORT cbReserved2;
    unsigned char *lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
} STARTUPINFOA;

typedef struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD  dwProcessId;
    DWORD  dwThreadId;
} PROCESS_INFORMATION;

typedef struct _WIN32_FIND_DATAA {
    DWORD    dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD    nFileSizeHigh;
    DWORD    nFileSizeLow;
    DWORD    dwReserved0;
    DWORD    dwReserved1;
    char     cFileName[MAX_PATH];
    char     cAlternateFileName[14];
} WIN32_FIND_DATAA;

typedef struct _STARTUPINFOEXA {
    STARTUPINFOA                  StartupInfo;
    LPPROC_THREAD_ATTRIBUTE_LIST  lpAttributeList;
} STARTUPINFOEXA;

typedef struct _SECURITY_ATTRIBUTES {
    DWORD  nLength;
    void  *lpSecurityDescriptor;
    BOOL   bInheritHandle;
} SECURITY_ATTRIBUTES;

typedef struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    DWORD     Offset;
    DWORD     OffsetHigh;
    HANDLE    hEvent;
} OVERLAPPED;

typedef struct _FILE_NOTIFY_INFORMATION {
    DWORD   NextEntryOffset;
    DWORD   Action;
    DWORD   FileNameLength;
    wchar_t FileName[1];
} FILE_NOTIFY_INFORMATION;

typedef struct _COORD {
    short X;
    short Y;
} COORD;

SOCKET __attribute__((__stdcall__)) socket(int af, int type, int protocol);
int __attribute__((__stdcall__)) bind(SOCKET s, const struct sockaddr *name, int namelen);
int __attribute__((__stdcall__)) getsockname(SOCKET s, struct sockaddr *name, int *namelen);
int __attribute__((__stdcall__)) listen(SOCKET s, int backlog);
int __attribute__((__stdcall__)) connect(SOCKET s, const struct sockaddr *name, int namelen);
SOCKET __attribute__((__stdcall__)) accept(SOCKET s, struct sockaddr *addr, int *addrlen);
int __attribute__((__stdcall__)) ioctlsocket(SOCKET s, long cmd, u_long *argp);
int __attribute__((__stdcall__)) send(SOCKET s, const char *buf, int len, int flags);
int __attribute__((__stdcall__)) recv(SOCKET s, char *buf, int len, int flags);
int __attribute__((__stdcall__)) sendto(SOCKET s,
                                        const char *buf,
                                        int len,
                                        int flags,
                                        const struct sockaddr *to,
                                        int tolen);
int __attribute__((__stdcall__)) recvfrom(SOCKET s,
                                          char *buf,
                                          int len,
                                          int flags,
                                          struct sockaddr *from,
                                          int *fromlen);
int __attribute__((__stdcall__)) closesocket(SOCKET s);
u_long __attribute__((__stdcall__)) htonl(u_long hostlong);
u_short __attribute__((__stdcall__)) htons(u_short hostshort);
u_short __attribute__((__stdcall__)) ntohs(u_short netshort);
int __attribute__((__stdcall__)) inet_pton(int af, const char *src, void *dst);
int __attribute__((__stdcall__)) setsockopt(SOCKET s,
                                            int level,
                                            int optname,
                                            const char *optval,
                                            int optlen);
int __attribute__((__stdcall__)) getsockopt(SOCKET s,
                                            int level,
                                            int optname,
                                            char *optval,
                                            int *optlen);
int __attribute__((__stdcall__)) WSAGetLastError(void);
int __attribute__((__stdcall__)) WSAStartup(WORD wVersionRequested, WSADATA *lpWSAData);
int __attribute__((__stdcall__)) WSAPoll(WSAPOLLFD fdarray[], ULONG nfds, int timeout);
int __attribute__((__stdcall__)) getaddrinfo(const char *node_name,
                                             const char *service_name,
                                             const struct addrinfo *hints,
                                             struct addrinfo **result);
void __attribute__((__stdcall__)) freeaddrinfo(struct addrinfo *ai);
const char *__attribute__((__stdcall__)) gai_strerrorA(int ecode);
#ifndef gai_strerror
#define gai_strerror gai_strerrorA
#endif

HANDLE __attribute__((__stdcall__)) CreateEventW(void *event_attributes,
                                                 BOOL  manual_reset,
                                                 BOOL  initial_state,
                                                 const wchar_t *name);
BOOL __attribute__((__stdcall__)) CloseHandle(HANDLE object);
BOOL __attribute__((__stdcall__)) SetEvent(HANDLE event);
BOOL __attribute__((__stdcall__)) ResetEvent(HANDLE event);
DWORD __attribute__((__stdcall__)) WaitForSingleObject(HANDLE handle, DWORD milliseconds);
HANDLE __attribute__((__stdcall__)) OpenProcess(DWORD desired_access,
                                                BOOL inherit_handle,
                                                DWORD process_id);
BOOL __attribute__((__stdcall__)) RegisterWaitForSingleObject(
    PHANDLE new_wait_object,
    HANDLE object,
    WAITORTIMERCALLBACK callback,
    PVOID context,
    ULONG milliseconds,
    ULONG flags);
BOOL __attribute__((__stdcall__)) UnregisterWaitEx(HANDLE wait_handle,
                                                   HANDLE completion_event);
BOOL __attribute__((__stdcall__)) GetExitCodeProcess(HANDLE process,
                                                     DWORD *exit_code);
BOOL __attribute__((__stdcall__)) TerminateProcess(HANDLE process,
                                                   unsigned int exit_code);
HANDLE __attribute__((__stdcall__)) GetStdHandle(DWORD std_handle);
BOOL __attribute__((__stdcall__)) SetStdHandle(DWORD std_handle,
                                               HANDLE handle);
HANDLE __attribute__((__stdcall__)) GetCurrentProcess(void);
BOOL __attribute__((__stdcall__)) DuplicateHandle(HANDLE source_process,
                                                  HANDLE source_handle,
                                                  HANDLE target_process,
                                                  HANDLE *target_handle,
                                                  DWORD desired_access,
                                                  BOOL inherit_handle,
                                                  DWORD options);
BOOL __attribute__((__stdcall__)) CreatePipe(HANDLE *read_pipe,
                                             HANDLE *write_pipe,
                                             SECURITY_ATTRIBUTES *pipe_attributes,
                                             DWORD size);
BOOL __attribute__((__stdcall__)) SetHandleInformation(HANDLE object,
                                                       DWORD mask,
                                                       DWORD flags);
BOOL __attribute__((__stdcall__)) ReadFile(HANDLE file,
                                           void *buffer,
                                           DWORD bytes_to_read,
                                           DWORD *bytes_read,
                                           void *overlapped);
BOOL __attribute__((__stdcall__)) WriteFile(HANDLE file,
                                            const void *buffer,
                                            DWORD bytes_to_write,
                                            DWORD *bytes_written,
                                            void *overlapped);
BOOL __attribute__((__stdcall__)) PeekNamedPipe(HANDLE pipe,
                                                void *buffer,
                                                DWORD buffer_size,
                                                DWORD *bytes_read,
                                                DWORD *total_bytes_available,
                                                DWORD *bytes_left_this_message);
BOOL __attribute__((__stdcall__)) CreateProcessA(const char *application_name,
                                                 char *command_line,
                                                 void *process_attributes,
                                                 void *thread_attributes,
                                                 BOOL inherit_handles,
                                                 DWORD creation_flags,
                                                 void *environment,
                                                 const char *current_directory,
                                                 STARTUPINFOA *startup_info,
                                                 PROCESS_INFORMATION *process_information);
DWORD __attribute__((__stdcall__)) GetFinalPathNameByHandleW(HANDLE file,
                                                             wchar_t *path,
                                                             DWORD path_len,
                                                             DWORD flags);
DWORD __attribute__((__stdcall__)) GetFileAttributesW(const wchar_t *path);
HANDLE __attribute__((__stdcall__)) FindFirstFileA(const char *file_name,
                                                   WIN32_FIND_DATAA *find_file_data);
BOOL __attribute__((__stdcall__)) FindClose(HANDLE find_file);
HANDLE __attribute__((__stdcall__)) CreateFileW(const wchar_t *file_name,
                                                DWORD desired_access,
                                                DWORD share_mode,
                                                void *security_attributes,
                                                DWORD creation_disposition,
                                                DWORD flags_and_attributes,
                                                HANDLE template_file);
BOOL __attribute__((__stdcall__)) CancelIo(HANDLE file);
BOOL __attribute__((__stdcall__)) ReadDirectoryChangesW(HANDLE directory,
                                                        void *buffer,
                                                        DWORD buffer_len,
                                                        BOOL watch_subtree,
                                                        DWORD notify_filter,
                                                        DWORD *bytes_returned,
                                                        OVERLAPPED *overlapped,
                                                        void *completion_routine);
BOOL __attribute__((__stdcall__)) GetOverlappedResult(HANDLE file,
                                                      OVERLAPPED *overlapped,
                                                      DWORD *bytes_transferred,
                                                      BOOL wait);
BOOL __attribute__((__stdcall__)) CreateHardLinkA(const char *file_name,
                                                  const char *existing_file_name,
                                                  void *security_attributes);
BOOL __attribute__((__stdcall__)) MoveFileExA(const char *existing_file_name,
                                              const char *new_file_name,
                                              DWORD flags);
HMODULE __attribute__((__stdcall__)) GetModuleHandleA(const char *module_name);
HMODULE __attribute__((__stdcall__)) LoadLibraryA(const char *file_name);
BOOL __attribute__((__stdcall__)) FreeLibrary(HMODULE module);
FARPROC __attribute__((__stdcall__)) GetProcAddress(HMODULE module,
                                                    const char *proc_name);
BOOL __attribute__((__stdcall__)) InitializeProcThreadAttributeList(
    LPPROC_THREAD_ATTRIBUTE_LIST attribute_list,
    DWORD attribute_count,
    DWORD flags,
    SIZE_T *size);
BOOL __attribute__((__stdcall__)) UpdateProcThreadAttribute(
    LPPROC_THREAD_ATTRIBUTE_LIST attribute_list,
    DWORD flags,
    DWORD_PTR attribute,
    void *value,
    SIZE_T size,
    void *previous_value,
    SIZE_T *return_size);
void __attribute__((__stdcall__)) DeleteProcThreadAttributeList(
    LPPROC_THREAD_ATTRIBUTE_LIST attribute_list);
HRESULT __attribute__((__stdcall__)) CreatePseudoConsole(COORD size,
                                                         HANDLE input,
                                                         HANDLE output,
                                                         DWORD flags,
                                                         HPCON *pseudo_console);
HRESULT __attribute__((__stdcall__)) ResizePseudoConsole(HPCON pseudo_console,
                                                         COORD size);
void __attribute__((__stdcall__)) ClosePseudoConsole(HPCON pseudo_console);

#endif

#endif
