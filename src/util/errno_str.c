/* src/util/errno_str.c — POSIX errno-to-string accessor.
 *
 * Implements the surface declared in include/util/errno_str.h:
 *   - n00b_errno_str  (pure lookup from int errno value to
 *                      rich-literal n00b_string_t *)
 *
 * The accessor mirrors the project-internal `n00b_attest_err_str`
 * / `n00b_base64_err_str` shape: a `switch` over integer codes,
 * each case returning a rich-string literal (`r"..."`) with
 * process-lifetime storage. Unknown codes (including platform-
 * only extensions not in the portable POSIX.1-2008 set) return a
 * documented fallback.
 *
 * # Coverage rationale
 *
 * Every POSIX.1-2008 portable errno value is in the table. The
 * portable set was assembled by walking the IEEE Std 1003.1-2008
 * "<errno.h>" page (the normative reference) and cross-checking
 * against the macOS `sys/errno.h` and Linux `asm-generic/errno*.h`
 * headers.
 *
 * In addition, Linux-only (`ECHRNG`, `EL2NSYNC`, ...) and
 * macOS/BSD-only (`ENOATTR`, `EBADRPC`, ...) extensions are
 * covered under `#ifdef <CODE>` guards so that on each platform
 * the accessor returns a stable description for every errno macro
 * the platform's `<errno.h>` actually defines. Codes that are not
 * `#define`d on the host platform fall through to the
 * unknown-code fallback. The guard pattern means a single source
 * file compiles cleanly on Linux, macOS, and any other libc that
 * defines a subset of these macros — no per-platform `#ifdef
 * __linux__` block needed.
 *
 * # Sign handling
 *
 * libn00b's `n00b_check_posix` wrapper returns `Err(errno)`
 * (positive) directly per `include/adt/result.h`, but several
 * subsystems re-encode the POSIX code as `Err(-errno)` to avoid
 * collision with negative module-domain codes (e.g., a -1001
 * Statement code would collide with a positive `EPERM = 1`
 * encoded as `-1` only via this negation convention). The
 * accessor folds the sign so a single entry point serves both
 * conventions; `n00b_errno_str(EPERM)` and `n00b_errno_str(-EPERM)`
 * both return the same description.
 *
 * # EAGAIN / EWOULDBLOCK aliasing
 *
 * POSIX permits these to be the same value or distinct. On both
 * Linux and macOS they are identical (`EWOULDBLOCK == EAGAIN`).
 * To stay compilable on the rare platform where they differ, the
 * `EWOULDBLOCK` case is guarded by `#if EWOULDBLOCK != EAGAIN`.
 * On platforms where they are identical the compiler would error
 * on a duplicate `case` label, hence the guard.
 *
 * # ENOTSUP / EOPNOTSUPP aliasing
 *
 * Same situation as EAGAIN / EWOULDBLOCK. On Linux these are
 * identical; on macOS they are distinct (ENOTSUP=45, EOPNOTSUPP=102).
 * Same guard pattern.
 *
 * Implementation note: we use a `switch` against the standard
 * `<errno.h>` macros rather than a numeric table because the codes
 * are not contiguous and differ between platforms — the compiler-
 * supplied `<errno.h>` definitions are authoritative for the host.
 */

#include "n00b.h"
#include "core/string.h"
#include "util/errno_str.h"

#include <errno.h>

n00b_string_t *
n00b_errno_str(int errno_val)
{
    // Fold the sign — libn00b's `n00b_check_posix` returns positive
    // errno but some subsystems re-encode as -errno; one accessor
    // serves both conventions.
    if (errno_val < 0) {
        errno_val = -errno_val;
    }

    switch (errno_val) {
    case 0:
        return r"no error";

    // ---- POSIX.1-2008 portable core ----------------------------
    case EPERM:
        return r"operation not permitted";
    case ENOENT:
        return r"no such file or directory";
    case ESRCH:
        return r"no such process";
    case EINTR:
        return r"interrupted system call";
    case EIO:
        return r"i/o error";
    case ENXIO:
        return r"no such device or address";
    case E2BIG:
        return r"argument list too long";
    case ENOEXEC:
        return r"exec format error";
    case EBADF:
        return r"bad file descriptor";
    case ECHILD:
        return r"no child processes";
    case EAGAIN:
        return r"resource temporarily unavailable";
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK:
        return r"operation would block";
#endif
    case ENOMEM:
        return r"out of memory";
    case EACCES:
        return r"permission denied";
    case EFAULT:
        return r"bad address";
#if defined(ENOTBLK)
    case ENOTBLK:
        return r"block device required";
#endif
    case EBUSY:
        return r"device or resource busy";
    case EEXIST:
        return r"file already exists";
    case EXDEV:
        return r"cross-device link";
    case ENODEV:
        return r"no such device";
    case ENOTDIR:
        return r"not a directory";
    case EISDIR:
        return r"is a directory";
    case EINVAL:
        return r"invalid argument";
    case ENFILE:
        return r"too many open files in system";
    case EMFILE:
        return r"too many open files in process";
    case ENOTTY:
        return r"not a terminal";
    case ETXTBSY:
        return r"text file busy";
    case EFBIG:
        return r"file too large";
    case ENOSPC:
        return r"no space left on device";
    case ESPIPE:
        return r"illegal seek";
    case EROFS:
        return r"read-only filesystem";
    case EMLINK:
        return r"too many links";
    case EPIPE:
        return r"broken pipe";
    case EDOM:
        return r"math argument out of domain";
    case ERANGE:
        return r"math result out of range";
    case EDEADLK:
        return r"resource deadlock avoided";
    case ENAMETOOLONG:
        return r"file name too long";
    case ENOLCK:
        return r"no record locks available";
    case ENOSYS:
        return r"function not implemented";
    case ENOTEMPTY:
        return r"directory not empty";
    case ELOOP:
        return r"too many levels of symbolic links";
    case ENOMSG:
        return r"no message of desired type";
    case EIDRM:
        return r"identifier removed";

    // ---- POSIX.1-2008 networking -------------------------------
    case ENOSTR:
        return r"device not a stream";
    case ENODATA:
        return r"no data available";
    case ETIME:
        return r"timer expired";
    case ENOSR:
        return r"out of stream resources";
    case ENOLINK:
        return r"link has been severed";
    case EPROTO:
        return r"protocol error";
#if defined(EMULTIHOP)
    case EMULTIHOP:
        return r"multihop attempted";
#endif
    case EBADMSG:
        return r"bad message";
    case EOVERFLOW:
        return r"value too large for data type";
    case EILSEQ:
        return r"illegal byte sequence";

    case ENOTSOCK:
        return r"not a socket";
    case EDESTADDRREQ:
        return r"destination address required";
    case EMSGSIZE:
        return r"message too long";
    case EPROTOTYPE:
        return r"protocol wrong type for socket";
    case ENOPROTOOPT:
        return r"protocol not available";
    case EPROTONOSUPPORT:
        return r"protocol not supported";
    case ENOTSUP:
        return r"operation not supported";
#if defined(EOPNOTSUPP) && EOPNOTSUPP != ENOTSUP
    case EOPNOTSUPP:
        return r"operation not supported on socket";
#endif
    case EAFNOSUPPORT:
        return r"address family not supported";
    case EADDRINUSE:
        return r"address already in use";
    case EADDRNOTAVAIL:
        return r"address not available";
    case ENETDOWN:
        return r"network is down";
    case ENETUNREACH:
        return r"network unreachable";
    case ENETRESET:
        return r"network dropped connection on reset";
    case ECONNABORTED:
        return r"connection aborted";
    case ECONNRESET:
        return r"connection reset by peer";
    case ENOBUFS:
        return r"no buffer space available";
    case EISCONN:
        return r"socket already connected";
    case ENOTCONN:
        return r"socket not connected";
    case ETIMEDOUT:
        return r"connection timed out";
    case ECONNREFUSED:
        return r"connection refused";
    case EHOSTUNREACH:
        return r"host unreachable";
    case EALREADY:
        return r"operation already in progress";
    case EINPROGRESS:
        return r"operation in progress";
#if defined(ESTALE)
    case ESTALE:
        return r"stale file handle";
#endif
#if defined(EDQUOT)
    case EDQUOT:
        return r"disk quota exceeded";
#endif
    case ECANCELED:
        return r"operation canceled";
#if defined(EOWNERDEAD)
    case EOWNERDEAD:
        return r"owner died";
#endif
#if defined(ENOTRECOVERABLE)
    case ENOTRECOVERABLE:
        return r"state not recoverable";
#endif

    // ---- Linux-only extensions (under #ifdef guards) -----------
    // The Linux generic kernel headers define a large supplemental
    // set of errno codes covering legacy STREAMS, XENIX
    // compatibility, RPC, networking, and key-management. Each is
    // guarded so the source compiles unmodified on macOS / BSD.
#if defined(ECHRNG)
    case ECHRNG:
        return r"channel number out of range";
#endif
#if defined(EL2NSYNC)
    case EL2NSYNC:
        return r"level 2 not synchronized";
#endif
#if defined(EL3HLT)
    case EL3HLT:
        return r"level 3 halted";
#endif
#if defined(EL3RST)
    case EL3RST:
        return r"level 3 reset";
#endif
#if defined(ELNRNG)
    case ELNRNG:
        return r"link number out of range";
#endif
#if defined(EUNATCH)
    case EUNATCH:
        return r"protocol driver not attached";
#endif
#if defined(ENOCSI)
    case ENOCSI:
        return r"no csi structure available";
#endif
#if defined(EL2HLT)
    case EL2HLT:
        return r"level 2 halted";
#endif
#if defined(EBADE)
    case EBADE:
        return r"invalid exchange";
#endif
#if defined(EBADR)
    case EBADR:
        return r"invalid request descriptor";
#endif
#if defined(EXFULL)
    case EXFULL:
        return r"exchange full";
#endif
#if defined(ENOANO)
    case ENOANO:
        return r"no anode";
#endif
#if defined(EBADRQC)
    case EBADRQC:
        return r"invalid request code";
#endif
#if defined(EBADSLT)
    case EBADSLT:
        return r"invalid slot";
#endif
#if defined(EDEADLOCK) && EDEADLOCK != EDEADLK
    case EDEADLOCK:
        return r"resource deadlock avoided";
#endif
#if defined(EBFONT)
    case EBFONT:
        return r"bad font file format";
#endif
#if defined(ENONET)
    case ENONET:
        return r"machine is not on the network";
#endif
#if defined(ENOPKG)
    case ENOPKG:
        return r"package not installed";
#endif
#if defined(EREMOTE)
    case EREMOTE:
        return r"object is remote";
#endif
#if defined(EADV)
    case EADV:
        return r"advertise error";
#endif
#if defined(ESRMNT)
    case ESRMNT:
        return r"srmount error";
#endif
#if defined(ECOMM)
    case ECOMM:
        return r"communication error on send";
#endif
#if defined(EDOTDOT)
    case EDOTDOT:
        return r"rfs specific error";
#endif
#if defined(ENOTUNIQ)
    case ENOTUNIQ:
        return r"name not unique on network";
#endif
#if defined(EBADFD)
    case EBADFD:
        return r"file descriptor in bad state";
#endif
#if defined(EREMCHG)
    case EREMCHG:
        return r"remote address changed";
#endif
#if defined(ELIBACC)
    case ELIBACC:
        return r"can not access a needed shared library";
#endif
#if defined(ELIBBAD)
    case ELIBBAD:
        return r"accessing a corrupted shared library";
#endif
#if defined(ELIBSCN)
    case ELIBSCN:
        return r".lib section in a.out corrupted";
#endif
#if defined(ELIBMAX)
    case ELIBMAX:
        return r"attempting to link in too many shared libraries";
#endif
#if defined(ELIBEXEC)
    case ELIBEXEC:
        return r"cannot exec a shared library directly";
#endif
#if defined(ERESTART)
    case ERESTART:
        return r"interrupted system call should be restarted";
#endif
#if defined(ESTRPIPE)
    case ESTRPIPE:
        return r"streams pipe error";
#endif
#if defined(EUSERS)
    case EUSERS:
        return r"too many users";
#endif
#if defined(ESHUTDOWN)
    case ESHUTDOWN:
        return r"cannot send after transport endpoint shutdown";
#endif
#if defined(ETOOMANYREFS)
    case ETOOMANYREFS:
        return r"too many references: cannot splice";
#endif
#if defined(EHOSTDOWN)
    case EHOSTDOWN:
        return r"host is down";
#endif
#if defined(EUCLEAN)
    case EUCLEAN:
        return r"structure needs cleaning";
#endif
#if defined(ENOTNAM)
    case ENOTNAM:
        return r"not a xenix named type file";
#endif
#if defined(ENAVAIL)
    case ENAVAIL:
        return r"no xenix semaphores available";
#endif
#if defined(EISNAM)
    case EISNAM:
        return r"is a named type file";
#endif
#if defined(EREMOTEIO)
    case EREMOTEIO:
        return r"remote i/o error";
#endif
#if defined(ENOMEDIUM)
    case ENOMEDIUM:
        return r"no medium found";
#endif
#if defined(EMEDIUMTYPE)
    case EMEDIUMTYPE:
        return r"wrong medium type";
#endif
#if defined(ENOKEY)
    case ENOKEY:
        return r"required key not available";
#endif
#if defined(EKEYEXPIRED)
    case EKEYEXPIRED:
        return r"key has expired";
#endif
#if defined(EKEYREVOKED)
    case EKEYREVOKED:
        return r"key has been revoked";
#endif
#if defined(EKEYREJECTED)
    case EKEYREJECTED:
        return r"key was rejected by service";
#endif
#if defined(ERFKILL)
    case ERFKILL:
        return r"operation not possible due to rf-kill";
#endif
#if defined(EHWPOISON)
    case EHWPOISON:
        return r"memory page has hardware error";
#endif

    // ---- macOS / BSD-only extensions (under #ifdef guards) -----
    // The macOS and BSD `<sys/errno.h>` headers add extensions
    // covering extended attributes, ONC RPC, Mach-O loader errors,
    // and Apple-specific codes. Each is guarded so the source
    // compiles unmodified on Linux.
#if defined(ENOATTR)
    case ENOATTR:
        return r"attribute not found";
#endif
#if defined(EBADRPC)
    case EBADRPC:
        return r"rpc struct is bad";
#endif
#if defined(ERPCMISMATCH)
    case ERPCMISMATCH:
        return r"rpc version wrong";
#endif
#if defined(EPROGUNAVAIL)
    case EPROGUNAVAIL:
        return r"rpc prog not available";
#endif
#if defined(EPROGMISMATCH)
    case EPROGMISMATCH:
        return r"rpc program version wrong";
#endif
#if defined(EPROCUNAVAIL)
    case EPROCUNAVAIL:
        return r"bad procedure for rpc program";
#endif
#if defined(EFTYPE)
    case EFTYPE:
        return r"inappropriate file type or format";
#endif
#if defined(EAUTH)
    case EAUTH:
        return r"authentication error";
#endif
#if defined(ENEEDAUTH)
    case ENEEDAUTH:
        return r"need authenticator";
#endif
#if defined(EPWROFF)
    case EPWROFF:
        return r"device power is off";
#endif
#if defined(EDEVERR)
    case EDEVERR:
        return r"device error";
#endif
#if defined(EBADEXEC)
    case EBADEXEC:
        return r"bad executable";
#endif
#if defined(EBADARCH)
    case EBADARCH:
        return r"bad cpu type in executable";
#endif
#if defined(ESHLIBVERS)
    case ESHLIBVERS:
        return r"shared library version mismatch";
#endif
#if defined(EBADMACHO)
    case EBADMACHO:
        return r"malformed mach-o file";
#endif
#if defined(ENOPOLICY)
    case ENOPOLICY:
        return r"no such policy";
#endif
#if defined(EQFULL)
    case EQFULL:
        return r"interface output queue is full";
#endif
#if defined(EPROCLIM)
    case EPROCLIM:
        return r"too many processes";
#endif
#if defined(EPFNOSUPPORT)
    case EPFNOSUPPORT:
        return r"protocol family not supported";
#endif
#if defined(ESOCKTNOSUPPORT)
    case ESOCKTNOSUPPORT:
        return r"socket type not supported";
#endif
#if defined(ENOTCAPABLE)
    case ENOTCAPABLE:
        return r"capabilities insufficient";
#endif

    default:
        return r"unknown errno value";
    }
}

#ifdef _WIN32
#include "internal/win32_sockets.h"
#else
#include <netdb.h>
#endif

n00b_string_t *
n00b_gai_str(int rc)
{
    // `getaddrinfo` sign conventions vary across libcs (BSD/macOS
    // uses positive small ints; glibc historically uses negatives).  Do not
    // normalize the sign before comparing because the platform EAI_* macros
    // themselves may be negative.
    if (rc == 0) {
        return r"no error";
    }

    // ---- POSIX.1 EAI_* core -----------------------------------
#if defined(EAI_BADFLAGS)
    if (rc == EAI_BADFLAGS || rc == -EAI_BADFLAGS)
        return r"invalid value for ai_flags";
#endif
#if defined(EAI_NONAME)
    if (rc == EAI_NONAME || rc == -EAI_NONAME)
        return r"host or service not known";
#endif
#if defined(EAI_AGAIN)
    if (rc == EAI_AGAIN || rc == -EAI_AGAIN)
        return r"temporary failure in name resolution";
#endif
#if defined(EAI_FAIL)
    if (rc == EAI_FAIL || rc == -EAI_FAIL)
        return r"non-recoverable failure in name resolution";
#endif
#if defined(EAI_FAMILY)
    if (rc == EAI_FAMILY || rc == -EAI_FAMILY)
        return r"address family not supported";
#endif
#if defined(EAI_SOCKTYPE)
    if (rc == EAI_SOCKTYPE || rc == -EAI_SOCKTYPE)
        return r"socket type not supported";
#endif
#if defined(EAI_SERVICE)
    if (rc == EAI_SERVICE || rc == -EAI_SERVICE)
        return r"service not supported for socket type";
#endif
#if defined(EAI_MEMORY)
    if (rc == EAI_MEMORY || rc == -EAI_MEMORY)
        return r"memory allocation failure";
#endif
#if defined(EAI_SYSTEM)
    if (rc == EAI_SYSTEM || rc == -EAI_SYSTEM)
        return r"system error (see errno)";
#endif
#if defined(EAI_OVERFLOW)
    if (rc == EAI_OVERFLOW || rc == -EAI_OVERFLOW)
        return r"argument buffer overflow";
#endif

    // ---- BSD / GNU extensions ---------------------------------
#if defined(EAI_NODATA) && (!defined(EAI_NONAME) || EAI_NODATA != EAI_NONAME)
    if (rc == EAI_NODATA || rc == -EAI_NODATA)
        return r"no address associated with host";
#endif
#if defined(EAI_ADDRFAMILY)
    if (rc == EAI_ADDRFAMILY || rc == -EAI_ADDRFAMILY)
        return r"address family for host not supported";
#endif
#if defined(EAI_BADHINTS)
    if (rc == EAI_BADHINTS || rc == -EAI_BADHINTS)
        return r"invalid value for hints";
#endif
#if defined(EAI_PROTOCOL)
    if (rc == EAI_PROTOCOL || rc == -EAI_PROTOCOL)
        return r"resolved protocol is unknown";
#endif
#if defined(EAI_INPROGRESS)
    if (rc == EAI_INPROGRESS || rc == -EAI_INPROGRESS)
        return r"processing request in progress";
#endif
#if defined(EAI_CANCELED)
    if (rc == EAI_CANCELED || rc == -EAI_CANCELED)
        return r"request canceled";
#endif
#if defined(EAI_NOTCANCELED)
    if (rc == EAI_NOTCANCELED || rc == -EAI_NOTCANCELED)
        return r"request not canceled";
#endif
#if defined(EAI_ALLDONE)
    if (rc == EAI_ALLDONE || rc == -EAI_ALLDONE)
        return r"all requests done";
#endif
#if defined(EAI_INTR)
    if (rc == EAI_INTR || rc == -EAI_INTR)
        return r"interrupted by a signal";
#endif
#if defined(EAI_IDN_ENCODE)
    if (rc == EAI_IDN_ENCODE || rc == -EAI_IDN_ENCODE)
        return r"parameter string not correctly encoded";
#endif

    return r"unknown getaddrinfo error";
}
