#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief C-level program entry invoked by the platform startup stub.
 *
 * @details This function is defined by ncc-generated C, not by libn00b's static
 * CRT object. The assembly startup stub captures the platform argument block and
 * transfers control here.
 *
 * PRE-RUNTIME CONTEXT: on entry, the n00b runtime is not initialized and the GC
 * does not exist. Code before `n00b_init_simple()` may use only raw C, the
 * platform ABI values passed here, and the plain-C runtime entry symbols needed
 * to bring n00b up and terminate the process. It must not allocate through n00b,
 * construct n00b strings or containers, or use conduit/print APIs.
 *
 * @param argc Argument count captured from the platform ABI.
 * @param argv NULL-terminated argument vector captured from the platform ABI.
 * @param envp NULL-terminated environment vector captured from the platform ABI.
 *
 * @pre Called exactly once, from the initial process thread, by one of the
 *      `n00b_start_*` assembly stubs.
 * @post Does not return; terminates through `n00b_exit()` or an equivalent fatal
 *       path in the generated entry.
 */
[[noreturn]] void n00b_crt_main(int argc, char **argv, char **envp);

#ifdef _WIN32
/**
 * @brief Windows C bridge used by the PE startup stub.
 *
 * @details Windows process entry does not receive `argc/argv/envp` from the
 * loader. This helper obtains the process command line and environment through
 * Win32 APIs, converts them to process-lifetime UTF-8 vectors, and then calls
 * `n00b_crt_main()`.
 *
 * PRE-RUNTIME CONTEXT: this helper may use Win32 process APIs and OS heap
 * allocation only. It must not use n00b allocation, GC, strings, containers, or
 * conduit/print APIs.
 *
 * @pre Called exactly once from a Windows `n00b_start_*` PE entry stub.
 * @post Does not return; transfers to `n00b_crt_main()` or terminates the
 *       process through `ExitProcess()` on unrecoverable setup failure.
 */
[[noreturn]] void n00b_crt_windows_main(void);
#endif

/**
 * @brief Run C/C++ static constructors recorded in the program init-array.
 *
 * @details The custom n00b entry suppresses the platform libc startup object, so
 * libc no longer walks constructor tables on behalf of the program. This helper
 * performs that walk for the generated entry.
 *
 * PRE-RUNTIME CONTEXT: this helper is pure pointer iteration. It must remain safe
 * before the GC and n00b allocator exist. Constructors reached through the table
 * are user/runtime code and must obey the ordering selected by the generated
 * entry.
 *
 * @pre The dynamic loader has mapped the program's static data segments.
 * @post Every constructor in the selected platform init table has been invoked
 *       once, in table order.
 */
void n00b_crt_run_init_array(void);

/**
 * @brief Run constructors in an explicit half-open function-pointer range.
 *
 * @details This is the testable core of `n00b_crt_run_init_array()`. Platform
 * startup table discovery is intentionally separate from the pure pointer walk.
 * Null entries are skipped, matching PE constructor-table sentinel behavior.
 *
 * PRE-RUNTIME CONTEXT: pure pointer iteration only; must not allocate or use
 * initialized n00b runtime services.
 *
 * @param start First table slot to inspect.
 * @param end   One-past-last table slot to inspect.
 *
 * @pre `start <= end`; both pointers identify slots in the same constructor
 *      table or fixture array.
 * @post Every non-null constructor in `[start, end)` has been invoked once, in
 *       table order.
 */
void n00b_crt_run_init_array_range(void (**start)(void), void (**end)(void));

#ifdef __cplusplus
}
#endif
