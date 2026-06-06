#pragma once

#include "core/runtime.h"

/**
 * @brief Prepare process signal state before n00b service threads spawn.
 *
 * On Linux this blocks the runtime default termination signals in the
 * initializing thread so n00b-created threads inherit a mask suitable for
 * `signalfd`. Other platforms prepare signal state in their event backend.
 */
extern void n00b_runtime_signal_defaults_prepare(void);

/**
 * @brief Install n00b's default process-signal policy on the runtime conduit.
 *
 * The default policy listens for common termination signals and restores
 * terminal state before exiting with the conventional `128 + signal` status.
 *
 * @param rt Runtime whose default conduit/service should receive the watches.
 * @pre `rt->default_conduit` and `rt->default_service` have been created.
 */
extern void n00b_runtime_signal_defaults_install(n00b_runtime_t *rt);

/**
 * @brief Drain the runtime's internal signal inbox.
 *
 * Called by the conduit signal service thread after each poll iteration.
 *
 * @param rt Runtime being serviced.
 */
extern void n00b_runtime_signal_defaults_drain(n00b_runtime_t *rt);

/**
 * @brief Begin runtime signal-policy shutdown.
 *
 * Disables default termination handling and restores any terminal state owned
 * by the display terminal lifecycle module.
 *
 * @param rt Runtime being shut down.
 */
extern void n00b_runtime_signal_defaults_begin_shutdown(n00b_runtime_t *rt);

/**
 * @brief Cancel runtime-owned default signal subscriptions.
 *
 * Call after conduit service threads have stopped and before the conduit
 * destroys topics.
 *
 * @param rt Runtime being shut down.
 */
extern void n00b_runtime_signal_defaults_cancel(n00b_runtime_t *rt);

/**
 * @brief Finish runtime signal-policy shutdown.
 *
 * Restores process signal-mask state changed by
 * `n00b_runtime_signal_defaults_prepare`.
 *
 * @param rt Runtime being shut down.
 */
extern void n00b_runtime_signal_defaults_finish_shutdown(n00b_runtime_t *rt);
