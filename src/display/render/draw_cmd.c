/*
 * Draw command list: init, append, clear, destroy.
 */

#include "n00b.h"
#include "core/alloc.h"
#include "display/render/draw_cmd.h"

#define DRAW_LIST_INITIAL_CAPACITY 16

void
n00b_draw_list_init(n00b_draw_list_t *dl)
{
    dl->cmds     = nullptr;
    dl->count    = 0;
    dl->capacity = 0;
}

void
n00b_draw_list_append(n00b_draw_list_t      *dl,
                       const n00b_draw_cmd_t *cmd)
{
    if (dl->count >= dl->capacity) {
        n00b_isize_t new_cap = dl->capacity == 0
                                  ? DRAW_LIST_INITIAL_CAPACITY
                                  : dl->capacity * 2;

        // Scanned (NOT no_scan): the command struct now holds its GC pointers
        // (string, style) at fixed offsets outside the union, so the collector
        // forwards them and they never dangle across a collection.
        n00b_draw_cmd_t *new_buf = n00b_alloc_array(n00b_draw_cmd_t, new_cap);
        if (dl->cmds) {
            memcpy(new_buf, dl->cmds,
                   dl->count * sizeof(n00b_draw_cmd_t));
            n00b_free(dl->cmds);
        }
        dl->cmds     = new_buf;
        dl->capacity = new_cap;
    }

    dl->cmds[dl->count++] = *cmd;
}

void
n00b_draw_list_clear(n00b_draw_list_t *dl)
{
    dl->count = 0;
}

void
n00b_draw_list_destroy(n00b_draw_list_t *dl)
{
    if (dl->cmds) {
        n00b_free(dl->cmds);
    }
    dl->cmds     = nullptr;
    dl->count    = 0;
    dl->capacity = 0;
}
