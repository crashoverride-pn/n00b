# rocs environment variables

## `ROCS_PLAN_NO_COST`

Set to any value to turn off cost-based planning and execution. With it unset
(the default), four things happen that otherwise do not:

- a group of index scans runs its operands narrowest-first;
- a lookup whose term covers the whole shard is skipped where a paired record
  scan settles the answer;
- a narrow candidate set is tested against the index rather than enumerated
  from it;
- a group of predicates is tested cheapest-first.

With it set, every group runs its children in the order the query wrote them.
It covers the choices made while a plan is built as well as those made while
one runs, so a query compared both ways is compared with all of them off. None
of it changes which records match, which is what makes the comparison a check.

The first query to consult it caches the answer, so a caller that wants it off
has to `setenv` before running any query. `n00b_plan_cost_set_enabled`
overrides it from inside the process at any point.

## `ROCS_QUERY_DEBUG`

Set to any value to write query planning and execution diagnostics to stderr.
Intended for development; the output format is not stable. The plan and query
error paths cache their first answer, and everywhere else re-reads it.
