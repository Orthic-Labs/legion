# Sentry — role architecture

## Ownership

`src/roster/sentry.md` owns identity, trigger, and model tier. `doctrine/sentry.md` is canonical for
watchdog operation, target isolation, baseline authority, Oracle transport, directive tracking, and
escalation. This page records the boundary only; it does not duplicate method details.

Sentry is a mechanical coordinator for explicitly requested watchdog checkpoints. It owns no
semantic judgment, scope decisions, implementation, or certification. Oracle judges checkpoints;
Sentry transports Oracle-authored executor-safe directives verbatim to authorized targets.

## Scheduling boundary

Recurring supervision requires an existing scheduler able to fire independently of the supervised
executor chat. A separate chat, subagent, or executor heartbeat alone is not an independent
scheduler. No new chat, scheduler, runtime, or persistence framework is implied. If independent
scheduling is unavailable, report supervision as unscheduled.
