---- MODULE upstream_retirement ----
EXTENDS Naturals, FiniteSets

\* Bounded logical abstraction of the exact-episode io_uring retirement ledger.
\* Start after ownership transfer; each initial cancel either submitted or
\* failed for SQ capacity. Two episodes model replacement/slot reuse.
\* Not a C++/kernel extraction: provided-buffer IDs, syscalls, max-episode
\* quarantine, downstream cancel ledgers and TLS buffers remain outside scope.
CONSTANTS OpCount, Episodes, Fault
ASSUME /\ OpCount \in {1, 2} /\ Episodes \in {1, 2}
       /\ Fault \in {"none", "more_final", "duplicate_final", "stale_final",
                      "wrong_aux", "missing_cancel_count", "retry_counted",
                      "retry_not_cleared", "early_reclaim", "double_reclaim",
                      "stale_callback", "unfair_target", "unfair_cancel"}
Ops == 1..OpCount
VARIABLES episode, target, cancel, retry, pending, other, closed, reclaimed,
          freed, safe, callbacks, tick
vars == <<episode, target, cancel, retry, pending, other, closed, reclaimed,
          freed, safe, callbacks, tick>>
Owned == target \union cancel \union retry
Count(t,c,o) == Cardinality(t) + Cardinality(c) + IF o THEN 1 ELSE 0
Init == /\ episode = 1 /\ target = Ops /\ retry \in SUBSET Ops
        /\ cancel = Ops \ retry /\ other = TRUE
        /\ pending = Count(target,cancel,other) +
                     IF Fault = "retry_counted" THEN Cardinality(retry) ELSE 0
        /\ closed = FALSE /\ reclaimed = FALSE /\ freed = 0
        /\ safe = TRUE /\ callbacks = 0 /\ tick = FALSE

Close == /\ ~closed /\ ~reclaimed /\ closed' = TRUE
         /\ UNCHANGED <<episode,target,cancel,retry,pending,other,reclaimed,freed,safe,callbacks,tick>>
RetrySubmit(op) ==
    /\ op \in retry /\ op \in target /\ ~reclaimed
    /\ retry' = retry \ {op} /\ cancel' = cancel \union {op}
    /\ pending' = pending + IF Fault = "missing_cancel_count" THEN 0 ELSE 1
    /\ UNCHANGED <<episode,target,other,closed,reclaimed,freed,safe,callbacks,tick>>
TargetFinal(op) ==
    /\ op \in target /\ ~reclaimed
    /\ target' = target \ {op}
    /\ retry' = IF Fault = "retry_not_cleared" THEN retry ELSE retry \ {op}
    /\ pending' = pending - 1
    /\ UNCHANGED <<episode,cancel,other,closed,reclaimed,freed,safe,callbacks,tick>>
CancelFinal(op) ==
    /\ op \in cancel /\ ~reclaimed
    /\ cancel' = cancel \ {op} /\ pending' = pending - 1
    /\ UNCHANGED <<episode,target,retry,other,closed,reclaimed,freed,safe,callbacks,tick>>
OtherFinal ==
    /\ other /\ ~reclaimed /\ other' = FALSE /\ pending' = pending - 1
    /\ UNCHANGED <<episode,target,cancel,retry,closed,reclaimed,freed,safe,callbacks,tick>>

\* MORE is a delivery, not a final ownership release, even for cancellation.
More(op) ==
    /\ op \in target /\ ~reclaimed
    /\ target' = IF Fault = "more_final" THEN target \ {op} ELSE target
    /\ pending' = pending - IF Fault = "more_final" THEN 1 ELSE 0
    /\ safe' = (safe /\ target' = target /\ pending' = pending)
    /\ tick' = ~tick
    /\ UNCHANGED <<episode,cancel,retry,other,closed,reclaimed,freed,callbacks>>
MoreCancel(op) ==
    /\ op \in cancel /\ ~reclaimed
    /\ cancel' = IF Fault = "more_final" THEN cancel \ {op} ELSE cancel
    /\ pending' = pending - IF Fault = "more_final" THEN 1 ELSE 0
    /\ safe' = (safe /\ cancel' = cancel /\ pending' = pending) /\ tick' = ~tick
    /\ UNCHANGED <<episode,target,retry,other,closed,reclaimed,freed,callbacks>>
RetryFull(op) ==
    /\ op \in retry /\ ~reclaimed /\ tick' = ~tick
    /\ UNCHANGED <<episode,target,cancel,retry,pending,other,closed,reclaimed,freed,safe,callbacks>>
Ignored(op,kind) ==
    /\ ~reclaimed /\ op \in Ops
    /\ kind \in {"duplicate", "duplicate_cancel", "stale", "aux"}
    /\ (kind = "duplicate" => op \notin target)
    /\ (kind = "duplicate_cancel" => op \notin cancel)
    /\ (kind = "stale" => episode > 1)
    /\ LET corrupt == (kind \in {"duplicate", "duplicate_cancel"} /\ Fault = "duplicate_final") \/
                       (kind = "stale" /\ Fault = "stale_final") \/
                       (kind = "aux" /\ Fault = "wrong_aux") IN
       /\ pending' = IF corrupt /\ pending > 0 THEN pending - 1 ELSE pending
       /\ safe' = safe
       /\ callbacks' = callbacks + IF kind = "stale" /\ Fault = "stale_callback" THEN 1 ELSE 0
    /\ tick' = ~tick
    /\ UNCHANGED <<episode,target,cancel,retry,other,closed,reclaimed,freed>>
Reclaim ==
    /\ closed /\ (~reclaimed \/ Fault = "double_reclaim")
    /\ ((Owned = {} /\ ~other /\ pending = 0) \/ Fault = "early_reclaim")
    /\ reclaimed' = TRUE /\ freed' = freed + 1
    /\ UNCHANGED <<episode,target,cancel,retry,pending,other,closed,safe,callbacks,tick>>
Reuse ==
    /\ reclaimed /\ episode < Episodes /\ episode' = episode + 1
    /\ target' = Ops /\ retry' \in SUBSET Ops /\ cancel' = Ops \ retry'
    /\ other' = TRUE /\ pending' = Count(target',cancel',other')
    /\ closed' = FALSE /\ reclaimed' = FALSE
    /\ UNCHANGED <<freed,safe,callbacks,tick>>
Done == episode = Episodes /\ reclaimed
Work == Close \/ (\E op \in Ops: RetrySubmit(op) \/ TargetFinal(op) \/ CancelFinal(op) \/ More(op) \/ MoreCancel(op) \/ RetryFull(op)) \/
        (\E op \in Ops, kind \in {"duplicate", "duplicate_cancel", "stale", "aux"}: Ignored(op,kind)) \/
        OtherFinal \/ Reclaim \/ Reuse
Next == Work \/ (Done /\ UNCHANGED vars)
Spec == Init /\ [][Next]_vars /\ WF_vars(Close) /\ WF_vars(OtherFinal) /\
        WF_vars(Reclaim) /\ WF_vars(Reuse) /\
        (IF Fault = "unfair_target" THEN TRUE
         ELSE \A op \in Ops: WF_vars(TargetFinal(op))) /\
        (IF Fault = "unfair_cancel" THEN TRUE
         ELSE \A op \in Ops: WF_vars(CancelFinal(op)))
Safety == /\ episode \in 1..Episodes /\ target \subseteq Ops /\ cancel \subseteq Ops
          /\ retry \subseteq target /\ retry \intersect cancel = {}
          /\ pending \in Nat /\ pending = Count(target,cancel,other)
          /\ other \in BOOLEAN /\ closed \in BOOLEAN /\ reclaimed \in BOOLEAN
          /\ safe /\ callbacks = 0 /\ freed = episode - 1 + IF reclaimed THEN 1 ELSE 0
          /\ (reclaimed => closed /\ Owned = {} /\ pending = 0 /\ ~other)
Settles == <>Done
====
