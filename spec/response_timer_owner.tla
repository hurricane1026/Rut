----------------------- MODULE response_timer_owner -----------------------
EXTENDS Naturals, FiniteSets
CONSTANTS Limit, Fault
ASSUME /\ Limit \in {1, 2, 3}
       /\ Fault \in {"none", "generation_wrap", "publish_before_sqe", "phantom_cancel",
                       "clear_on_first", "missing_generation", "accept_duplicate",
                       "reset_borrowed_storage", "clear_owned", "unfair_target", "unfair_cancel"}
Kinds == {"target", "cancel"}
VARIABLES generation, owner, phase, owned, kernel, storage, fuel, safe
vars == <<generation, owner, phase, owned, kernel, storage, fuel, safe>>
Init == /\ generation = 0 /\ owner = 0 /\ phase = "None"
        /\ owned = {} /\ kernel = {} /\ storage = 0 /\ fuel = 3 /\ safe = TRUE
\* The kernel ledger is an independent ghost: only a submitted SQE creates
\* an obligation and only its exact final CQE removes it.
Arm == /\ owned = {} /\ owner = 0
       /\ (generation < Limit \/ Fault = "generation_wrap")
       /\ generation' = IF generation = Limit THEN 1 ELSE generation + 1
       /\ owner' = generation' /\ storage' = generation' /\ phase' = "Armed"
       /\ owned' = {"target"} /\ kernel' = {"target"}
       /\ safe' = (safe /\ generation' > generation)
       /\ UNCHANGED fuel
Cancel == /\ phase = "Armed"
          /\ phase' = "CancelPending" /\ owned' = owned \cup {"cancel"}
          /\ kernel' = kernel \cup {"cancel"}
          /\ UNCHANGED <<generation, owner, storage, fuel, safe>>
ArmFull == /\ fuel > 0 /\ owner = 0
           /\ fuel' = fuel - 1
           /\ owner' = IF Fault = "publish_before_sqe" THEN generation + 1 ELSE owner
           /\ UNCHANGED <<generation, phase, owned, kernel, storage, safe>>
CancelFull == /\ fuel > 0 /\ phase = "Armed"
              /\ fuel' = fuel - 1
              /\ owned' = IF Fault = "phantom_cancel" THEN owned \cup {"cancel"} ELSE owned
              /\ UNCHANGED <<generation, owner, phase, kernel, storage, safe>>
Complete(kind) ==
    /\ kind \in kernel
    /\ kernel' = kernel \ {kind}
    /\ owned' = IF Fault = "clear_on_first" THEN {} ELSE owned \ {kind}
    /\ owner' = IF owned' = {} THEN 0 ELSE owner
    /\ storage' = IF owned' = {} THEN 0 ELSE storage
    /\ phase' = IF owned' = {} THEN "None" ELSE phase
    /\ UNCHANGED <<generation, fuel, safe>>
Ignored(kind, stale) ==
    /\ fuel > 0 /\ kind \in Kinds /\ (stale \/ kind \notin owned)
    /\ fuel' = fuel - 1
    /\ owned' = IF stale /\ Fault = "missing_generation" THEN owned \ {kind} ELSE owned
    /\ owner' = IF owned' = {} THEN 0 ELSE owner
    /\ storage' = IF owned' = {} THEN 0 ELSE storage
    /\ phase' = IF owned' = {} THEN "None" ELSE phase
    /\ safe' = (safe /\ ~(~stale /\ phase = "CancelPending" /\ Fault = "accept_duplicate"))
    /\ UNCHANGED <<generation, kernel>>
Reset == /\ fuel > 0 /\ fuel' = fuel - 1
         /\ storage' = IF Fault = "reset_borrowed_storage" THEN 0 ELSE storage
         /\ UNCHANGED <<generation, owner, phase, owned, kernel, safe>>
Clear == /\ fuel > 0 /\ fuel' = fuel - 1
         /\ owner' = IF Fault = "clear_owned" THEN 0 ELSE owner
         /\ storage' = IF Fault = "clear_owned" THEN 0 ELSE storage
         /\ UNCHANGED <<generation, phase, owned, kernel, safe>>
Next == Arm \/ Cancel \/ ArmFull \/ CancelFull \/ Reset \/ Clear
        \/ (\E kind \in Kinds : Complete(kind) \/ Ignored(kind, TRUE) \/ Ignored(kind, FALSE))
        \/ (owned = {} /\ UNCHANGED vars)
Safety == /\ safe /\ owned = kernel
          /\ (owned = {} => owner = 0 /\ storage = 0 /\ phase = "None")
          /\ (owned # {} => owner = generation /\ storage = generation /\ owner > 0)
          /\ (phase = "Armed" => owned = {"target"})
          /\ (phase = "CancelPending" => owned # {})
Settles == <>[] (owned = {} /\ owner = 0)
Spec == Init /\ [][Next]_vars
        /\ (IF Fault = "unfair_target" THEN TRUE ELSE WF_vars(Complete("target")))
        /\ (IF Fault = "unfair_cancel" THEN TRUE ELSE WF_vars(Complete("cancel")))
=============================================================================
