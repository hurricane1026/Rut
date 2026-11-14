--------------------------- MODULE yield_timer ---------------------------
EXTENDS Naturals, FiniteSets
CONSTANTS Backend, Fault
VARIABLES epoch, waiting, armed, live, tokens, now, wins, valid, reused
vars == <<epoch, waiting, armed, live, tokens, now, wins, valid, reused>>
Init == /\ epoch = 1 /\ waiting = TRUE /\ armed = TRUE /\ live = TRUE
        /\ tokens = {1} /\ now = 0
        /\ wins = [i \in 1..2 |-> 0] /\ valid = TRUE /\ reused = FALSE
Clock == /\ now < 2 /\ now' = now + 1
         /\ UNCHANGED <<epoch, waiting, armed, live, tokens, wins, valid, reused>>
IO == /\ live /\ waiting
      /\ waiting' = FALSE
      /\ armed' = (Fault = "io_leaves_armed")
      /\ tokens' = IF Backend = "heap" THEN tokens \ {epoch} ELSE tokens
      /\ wins' = [wins EXCEPT ![epoch] = @ + 1]
      /\ UNCHANGED <<epoch, live, now, valid, reused>>
Close == /\ live /\ live' = FALSE /\ waiting' = FALSE /\ armed' = FALSE
         /\ tokens' = IF Backend = "heap" THEN {} ELSE tokens
         /\ UNCHANGED <<epoch, now, wins, valid, reused>>
Rearm == /\ live /\ ~waiting /\ epoch = 1
         /\ epoch' = 2 /\ waiting' = TRUE /\ armed' = TRUE
         /\ tokens' = tokens \cup {2}
         /\ UNCHANGED <<live, now, wins, valid, reused>>
Reuse == /\ ~live /\ ~reused /\ epoch = 1
         /\ (Backend = "heap" \/ tokens = {} \/ Fault = "early_reuse")
         /\ valid' = (valid /\ (Backend = "heap" \/ tokens = {}))
         /\ epoch' = 2 /\ live' = TRUE /\ waiting' = TRUE /\ armed' = TRUE /\ reused' = TRUE
         /\ tokens' = tokens \cup {2}
         /\ UNCHANGED <<now, wins>>
Deliver(t) ==
    /\ t \in tokens
    /\ now >= t \/ Fault = "early_fire"
    /\ LET matching == t = epoch \/ Fault = "missing_generation"
           resume == live /\ armed /\ matching
       IN /\ valid' = (valid /\ (resume => (waiting /\ t = epoch /\ now >= t)))
          /\ wins' = IF resume THEN [wins EXCEPT ![epoch] = @ + 1] ELSE wins
          /\ waiting' = IF resume THEN FALSE ELSE waiting
          /\ armed' = IF matching \/ Fault = "stale_disarms" THEN FALSE ELSE armed
    /\ tokens' = tokens \ {t}
    /\ UNCHANGED <<epoch, live, now, reused>>
Next == (~waiting /\ tokens = {} /\ UNCHANGED vars) \/ Clock \/ IO \/ Close \/ Rearm \/ Reuse \/ (\E t \in 1..2 : Deliver(t))
Safety == valid /\ (\A i \in 1..2 : wins[i] <= 1)
Settles == <>[] (~waiting /\ tokens = {})
Spec == Init /\ [][Next]_vars
        /\ (IF Fault = "unfair_clock" THEN TRUE ELSE WF_vars(Clock))
        /\ (\A t \in 1..2 : WF_vars(Deliver(t)))
=============================================================================
