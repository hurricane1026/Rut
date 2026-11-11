---- MODULE wait_scheduler ----
EXTENDS Naturals, Sequences, FiniteSets, TLC
\* Bounded logical scheduling contract; not extraction/proof of kernel/C++.
\* Small BatchLimit explores the boundary; C++ tests cover 64/65/129 owners.
\* Backend completion-ring deferral is outside this model; C++ backend tests
\* cover its bounded send-state behavior.
CONSTANTS OwnerCount, BatchLimit, Fault
ASSUME /\ OwnerCount \in Nat /\ OwnerCount > 0
       /\ BatchLimit \in Nat /\ BatchLimit > 0
       /\ Fault \in {"none", "inline", "lifo", "redrain", "no_fence", "no_cancel",
                       "stale_wake", "blocking", "unfair_scheduler", "unfair_io", "no_shutdown_cancel"}
Owners == 1..OwnerCount
Token(o,g,p) == [owner |-> o, gen |-> g, pc |-> p]
Tokens == [owner : Owners, gen : 1..2, pc : 0..1]
VARIABLES state, gen, pc, queue, batch, phase, owed, settled, resumed, served, safe, dispatched
vars == <<state,gen,pc,queue,batch,phase,owed,settled,resumed,served,safe,dispatched>>
Entries(s) == {s[i] : i \in 1..Len(s)}
Without(s,o) == SelectSeq(s,LAMBDA t: t.owner # o)
Prefix(s) == SubSeq(s,1,IF Len(s) < BatchLimit THEN Len(s) ELSE BatchLimit)
Live(t) == gen[t.owner] = t.gen /\ pc[t.owner] = t.pc /\ state[t.owner] = "Ready"
Init == /\ state = [o \in Owners |-> "Running"]
        /\ gen = [o \in Owners |-> 1] /\ pc = [o \in Owners |-> 0]
        /\ queue = <<>> /\ batch = <<>> /\ phase = "Begin"
        /\ owed = {} /\ settled = {} /\ resumed = {} /\ served = {} /\ safe = TRUE /\ dispatched = {}
Publish(o) ==
    LET t == Token(o,gen[o],pc[o]) IN
    /\ state[o] = "Running"
    /\ state' = [state EXCEPT ![o] = "Ready"]
    /\ owed' = owed \union {t} /\ queue' = Append(queue,t)
    /\ safe' = safe
    /\ resumed' = IF Fault = "inline" THEN resumed \union {t} ELSE resumed
    /\ UNCHANGED <<gen,pc,batch,phase,settled,served,dispatched>>
ArmIO(o) ==
    /\ state[o] = "Running"
    /\ state' = [state EXCEPT ![o] = "IO"]
    /\ owed' = owed \union {Token(o,gen[o],pc[o])}
    /\ UNCHANGED <<gen,pc,queue,batch,phase,settled,resumed,served,safe,dispatched>>
Execute(o) == Publish(o) \/ ArmIO(o)
Begin ==
    LET chosen == IF Fault = "lifo" /\ Len(queue) > 1
                  THEN <<queue[Len(queue)]>> ELSE Prefix(queue) IN
    /\ phase = "Begin" /\ batch' = chosen
    /\ queue' = IF Fault = "lifo" /\ Len(queue) > 1
                THEN SubSeq(queue,1,Len(queue)-1)
                ELSE SubSeq(queue,Len(chosen)+1,Len(queue))
    /\ safe' = (safe /\ (chosen = Prefix(queue)))
    /\ served' = {} /\ phase' = "Drain"
    /\ dispatched' = dispatched \union Entries(chosen)
    /\ UNCHANGED <<state,gen,pc,owed,settled,resumed>>
Resume ==
    LET t == Head(batch)
        o == t.owner
        valid == Live(t)
        run == valid \/ Fault = "no_fence"
        more == run /\ pc[o] = 0
        next == Token(o,gen[o],1)
    IN
    /\ phase = "Drain" /\ Len(batch) > 0
    /\ batch' = IF Fault = "redrain" /\ more
                THEN Append(Tail(batch),next) ELSE Tail(batch)
    /\ queue' = IF more /\ Fault # "redrain" THEN Append(queue,next) ELSE queue
    /\ pc' = IF run THEN [pc EXCEPT ![o] = @ + 1] ELSE pc
    /\ state' = IF run THEN [state EXCEPT ![o] = IF more THEN "Ready" ELSE "Done"] ELSE state
    /\ owed' = IF more THEN owed \union {next} ELSE owed
    /\ settled' = IF run THEN settled \union {t} ELSE settled
    /\ resumed' = IF run THEN resumed \union {t} ELSE resumed
    /\ served' = IF run THEN served \union {o} ELSE served
    /\ safe' = (safe /\ (~run \/ (valid /\ t \notin resumed /\ o \notin served)))
    /\ UNCHANGED <<gen,phase,dispatched>>
EndDrain ==
    /\ phase = "Drain" /\ batch = <<>> /\ phase' = "Poll"
    /\ UNCHANGED <<state,gen,pc,queue,batch,owed,settled,resumed,served,safe,dispatched>>
Poll ==
    /\ phase = "Poll" /\ ~(Fault = "blocking" /\ Len(queue) > 0)
    /\ phase' = "Begin"
    /\ UNCHANGED <<state,gen,pc,queue,batch,owed,settled,resumed,served,safe,dispatched>>
Scheduler == Begin \/ Resume \/ EndDrain \/ Poll
IOComplete(o) ==
    LET t == Token(o,gen[o],pc[o]) IN
    /\ phase = "Poll" /\ state[o] = "IO"
    /\ pc' = [pc EXCEPT ![o] = @ + 1]
    /\ state' = [state EXCEPT ![o] = IF pc[o] = 0 THEN "Running" ELSE "Done"]
    /\ settled' = settled \union {t} /\ resumed' = resumed \union {t}
    /\ safe' = (safe /\ (t \notin resumed))
    /\ dispatched' = dispatched \union {t}
    /\ UNCHANGED <<gen,queue,batch,phase,owed,served>>
Close(o) ==
    /\ state[o] \notin {"Closed","Done"}
    /\ state' = [state EXCEPT ![o] = "Closed"]
    /\ queue' = IF Fault = "no_cancel" THEN queue ELSE Without(queue,o)
    /\ settled' = settled \union {t \in owed: t.owner = o /\ t.gen = gen[o]}
    /\ UNCHANGED <<gen,pc,batch,phase,owed,resumed,served,safe,dispatched>>
Reuse(o) ==
    /\ phase # "Stopped"
    /\ state[o] = "Closed" /\ gen[o] = 1
    /\ gen' = [gen EXCEPT ![o] = 2] /\ pc' = [pc EXCEPT ![o] = 0]
    /\ state' = [state EXCEPT ![o] = "Running"]
    /\ UNCHANGED <<queue,batch,phase,owed,settled,resumed,served,safe,dispatched>>
\* Healthy code ignores old CQEs while a ready completion owns the wakeup.
StaleWake(o) ==
    /\ Fault = "stale_wake" /\ phase = "Poll" /\ state[o] = "Ready"
    /\ \E t \in Entries(queue): t.owner = o
    /\ resumed' = resumed \union {Token(o,gen[o],pc[o])}
    /\ UNCHANGED <<state,gen,pc,queue,batch,phase,owed,settled,served,safe,dispatched>>
Shutdown ==
    /\ phase # "Stopped"
    /\ phase' = "Stopped" /\ state' = [o \in Owners |-> "Closed"]
    /\ queue' = IF Fault = "no_shutdown_cancel" THEN queue ELSE <<>>
    /\ batch' = <<>> /\ settled' = settled \union owed
    /\ UNCHANGED <<gen,pc,owed,resumed,served,safe,dispatched>>
Next == Shutdown \/ (phase = "Stopped" /\ UNCHANGED vars) \/ Scheduler \/ (\E o \in Owners: Execute(o) \/ IOComplete(o) \/ Close(o) \/ Reuse(o) \/ StaleWake(o))
Spec == Init /\ [][Next]_vars /\ (IF Fault = "unfair_scheduler" THEN TRUE ELSE WF_vars(Scheduler)) /\
        (\A o \in Owners: WF_vars(Execute(o)) /\
            (IF Fault = "unfair_io" THEN WF_vars(IOComplete(o)) ELSE SF_vars(IOComplete(o))))
Safety == /\ safe
          /\ \A t \in Entries(queue): Live(t)
          /\ Cardinality({t.owner: t \in Entries(queue)}) = Len(queue)
          /\ resumed \subseteq owed
          /\ resumed \subseteq dispatched
\* A pending obligation eventually completes or is cancelled by close.
Settles == \A t \in Tokens: [](t \in owed => <> (t \in settled))
====
