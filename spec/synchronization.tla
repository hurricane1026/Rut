---- MODULE synchronization ----
EXTENDS Naturals, FiniteSets

\* Independent bounded design contract for submit, all/any collection, and
\* owner-shard apply/ack. These constants select intentional protocol defects
\* as well as supported design paths; they do not enable new Rut syntax.
CONSTANTS WaitAll, EarlyResume, EarlyAck, SelfWait, QueueFull, Timeout,
          WaitBeforeSubmit
VARIABLES phase, submitted, completed, collected, queued, applied, acknowledged
vars == <<phase, submitted, completed, collected, queued, applied, acknowledged>>
Handles == {1, 2}
Done == phase \in {"Done", "Failed"} /\ completed = submitted
Init == /\ phase = IF WaitBeforeSubmit THEN "WaitIO" ELSE "SubmitA"
        /\ submitted = {} /\ completed = {} /\ collected = {}
        /\ queued = FALSE /\ applied = FALSE /\ acknowledged = FALSE

SubmitA == /\ phase = "SubmitA"
           /\ phase' = "SubmitB" /\ submitted' = {1}
           /\ UNCHANGED <<completed, collected, queued, applied, acknowledged>>
SubmitB == /\ phase = "SubmitB"
           /\ phase' = "WaitIO" /\ submitted' = Handles
           /\ UNCHANGED <<completed, collected, queued, applied, acknowledged>>
Complete(i) == /\ i \in submitted \ completed
               /\ completed' = completed \union {i}
               /\ UNCHANGED <<phase, submitted, collected, queued, applied, acknowledged>>
Resume == /\ phase = "WaitIO"
          /\ (EarlyResume \/ IF WaitAll THEN completed = Handles ELSE completed # {})
          /\ collected' = completed
          /\ phase' = IF QueueFull THEN "Failed" ELSE "WaitOwner"
          /\ queued' = ~QueueFull
          /\ UNCHANGED <<submitted, completed, applied, acknowledged>>
Apply == /\ queued /\ ~applied /\ ~SelfWait
         /\ applied' = TRUE
         /\ UNCHANGED <<phase, submitted, completed, collected, queued, acknowledged>>
Acknowledge == /\ queued /\ ~acknowledged /\ ~SelfWait
               /\ (applied \/ EarlyAck)
               /\ acknowledged' = TRUE
               /\ UNCHANGED <<phase, submitted, completed, collected, queued, applied>>
Finish == /\ phase = "WaitOwner" /\ acknowledged
          /\ phase' = "Done"
          /\ UNCHANGED <<submitted, completed, collected, queued, applied, acknowledged>>
Expire == /\ Timeout /\ phase \in {"WaitIO", "WaitOwner"}
          /\ phase' = "Failed"
          /\ UNCHANGED <<submitted, completed, collected, queued, applied, acknowledged>>
Work == SubmitA \/ SubmitB \/ (\E i \in Handles: Complete(i)) \/ Resume \/
        Apply \/ Acknowledge \/ Finish \/ Expire
Next == Work \/ (Done /\ UNCHANGED vars)
Spec == Init /\ [][Next]_vars /\ WF_vars(Work) /\
        (\A i \in Handles: WF_vars(Complete(i)))
TypeOK == /\ phase \in {"SubmitA", "SubmitB", "WaitIO", "WaitOwner", "Done", "Failed"}
          /\ submitted \subseteq Handles /\ completed \subseteq submitted
          /\ collected \subseteq completed
          /\ queued \in BOOLEAN /\ applied \in BOOLEAN /\ acknowledged \in BOOLEAN
Safety == /\ TypeOK
          /\ (acknowledged => applied)
          /\ (applied => queued)
          /\ (phase \in {"WaitOwner", "Done"} =>
                  IF WaitAll THEN collected = Handles ELSE collected # {})
Termination == <>Done
====
