--------------------------- MODULE timer_wheel ---------------------------
EXTENDS Naturals, FiniteSets
CONSTANTS Slots, Budget, Fault
Owners == {1, 2}
VARIABLES cursor, fuel, armed, bucket, deadline, valid
vars == <<cursor, fuel, armed, bucket, deadline, valid>>
Init == /\ cursor = Slots - 1
        /\ fuel = Budget
        /\ armed = {}
        /\ bucket = [i \in Owners |-> 0]
        /\ deadline = [i \in Owners |-> 0]
        /\ valid = TRUE
\* API precondition: add only an unlinked node; refresh unlinks first.
Arm(i, delay) ==
    /\ fuel > 0
    /\ cursor <= Slots + Budget
    /\ armed' = armed \cup {i}
    /\ bucket' = [bucket EXCEPT ![i] =
         IF Fault = "refresh_keeps_old" /\ i \in armed THEN @
         ELSE (cursor + delay + IF Fault = "off_by_one" THEN 1 ELSE 0) % Slots]
    /\ deadline' = [deadline EXCEPT ![i] = cursor + delay]
    /\ fuel' = fuel - 1
    /\ UNCHANGED <<cursor, valid>>
Remove(i) ==
    /\ fuel > 0
    /\ armed' = IF Fault = "remove_lost" THEN armed ELSE armed \ {i}
    /\ valid' = (valid /\ (i \notin armed'))
    /\ fuel' = fuel - 1
    /\ UNCHANGED <<cursor, bucket, deadline>>
Tick ==
    /\ cursor < Slots + Budget + Slots
    /\ LET due == {i \in armed : bucket[i] = cursor % Slots}
           expected == {i \in armed : deadline[i] = cursor}
       IN /\ valid' = (valid /\ due = expected)
          /\ armed' = armed \ due
    /\ cursor' = cursor + 1
    /\ UNCHANGED <<fuel, bucket, deadline>>
Next == (fuel = 0 /\ armed = {} /\ UNCHANGED vars) \/ Tick \/ (\E i \in Owners : Remove(i) \/
                 (\E delay \in {0, 1, Slots - 1} : Arm(i, delay)))
Safety == valid /\ (\A i \in armed : deadline[i] >= cursor)
Settles == <>[] (armed = {})
\* Bounded API activity eventually stops; fair ticking drains remaining nodes.
Spec == Init /\ [][Next]_vars
        /\ (IF Fault = "unfair_tick" THEN TRUE ELSE WF_vars(Tick))
=============================================================================
