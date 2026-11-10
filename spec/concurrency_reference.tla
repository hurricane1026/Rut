---- MODULE concurrency_reference ----
EXTENDS Naturals, Sequences

\* Independent TLC semantics for models exported by test_concurrency_verifier.
\* Action assertions are safety properties, never enabling conditions.
CONSTANTS ActorCount, Initial, Terminal, InitialBits, TerminalClear,
          Actions, Invariants, FairGroups
VARIABLES pc, bits, safe, tick
vars == <<pc, bits, safe, tick>>

Done == pc = Terminal
Init == /\ pc = Initial
        /\ bits = InitialBits
        /\ safe = TRUE
        /\ tick = FALSE

Step(i) ==
    LET a == Actions[i] IN
    /\ ~Done
    /\ pc[a.actor] = a.source
    /\ a.needs \subseteq bits
    /\ a.absent \intersect bits = {}
    /\ pc' = [pc EXCEPT ![a.actor] = a.target]
    /\ bits' = (bits \ a.remove) \union a.add
    /\ safe' = (safe /\ a.assertSet \subseteq bits /\ a.assertClear \intersect bits = {})
    \* An executed no-op still counts as scheduling its fairness group.
    /\ tick' = ~tick

Group(g) == \E i \in 1..Len(Actions): Actions[i].fair = g /\ Step(i)
Work == \E i \in 1..Len(Actions): Step(i)
Next == Work \/ (Done /\ UNCHANGED vars)
\* Match maximal native executions: a runnable scheduler cannot idle forever.
Spec == Init /\ [][Next]_vars /\ WF_vars(Work) /\
        (\A g \in FairGroups: WF_vars(Group(g)))

Safety ==
    /\ safe
    /\ (Done => bits \intersect TerminalClear = {})
    /\ \A i \in 1..Len(Invariants):
        LET inv == Invariants[i] IN
        (inv.whenSet \subseteq bits /\ inv.whenClear \intersect bits = {}) =>
            (inv.requireSet \subseteq bits /\ inv.requireClear \intersect bits = {})
Termination == <>Done
====
