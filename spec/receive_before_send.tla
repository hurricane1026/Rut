---- MODULE receive_before_send ----
EXTENDS Naturals

\* Reference abstraction of tests/fixtures/deadlock/*.rut, with the explicit
\* peer contract "reply only after request". Not an automatic source extractor.
\* Timeout, transport failure and close escapes are deliberately excluded.
CONSTANT ReceiveFirst
VARIABLES handler, peer, requestSent, replyReady
vars == <<handler, peer, requestSent, replyReady>>
First == IF ReceiveFirst THEN "Recv" ELSE "Send"
Second == IF ReceiveFirst THEN "Send" ELSE "Recv"
Init == /\ handler = "Connect" /\ peer = "WaitRequest"
        /\ requestSent = FALSE /\ replyReady = FALSE
Connect == /\ handler = "Connect" /\ handler' = First
           /\ UNCHANGED <<peer, requestSent, replyReady>>
Send == /\ handler = "Send"
        /\ handler' = IF First = "Send" THEN Second ELSE "Return"
        /\ requestSent' = TRUE
        /\ UNCHANGED <<peer, replyReady>>
Reply == /\ peer = "WaitRequest" /\ requestSent
         /\ peer' = "WaitConsumed" /\ replyReady' = TRUE
         /\ requestSent' = FALSE /\ UNCHANGED handler
Recv == /\ handler = "Recv" /\ replyReady
        /\ handler' = IF First = "Recv" THEN Second ELSE "Return"
        /\ replyReady' = FALSE /\ UNCHANGED <<peer, requestSent>>
PeerDone == /\ peer = "WaitConsumed" /\ ~replyReady
            /\ peer' = "Done" /\ UNCHANGED <<handler, requestSent, replyReady>>
Return == /\ handler = "Return" /\ handler' = "Done"
          /\ UNCHANGED <<peer, requestSent, replyReady>>
Done == handler = "Done" /\ peer = "Done"
Work == Connect \/ Send \/ Reply \/ Recv \/ PeerDone \/ Return
Next == Work \/ (Done /\ UNCHANGED vars)
Spec == Init /\ [][Next]_vars /\ WF_vars(Work)
Safety == /\ handler \in {"Connect", "Recv", "Send", "Return", "Done"}
          /\ peer \in {"WaitRequest", "WaitConsumed", "Done"}
          /\ requestSent \in BOOLEAN /\ replyReady \in BOOLEAN
          /\ (Done => ~requestSent /\ ~replyReady)
Termination == <>Done
====
