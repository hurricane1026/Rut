---- MODULE RutRuntimeState ----
EXTENDS Naturals

\* @rut.states: Idle ReadingHeader ReadingBody ExecHandler Proxying Sending
\* @rut.slots: Recv Send UpstreamRecv UpstreamSend
\* @rut.action AcceptToReadingHeader: on_accept check_reading_header_invariant
\* @rut.action HeaderStaticToSending: static_dispatch_keeps_slots_consistent check_sending_response_invariant
\* @rut.action HeaderProxyConnectToProxying: proxy_dispatch_keeps_slots_consistent check_proxying_upstream_wait_invariant
\* @rut.action HeaderJitBodyToReadingBody: jit_content_length_body_waits_until_full_buffer check_jit_reading_body_invariant
\* @rut.action HeaderJitYieldToExecHandler: jit_body_completion_enters_exec_handler_before_resume check_exec_handler_yield_invariant
\* @rut.action BodyCompleteToExecHandler: jit_body_completion_enters_exec_handler_before_resume check_exec_handler_yield_invariant
\* @rut.action JitYieldTimer: jit_timer_yield_keeps_exec_handler_slots_clear check_exec_handler_yield_invariant
\* @rut.action JitYieldEvent: jit_event_yield_resumes_only_on_matching_event check_exec_handler_yield_invariant
\* @rut.action JitTerminalToSending: jit_timer_yield_keeps_exec_handler_slots_clear check_sending_response_invariant
\* @rut.action ProxyConnectFailureToSending: connect_failure_drops_proxy_slots check_sending_response_invariant
\* @rut.action ProxyResponseHeadersToSending: streaming_response_body_wait_is_explicit_sending_exception check_sending_response_invariant
\* @rut.action StreamingResponseBodyWait: streaming_response_body_wait_is_explicit_sending_exception check_sending_waiting_upstream_body_invariant
\* @rut.action ProxyBodyStreaming: body_streaming_slots_match_proxying_state check_proxying_body_stream_invariant
\* @rut.action ProxyEarlyResponseDeferral: early_response_during_body_send_has_one_upstream_slot check_proxying_upstream_send_only_invariant
\* @rut.action SendCompleteToReadingHeader: static_dispatch_keeps_slots_consistent check_reading_header_invariant
\* @rut.action SendCompleteToIdle: static_dispatch_keeps_slots_consistent check_idle_invariant
\* @rut.action CloseToIdle: free_conn_clears_active_proxy_state check_idle_invariant

States == {"Idle", "ReadingHeader", "ReadingBody", "ExecHandler", "Proxying", "Sending"}
Slots == {"Recv", "Send", "UpstreamRecv", "UpstreamSend"}
Actions == {
    "Init",
    "AcceptToReadingHeader",
    "HeaderStaticToSending",
    "HeaderProxyConnectToProxying",
    "HeaderJitBodyToReadingBody",
    "HeaderJitYieldToExecHandler",
    "BodyCompleteToExecHandler",
    "JitYieldTimer",
    "JitYieldEvent",
    "JitTerminalToSending",
    "ProxyConnectFailureToSending",
    "ProxyResponseHeadersToSending",
    "StreamingResponseBodyWait",
    "ProxyBodyStreaming",
    "ProxyEarlyResponseDeferral",
    "SendCompleteToReadingHeader",
    "SendCompleteToIdle",
    "CloseToIdle"
}

VARIABLES state,
          slots,
          fdAlive,
          upstreamAlive,
          pendingHandler,
          handlerState,
          yieldArmed,
          pendingOps,
          lastAction

vars == <<state, slots, fdAlive, upstreamAlive, pendingHandler, handlerState, yieldArmed, pendingOps, lastAction>>

TypeOK ==
    /\ state \in States
    /\ slots \subseteq Slots
    /\ fdAlive \in BOOLEAN
    /\ upstreamAlive \in BOOLEAN
    /\ pendingHandler \in BOOLEAN
    /\ handlerState \in Nat
    /\ yieldArmed \in BOOLEAN
    /\ pendingOps \in Nat
    /\ lastAction \in Actions

IdleInvariant ==
    state = "Idle" =>
        /\ slots = {}
        /\ fdAlive = FALSE
        /\ upstreamAlive = FALSE
        /\ pendingHandler = FALSE
        /\ handlerState = 0
        /\ yieldArmed = FALSE
        /\ pendingOps = 0

ReadingHeaderInvariant ==
    state = "ReadingHeader" =>
        /\ fdAlive = TRUE
        /\ upstreamAlive = FALSE
        /\ slots = {"Recv"}
        /\ pendingHandler = FALSE
        /\ yieldArmed = FALSE

ReadingBodyInvariant ==
    state = "ReadingBody" =>
        /\ fdAlive = TRUE
        /\ slots = {"Recv"}
        /\ pendingHandler = FALSE
        /\ yieldArmed = FALSE

ExecHandlerInvariant ==
    state = "ExecHandler" =>
        /\ fdAlive = TRUE
        /\ slots = {}
        /\ pendingHandler = TRUE
        /\ handlerState > 0
        /\ yieldArmed = TRUE

ProxyingInvariant ==
    state = "Proxying" =>
        /\ fdAlive = TRUE
        /\ upstreamAlive = TRUE
        /\ pendingHandler = FALSE
        /\ yieldArmed = FALSE
        /\ slots \subseteq {"Recv", "UpstreamRecv", "UpstreamSend"}
        /\ "Send" \notin slots

SendingInvariant ==
    state = "Sending" =>
        /\ fdAlive = TRUE
        /\ pendingHandler = FALSE
        /\ yieldArmed = FALSE
        /\ (slots = {"Send"} \/ slots = {"UpstreamRecv"})
        /\ (slots = {"UpstreamRecv"} => upstreamAlive = TRUE)

NoDanglingUpstreamCallbacks ==
    upstreamAlive = FALSE =>
        /\ "UpstreamRecv" \notin slots
        /\ "UpstreamSend" \notin slots

Invariant ==
    /\ IdleInvariant
    /\ ReadingHeaderInvariant
    /\ ReadingBodyInvariant
    /\ ExecHandlerInvariant
    /\ ProxyingInvariant
    /\ SendingInvariant
    /\ NoDanglingUpstreamCallbacks

Init ==
    /\ state = "Idle"
    /\ slots = {}
    /\ fdAlive = FALSE
    /\ upstreamAlive = FALSE
    /\ pendingHandler = FALSE
    /\ handlerState = 0
    /\ yieldArmed = FALSE
    /\ pendingOps = 0
    /\ lastAction = "Init"

AcceptToReadingHeader ==
    /\ state = "Idle"
    /\ state' = "ReadingHeader"
    /\ slots' = {"Recv"}
    /\ fdAlive' = TRUE
    /\ upstreamAlive' = FALSE
    /\ pendingHandler' = FALSE
    /\ handlerState' = 0
    /\ yieldArmed' = FALSE
    /\ pendingOps' \in 0..1
    /\ lastAction' = "AcceptToReadingHeader"

HeaderStaticToSending ==
    /\ state = "ReadingHeader"
    /\ state' = "Sending"
    /\ slots' = {"Send"}
    /\ fdAlive' = TRUE
    /\ upstreamAlive' = FALSE
    /\ pendingHandler' = FALSE
    /\ handlerState' = 0
    /\ yieldArmed' = FALSE
    /\ pendingOps' \in 0..1
    /\ lastAction' = "HeaderStaticToSending"

HeaderProxyConnectToProxying ==
    /\ state = "ReadingHeader"
    /\ state' = "Proxying"
    /\ slots' = {"UpstreamSend"}
    /\ fdAlive' = TRUE
    /\ upstreamAlive' = TRUE
    /\ pendingHandler' = FALSE
    /\ handlerState' = 0
    /\ yieldArmed' = FALSE
    /\ pendingOps' \in 0..1
    /\ lastAction' = "HeaderProxyConnectToProxying"

HeaderJitBodyToReadingBody ==
    /\ state = "ReadingHeader"
    /\ state' = "ReadingBody"
    /\ slots' = {"Recv"}
    /\ fdAlive' = TRUE
    /\ upstreamAlive' = FALSE
    /\ pendingHandler' = FALSE
    /\ handlerState' = 0
    /\ yieldArmed' = FALSE
    /\ pendingOps' \in 0..1
    /\ lastAction' = "HeaderJitBodyToReadingBody"

HeaderJitYieldToExecHandler ==
    /\ state = "ReadingHeader"
    /\ state' = "ExecHandler"
    /\ slots' = {}
    /\ fdAlive' = TRUE
    /\ upstreamAlive' = FALSE
    /\ pendingHandler' = TRUE
    /\ handlerState' \in 1..16
    /\ yieldArmed' = TRUE
    /\ pendingOps' \in 0..2
    /\ lastAction' = "HeaderJitYieldToExecHandler"

BodyCompleteToExecHandler ==
    /\ state = "ReadingBody"
    /\ state' = "ExecHandler"
    /\ slots' = {}
    /\ fdAlive' = TRUE
    /\ upstreamAlive' = FALSE
    /\ pendingHandler' = TRUE
    /\ handlerState' \in 1..16
    /\ yieldArmed' = TRUE
    /\ pendingOps' \in 0..2
    /\ lastAction' = "BodyCompleteToExecHandler"

JitYieldTimer ==
    /\ state = "ExecHandler"
    /\ state' = "ExecHandler"
    /\ slots' = {}
    /\ fdAlive' = TRUE
    /\ upstreamAlive' = upstreamAlive
    /\ pendingHandler' = TRUE
    /\ handlerState' \in 1..16
    /\ yieldArmed' = TRUE
    /\ pendingOps' \in 0..2
    /\ lastAction' = "JitYieldTimer"

JitYieldEvent ==
    /\ state = "ExecHandler"
    /\ state' = "ExecHandler"
    /\ slots' = {}
    /\ fdAlive' = TRUE
    /\ upstreamAlive' = upstreamAlive
    /\ pendingHandler' = TRUE
    /\ handlerState' \in 1..16
    /\ yieldArmed' = TRUE
    /\ pendingOps' \in 0..2
    /\ lastAction' = "JitYieldEvent"

JitTerminalToSending ==
    /\ state = "ExecHandler"
    /\ state' = "Sending"
    /\ slots' = {"Send"}
    /\ fdAlive' = TRUE
    /\ upstreamAlive' = FALSE
    /\ pendingHandler' = FALSE
    /\ handlerState' = 0
    /\ yieldArmed' = FALSE
    /\ pendingOps' \in 0..1
    /\ lastAction' = "JitTerminalToSending"

ProxyConnectFailureToSending ==
    /\ state = "Proxying"
    /\ state' = "Sending"
    /\ slots' = {"Send"}
    /\ fdAlive' = TRUE
    /\ upstreamAlive' = FALSE
    /\ pendingHandler' = FALSE
    /\ handlerState' = 0
    /\ yieldArmed' = FALSE
    /\ pendingOps' \in 0..1
    /\ lastAction' = "ProxyConnectFailureToSending"

ProxyResponseHeadersToSending ==
    /\ state = "Proxying"
    /\ state' = "Sending"
    /\ slots' = {"Send"}
    /\ fdAlive' = TRUE
    /\ upstreamAlive' = TRUE
    /\ pendingHandler' = FALSE
    /\ handlerState' = 0
    /\ yieldArmed' = FALSE
    /\ pendingOps' \in 0..1
    /\ lastAction' = "ProxyResponseHeadersToSending"

StreamingResponseBodyWait ==
    /\ state = "Sending"
    /\ state' = "Sending"
    /\ slots' = {"UpstreamRecv"}
    /\ fdAlive' = TRUE
    /\ upstreamAlive' = TRUE
    /\ pendingHandler' = FALSE
    /\ handlerState' = 0
    /\ yieldArmed' = FALSE
    /\ pendingOps' \in 0..1
    /\ lastAction' = "StreamingResponseBodyWait"

ProxyBodyStreaming ==
    /\ state = "Proxying"
    /\ state' = "Proxying"
    /\ slots' \in {{"Recv", "UpstreamSend"}, {"Recv", "UpstreamRecv", "UpstreamSend"}}
    /\ fdAlive' = TRUE
    /\ upstreamAlive' = TRUE
    /\ pendingHandler' = FALSE
    /\ handlerState' = 0
    /\ yieldArmed' = FALSE
    /\ pendingOps' \in 0..2
    /\ lastAction' = "ProxyBodyStreaming"

ProxyEarlyResponseDeferral ==
    /\ state = "Proxying"
    /\ state' = "Proxying"
    /\ slots' = {"UpstreamSend"}
    /\ fdAlive' = TRUE
    /\ upstreamAlive' = TRUE
    /\ pendingHandler' = FALSE
    /\ handlerState' = 0
    /\ yieldArmed' = FALSE
    /\ pendingOps' \in 0..1
    /\ lastAction' = "ProxyEarlyResponseDeferral"

SendCompleteToReadingHeader ==
    /\ state = "Sending"
    /\ state' = "ReadingHeader"
    /\ slots' = {"Recv"}
    /\ fdAlive' = TRUE
    /\ upstreamAlive' = FALSE
    /\ pendingHandler' = FALSE
    /\ handlerState' = 0
    /\ yieldArmed' = FALSE
    /\ pendingOps' \in 0..1
    /\ lastAction' = "SendCompleteToReadingHeader"

SendCompleteToIdle ==
    /\ state = "Sending"
    /\ state' = "Idle"
    /\ slots' = {}
    /\ fdAlive' = FALSE
    /\ upstreamAlive' = FALSE
    /\ pendingHandler' = FALSE
    /\ handlerState' = 0
    /\ yieldArmed' = FALSE
    /\ pendingOps' = 0
    /\ lastAction' = "SendCompleteToIdle"

CloseToIdle ==
    /\ state \in States
    /\ state' = "Idle"
    /\ slots' = {}
    /\ fdAlive' = FALSE
    /\ upstreamAlive' = FALSE
    /\ pendingHandler' = FALSE
    /\ handlerState' = 0
    /\ yieldArmed' = FALSE
    /\ pendingOps' = 0
    /\ lastAction' = "CloseToIdle"

Next ==
    \/ AcceptToReadingHeader
    \/ HeaderStaticToSending
    \/ HeaderProxyConnectToProxying
    \/ HeaderJitBodyToReadingBody
    \/ HeaderJitYieldToExecHandler
    \/ BodyCompleteToExecHandler
    \/ JitYieldTimer
    \/ JitYieldEvent
    \/ JitTerminalToSending
    \/ ProxyConnectFailureToSending
    \/ ProxyResponseHeadersToSending
    \/ StreamingResponseBodyWait
    \/ ProxyBodyStreaming
    \/ ProxyEarlyResponseDeferral
    \/ SendCompleteToReadingHeader
    \/ SendCompleteToIdle
    \/ CloseToIdle

Spec == Init /\ [][Next]_vars

====
