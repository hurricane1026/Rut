"""Check that the production compiler gate rejects deliberate contract faults."""

from pathlib import Path
import os
import subprocess
import sys
import tempfile


def check_downstream_send(compiler, root, overlay):
    # The backend contract uses the Linux completion flag definitions.
    if not sys.platform.startswith("linux"):
        return
    source = "src/runtime/io_uring_send_target.h"
    check(compiler, root, overlay, source=source)
    for before, after in [
        ("owner == incoming &&", "(owner & 0xffff) == (incoming & 0xffff) &&"),
        ("(incoming & kNonUpstreamSendCancelBit) == 0 &&", ""),
        ("(flags & IORING_CQE_F_MORE) == 0;", "true;"),
        ("(flags & IORING_CQE_F_MORE) == 0;", "flags != IORING_CQE_F_MORE;"),
    ]:
        probe = mutate(root, overlay, source, before, after)
        check(compiler, root, overlay, "Downstream send completion violates target identity",
              source=probe)
        probe.unlink()


def mutate(include, overlay, header, before, after):
    source = (include / header).read_text()
    if source.count(before) != 1:
        raise RuntimeError(f"Update the mutation for {header}")
    path = overlay / header
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source.replace(before, after))
    return path


def check(compiler, root, overlay, diagnostic=None, source="src/compiler/handler_verifier.cc"):
    command = [compiler, "-std=c++23", "-fsyntax-only", "-I", str(overlay),
               "-I", str(root / "include"), str(root / source)]
    # A new shadow header must invalidate the positive control on every run.
    result = subprocess.run(command, capture_output=True, text=True,
                            env={**os.environ, "LC_ALL": "C", "CCACHE_DISABLE": "1"})
    if diagnostic is None:
        if result.returncode:
            raise RuntimeError(result.stderr)
    elif result.returncode == 0 or diagnostic not in result.stderr:
        raise RuntimeError(f"Expected compilation to fail with {diagnostic!r}\n{result.stderr}")


def check_timer_transport(compiler, root, overlay):
    source = "src/runtime/response_read_timer_transport.cc"
    header = "rut/runtime/io_event.h"
    check(compiler, root, overlay, source=source)
    for before, after, diagnostic in [
        ("event.result == -ENOENT", "event.result == -ETIME", "Response timer result domain mismatch"),
        ("event.copy_end == 0 && ", "", "Response timer accepts unrelated event metadata"),
        ("u8 provided_ring_empty = 0;", "u8 provided_ring_empty = 0;\n    u8 new_field = 0;",
         "names"),  # Both compilers report the mismatch in the number of binding names.
    ]:
        probe = mutate(root / "include", overlay, header, before, after)
        check(compiler, root, overlay, diagnostic, source=source)
        probe.unlink()


def main():
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as directory:
        overlay = Path(directory)
        compiler = sys.argv[1]
        source = "src/runtime/response_body_chain.cc"
        check(compiler, root, overlay, source=source)
        for before, after in [
            ("(node == chain.tail && tail_pinned)", "false"),
            ("chain.size -= kUsed;", "chain.size = 0;"),
            ("chain.head = node->next;", "chain.head = nullptr;"),
        ]:
            probe = mutate(root, overlay, source, before, after)
            check(compiler, root, overlay, "Response body consumption violates prefix or tail ownership",
                  source=probe)
            probe.unlink()
        for before, after in [
            ("tail->len += n;", "tail->len = n;"),
            ("size += n;", "size = tail->len - tail->offset;"),
            ("if (tail->dirty_end < tail->len) tail->dirty_end = tail->len;",
             "tail->dirty_end = tail->len;"),
            ("tail->len += n;", "tail->offset = 0; tail->len += n;"),
        ]:
            probe = mutate(root / "include", overlay, "rut/runtime/response_body_chain.h",
                           before, after)
            check(compiler, root, overlay, "Pinned receive commit violates buffered response suffix contract",
                  source=source)
            probe.unlink()
        for before, after in [
            ("address - begin > capacity", "static_cast<u32>(address - begin) > capacity"),
            ("count > capacity - kOffset", "count >= capacity - kOffset"),
            ("count > capacity - kOffset", "kOffset + count > capacity"),
            ("if (kEnd > node_dirty) node_dirty = kEnd;", "node_dirty = kEnd;"),
            ("if (kEnd > tail_dirty) tail_dirty = kEnd;", "tail_dirty = kEnd;"),
        ]:
            probe = mutate(root / "include", overlay, "rut/runtime/response_body_chain.h", before, after)
            check(compiler, root, overlay, "Direct receive violates physical write extent contract",
                  source=source)
            probe.unlink()
        for before, after in [
            ("result > 0 && received <= kLimit", "result >= 0 && received <= kLimit"),
            ("received <= kLimit && ", ""),
            ("declared < kMaxBody ? declared : kMaxBody", "declared"),
            ("declared < kMaxBody ? declared : kMaxBody", "kMaxBody"),
            ("static_cast<u32>(result) <= kLimit - received",
             "static_cast<u32>(result) < kLimit - received"),
        ]:
            probe = mutate(root / "include", overlay, "rut/runtime/response_body_chain.h", before, after)
            check(compiler, root, overlay, "Direct receive violates logical body bounds", source=source)
            probe.unlink()
        for before, after in [
            ("received <= kMaxBody ? kMaxBody - received + 1u : 0u", "kMaxBody - received + 1u"),
            ("received <= kMaxBody ?", "received < kMaxBody ?"),
            ("kMaxBody - received + 1u", "kMaxBody - received"),
            ("kMaxBody - received + 1u", "kMaxBody - received + 2u"),
        ]:
            probe = mutate(root / "include", overlay, "rut/runtime/response_body_chain.h", before, after)
            check(compiler, root, overlay, "Direct receive reservation violates body limit", source=source)
            probe.unlink()
        check_timer_transport(compiler, root, overlay)
        source = "src/runtime/send_progress.cc"
        check(compiler, root, overlay, source=source)
        for before, after in [
            ("completed > remaining", "completed >= remaining"),
            ("total <= INT32_MAX", "total <= UINT32_MAX"),
            ("remaining -= completed;", "remaining = 0;"),
        ]:
            probe = mutate(root / "include", overlay, "rut/runtime/send_progress.h", before, after)
            check(compiler, root, overlay, "Partial send violates byte accounting contract",
                  source=source)
            probe.unlink()
        check(compiler, root, overlay)
        source = "src/runtime/direct_body_recv_phase.cc"
        check(compiler, root, overlay, source=source)
        for before, after in [
            ("return mode == ForwardResponseBufferingMode::Bounded;", "return true;"),
            ("return mode == ForwardResponseBufferingMode::Bounded;",
             "return mode == ForwardResponseBufferingMode::Bounded && phase != Phase::WaitingBody;"),
            (" && !terminal_pending", ""),
            (" && !close_after_drain", ""),
            ("phase == ResponseReadDeadlinePostCommitPhase::Buffering ||", ""),
        ]:
            probe = mutate(root / "include", overlay, "rut/runtime/direct_body_recv_phase.h", before, after)
            check(compiler, root, overlay, "Direct body receive violates phase contract", source=source)
            probe.unlink()
        probe = mutate(root / "include", overlay, "rut/runtime/direct_body_recv_phase.h",
                       "    CombinedSend,", "    CombinedSend,\n    UnclassifiedBodyPhase,")
        check(compiler, root, overlay, "UnclassifiedBodyPhase", source=source)
        probe.unlink()
        check_downstream_send(compiler, root, overlay)
        source = "src/runtime/io_event.cc"
        check(compiler, root, overlay, source=source)
        for before, after in [
            ("event.copy_begin == expected_begin &&", ""),
            ("event.copy_end >= event.copy_begin &&", ""),
            ("event.result > 0 &&", "event.result >= 0 &&"),
            ("event.copy_witness == IoEventCopyWitness::Full &&", ""),
            ("event.copy_end - event.copy_begin ==", "event.copy_end - event.copy_begin >="),
        ]:
            probe = mutate(root / "include", overlay, "rut/runtime/io_event.h", before, after)
            check(compiler, root, overlay, "Response copy violates positive span contract", source=source)
            probe.unlink()
        for before, after in [
            ("token.aux) << 56", "token.aux) << 55"),
            ("token.episode = kInvalidUpstreamEventEpisode;", "token.episode = 0;"),
            ("case IoEventType::RelayWrite:\n            return true;",
             "case IoEventType::RelayWrite:\n            return type != IoEventType::RelayWrite;"),
        ]:
            probe = mutate(root / "include", overlay, "rut/runtime/io_event.h", before, after)
            check(compiler, root, overlay, "Upstream completion token violates wire or episode contract",
                  source=source)
            probe.unlink()
        probe = mutate(root / "include", overlay, "rut/jit/handler_abi.h",
                       "enum class YieldKind : u8 {",
                       "enum class YieldKind : u8 {\n    UndeclaredContractProbe = 255,")
        check(compiler, root, overlay, "UndeclaredContractProbe")
        probe.unlink()
        source = "src/runtime/buffered_send_vector.cc"
        check(compiler, root, overlay, source=source)
        for before, after in [
            ("source + (kSize - part.iov_len)", "source + kStep"),
            ("++message.msg_iov;", "/* leave the previous span selected */"),
            ("\n            n -= kStep;", "\n            n = 0;"),
        ]:
            probe = mutate(root / "include", overlay, "rut/runtime/buffered_send_vector.h",
                           before, after)
            check(compiler, root, overlay, "Buffered send cursor violates suffix contract", source=source)
            probe.unlink()
        probe = mutate(root / "include", overlay, "rut/runtime/buffered_send_vector.h",
                       "second_source == parts[1].iov_base && ", "")
        check(compiler, root, overlay, "Buffered send spans disagree with pinned sources", source=source)
        probe.unlink()
        probe = mutate(root / "include", overlay, "rut/jit/yield_contract.h",
                       "return {DownstreamSend, None};", "return {DownstreamRecv, None};")
        check(compiler, root, overlay, "Yield contract disagrees with RIR wait arms")
        probe.unlink()

        source = "src/runtime/io_generation.cc"
        check(compiler, root, overlay, source=source)
        for before, after in [
            ("counter >= maximum", "counter == maximum"),
            ("counter >= maximum", "counter > maximum"),
            ("owner = counter;", "owner = counter - 1;"),
        ]:
            probe = mutate(root / "include", overlay, "rut/runtime/io_event.h", before, after)
            check(compiler, root, overlay, "I/O generation allocation violates the non-wrapping contract",
                  source=source)
            probe.unlink()

        probe = mutate(root / "include", overlay, "rut/runtime/io_event.h",
                       "kResponseReadTimerGenerationMask = 0x7FFFFFFFu",
                       "kResponseReadTimerGenerationMask = 0xFFFFFFFFu")
        check(compiler, root, overlay, "Cancellation marker must remain outside the generation range",
              source=source)
        probe.unlink()

        runtime = "src/runtime/jit_dispatch.cc"
        check(compiler, root, overlay, source=runtime)
        header = "rut/runtime/jit_dispatch.h"
        mutate(root / "include", overlay, header,
               "return jit::YieldKind::Recv;", "return jit::YieldKind::Send;")
        check(compiler, root, overlay, "Event eligibility disagrees with handler completion contract",
              source=runtime)
        # Replacing the overlay starts each mutation from the original header.
        mutate(root / "include", overlay, header,
               "return contract.secondary == jit::YieldArm::Timer;", "return false;")
        check(compiler, root, overlay, "Event eligibility disagrees with handler completion contract",
              source=runtime)
        (overlay / header).unlink()
        mutate(root / "include", overlay, "rut/runtime/io_event.h",
               "    Count,\n};", "    Count,\n    UnclassifiedEvent = 254,\n};")
        check(compiler, root, overlay, "UnclassifiedEvent", source=runtime)
        (overlay / "rut/runtime/io_event.h").unlink()

        runtime = "src/runtime/response_read_timer.cc"
        header = "rut/runtime/response_read_timer.h"
        check(compiler, root, overlay, source=runtime)
        for before, after in [
            ("generation == 0 || generation != owner_generation", "generation == 0"),
            ("cancel ? cancel_owned : target_owned", "cancel ? target_owned : cancel_owned"),
            ("target_owned || cancel_owned ?", "target_owned && cancel_owned ?"),
        ]:
            mutate(root / "include", overlay, header, before, after)
            check(compiler, root, overlay, "Response-read timer completion violates ownership contract",
                  source=runtime)


if __name__ == "__main__":
    main()
