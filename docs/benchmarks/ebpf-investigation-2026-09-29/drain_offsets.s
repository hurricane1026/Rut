	.file	"drain_offsets.cc"
	.text
	.globl	offset_drain                    # -- Begin function offset_drain
	.p2align	4
	.type	offset_drain,@function
offset_drain:                           # @offset_drain
	.cfi_startproc
# %bb.0:
	movl	$3600, %eax                     # imm = 0xE10
	retq
.Lfunc_end0:
	.size	offset_drain, .Lfunc_end0-offset_drain
	.cfi_endproc
                                        # -- End function
	.globl	offset_phase                    # -- Begin function offset_phase
	.p2align	4
	.type	offset_phase,@function
offset_phase:                           # @offset_phase
	.cfi_startproc
# %bb.0:
	movl	$2380, %eax                     # imm = 0x94C
	retq
.Lfunc_end1:
	.size	offset_phase, .Lfunc_end1-offset_phase
	.cfi_endproc
                                        # -- End function
	.ident	"clang version 22.1.8 (Fedora 22.1.8-4.fc44)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
