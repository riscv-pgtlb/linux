/* Test-only probes; normal Linux ABI, RV64, no compressed instructions. */
#include <linux/linkage.h>
.option push
.option norvc
.text
SYM_FUNC_START(pv_test_call)
    addi sp, sp, -16
    sd ra, 0(sp)
    jalr ra, a0, 0
.globl pv_test_call_resume
pv_test_call_resume:
    ld ra, 0(sp)
    addi sp, sp, 16
    ret
SYM_FUNC_END(pv_test_call)

SYM_FUNC_START(pv_test_store)
.globl pv_test_store_insn
pv_test_store_insn:
    sb a1, 0(a0)
.globl pv_test_store_resume
pv_test_store_resume:
    ret
SYM_FUNC_END(pv_test_store)
.option pop
