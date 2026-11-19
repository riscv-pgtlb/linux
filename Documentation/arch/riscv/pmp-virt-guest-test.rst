PMP.Virt cooperative VS/HS execution test
=======================================

Build with CONFIG_RISCV_PMP_VIRT_GUEST_TEST=y and boot the guest with
pmpvirt_guest_test=1. Both switches default to off. Use RV64 lkvm with
--pmp-virt-test and one vCPU, plus the paired host /dev/pvtest ioctl 0x57.
The probe runs in guest kernel context at late_initcall time, not userspace.
It does not independently detect virtualization; only run it in the guest.

The test uses experimental SBI extension 0x08000057, inside KVM's forwarded
experimental range. This is distinct from the firmware seal extension.
SBI BASE probe checks endpoint availability, not host ioctl readiness.

Sequence
--------

1. Allocate one zeroed page, write fixed RV64 instructions returning 42,
   create an RX kernel alias and synchronize the instruction cache.
2. Execute the page in VS and require result 42. Log its GPA.
3. BEGIN (function 0, a0=GPA, a1=42, other args zero) exits synchronously to
   lkvm. The host pins the backing page, verifies an HS RX/U0 alias and
   requires an instruction access fault, cause 1. The pin remains held.
4. After BEGIN succeeds, execute the unchanged page again and require 42.
5. COMPLETE (function 1, same GPA and result) checks the same host backing
   page, rechecks the HS denial and releases the host session.
6. Emit the final marker only after both SBI replies succeed. Release the
   guest alias and page after the protocol finishes.

Expected guest records::

  PMP.Virt VS BEFORE PASS: GPA=... result=42
  PMP.Virt VS AFTER PASS: GPA=... result=42
  PMP.Virt VS-HS-VS SAME-PAGE PASS: GPA=...

A protocol failure emits VS-HS-VS FAIL and no final PASS. ABORT (function 2,
all arguments zero) closes an incomplete host session. Unexpected instruction
access faults follow normal kernel fault handling, not a recovery hook.
An initcall failure does not necessarily stop boot: regression callers must
require the final marker and reject faults and FAIL records.

GPA is not HPA. Host and lkvm logs provide the HPA and matching session result.
This is a cooperative, single-vCPU test: the guest, hypervisor and memory
layout are assumed not to maliciously change code or backing mappings. Host
checks happen at BEGIN and COMPLETE; this is not continuous monitoring or
attestation. Writable aliases still exist in both RAM mappings. A pin prevents
page migration/reuse, not all possible mapping changes or writes.

The SDK regression/parser and source version locks have not yet been updated
to enable this experiment. Object compilation alone does not prove that the
three phases run correctly under KVM.

Executable alias setup
----------------------

Generic vmap strips executable permission using pgprot_nx even if the caller
supplies PAGE_KERNEL_READ_EXEC. The probe explicitly walks its own alias PTE,
checks that it maps the dedicated page with R/U0/no-W, sets EXEC, flushes the
kernel TLB range and then walks it again to require RX/U0 on the same page.
Only after that verification does it execute the instructions. Passing an RX
protection to vmap alone caused the first real guest run to fault with cause
12 (instruction page fault), before the host comparison was reached.
