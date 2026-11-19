PMP.Virt host same-page test interface
=====================================

The experimental /dev/pvtest retains its existing HU ioctl 0x56 and adds
PV_GUEST_PROBE, _IOWR('V', 0x57, struct pv_guest_request). The request contains
four u64 fields: operation, address (host userspace VA), physical (HPA), cause.
All operations require CAP_SYS_ADMIN, completed boot probes and one online CPU.

BEGIN (operation 0) requires zero input physical/cause and an aligned ordinary
anonymous writable page. The implementation holds the mmap read lock, pins
with FOLL_WRITE | FOLL_LONGTERM, checks the fixed eight-byte return-42 payload,
creates an HS RX/U0 alias, checks executable PTE permissions, and requires an
instruction access fault with cause 1. Successful return supplies HPA/cause;
the pin and an mm reference remain attached to the open file.

COMPLETE (operation 1) requires the same mm, VA, expected HPA and zero input
cause. It pins the current mapping again, compares struct page identity with
the retained page and repeats payload/PTE/HS checks. Success returns the same
HPA and cause 1. An accepted COMPLETE releases the session even if checks
fail. Invalid arguments may leave the session active; close the fd to abort.
File release always unpins and drops the mm reference. The existing HU and
new guest probes share a mutex around their global exception-test state.

This is a cooperative experiment, not a general guest memory ioctl. It only
supports 4 KiB pages and ordinary anonymous RAM, not hugetlbfs or device/file
mappings. Holding a pin prevents migration/reuse, not all writes or malicious
remapping. Mapping and payload are checked at the two endpoints; the test
assumes guest code and hypervisor backing mappings remain stable in between.

The companion lkvm endpoint and VS guest must complete both phases, and their
logs must agree, before the experiment is considered successful. Object
compilation and mocked SBI tests are not runtime permission evidence.
