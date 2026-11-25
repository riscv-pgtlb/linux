// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test the RISC-V KVM Stage2Virt userspace interface.
 */
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

#include "kvm_util.h"
#include "test_util.h"

#define TEST_GPA	0x10000000ULL
#define TEST_SLOT	1

static void stage2_virt_ioctl(struct kvm_vm *vm,
			      struct kvm_riscv_stage2_virt *request,
			      int expected_errno)
{
	int ret;

	errno = 0;
	ret = __vm_ioctl(vm, KVM_RISCV_SET_STAGE2_VIRT, request);
	if (!expected_errno) {
		TEST_ASSERT(!ret,
			    "KVM_RISCV_SET_STAGE2_VIRT failed, errno=%d (%s)",
			    errno, strerror(errno));
		return;
	}

	TEST_ASSERT(ret == -1 && errno == expected_errno,
		    "KVM_RISCV_SET_STAGE2_VIRT returned %d, errno=%d (%s), expected errno=%d",
		    ret, errno, strerror(errno), expected_errno);
}

static void set_stage2_virt(struct kvm_vm *vm, uint64_t gpa, uint64_t size,
			    uint64_t flags, int expected_errno)
{
	struct kvm_riscv_stage2_virt request = {
		.guest_phys_addr = gpa,
		.memory_size = size,
		.flags = flags,
	};

	stage2_virt_ioctl(vm, &request, expected_errno);
}

static void set_memslot(struct kvm_vm *vm, void *hva, uint64_t size,
			uint32_t flags, int expected_errno)
{
	int ret;

	errno = 0;
	ret = __vm_set_user_memory_region(vm, TEST_SLOT, flags, TEST_GPA,
					  size, hva);
	if (!expected_errno) {
		TEST_ASSERT(!ret, "KVM_SET_USER_MEMORY_REGION failed, errno=%d (%s)",
			    errno, strerror(errno));
		return;
	}

	TEST_ASSERT(ret == -1 && errno == expected_errno,
		    "KVM_SET_USER_MEMORY_REGION returned %d, errno=%d (%s), expected errno=%d",
		    ret, errno, strerror(errno), expected_errno);
}

int main(void)
{
	struct kvm_riscv_stage2_virt request;
	struct kvm_vm *vm;
	long page_size;
	void *memory;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_RISCV_STAGE2_VIRT));

	page_size = sysconf(_SC_PAGESIZE);
	TEST_ASSERT(page_size > 0, "failed to obtain the host page size");

	vm = vm_create_barebones();
	TEST_ASSERT(vm_check_cap(vm, KVM_CAP_RISCV_STAGE2_VIRT) > 0,
		    "VM does not report KVM_CAP_RISCV_STAGE2_VIRT");

	memory = mmap(NULL, 2 * page_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	TEST_ASSERT(memory != MAP_FAILED, "mmap failed, errno=%d (%s)",
		    errno, strerror(errno));

	set_memslot(vm, memory, 2 * page_size, 0, 0);

	/* Valid enable, range update, and disable requests. */
	set_stage2_virt(vm, TEST_GPA, page_size,
			KVM_RISCV_STAGE2_VIRT_ENABLE, 0);
	set_stage2_virt(vm, TEST_GPA, 2 * page_size,
			KVM_RISCV_STAGE2_VIRT_ENABLE, 0);
	set_stage2_virt(vm, 0, 0, 0, 0);

	/* Reject malformed or unsupported requests. */
	set_stage2_virt(vm, TEST_GPA, 0,
			KVM_RISCV_STAGE2_VIRT_ENABLE, EINVAL);
	set_stage2_virt(vm, TEST_GPA + 1, page_size,
			KVM_RISCV_STAGE2_VIRT_ENABLE, EINVAL);
	set_stage2_virt(vm, TEST_GPA, page_size - 1,
			KVM_RISCV_STAGE2_VIRT_ENABLE, EINVAL);
	set_stage2_virt(vm, TEST_GPA, page_size, 1ULL << 1, EINVAL);
	set_stage2_virt(vm, TEST_GPA, page_size, 0, EINVAL);
	set_stage2_virt(vm, UINT64_MAX & ~((uint64_t)page_size - 1), page_size,
			KVM_RISCV_STAGE2_VIRT_ENABLE, EINVAL);

	memset(&request, 0, sizeof(request));
	request.guest_phys_addr = TEST_GPA;
	request.memory_size = page_size;
	request.flags = KVM_RISCV_STAGE2_VIRT_ENABLE;
	request.reserved[0] = 1;
	stage2_virt_ioctl(vm, &request, EINVAL);

	/* Dirty logging first must block an overlapping Stage2Virt range. */
	set_memslot(vm, memory, 2 * page_size, KVM_MEM_LOG_DIRTY_PAGES, 0);
	set_stage2_virt(vm, TEST_GPA, page_size,
			KVM_RISCV_STAGE2_VIRT_ENABLE, EBUSY);
	set_memslot(vm, memory, 2 * page_size, 0, 0);

	/* Stage2Virt first must block dirty logging on an overlapping memslot. */
	set_stage2_virt(vm, TEST_GPA, page_size,
			KVM_RISCV_STAGE2_VIRT_ENABLE, 0);
	set_memslot(vm, memory, 2 * page_size, KVM_MEM_LOG_DIRTY_PAGES, EBUSY);
	set_stage2_virt(vm, 0, 0, 0, 0);

	set_memslot(vm, NULL, 0, 0, 0);
	munmap(memory, 2 * page_size);
	kvm_vm_free(vm);

	pr_info("RISC-V KVM Stage2Virt selftest: PASS\n");
	return 0;
}
