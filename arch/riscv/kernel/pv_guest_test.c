// SPDX-License-Identifier: GPL-2.0-only
/* Cooperative VS -> HS -> VS fixed-page execution test. */
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

#include <asm/cacheflush.h>
#include <asm/pgtable.h>
#include <asm/sbi.h>

#define PV_TEST_EXT 0x08000057
#define PV_TEST_BEGIN 0
#define PV_TEST_COMPLETE 1
#define PV_TEST_ABORT 2

static bool pv_guest_test_enabled;

/* Retained until the synchronous host/guest handshake completes. */
static struct page *pv_guest_test_page;
static void *pv_guest_test_exec;

static int __init pv_guest_test_setup(char *value)
{
	if (!value || kstrtobool(value, &pv_guest_test_enabled))
		return -EINVAL;
	return 0;
}
early_param("pmpvirt_guest_test", pv_guest_test_setup);

static int __init pv_guest_test_init(void)
{
	/* addi a0, zero, 42; jalr zero, 0(ra). No compressed instructions. */
	static const __le32 code[] = {
		cpu_to_le32(0x02a00513),
		cpu_to_le32(0x00008067),
	};
	phys_addr_t gpa;
	unsigned long result;
	unsigned long (*execute)(void);
	struct sbiret ret;
	int rc = -EINVAL;

	if (!pv_guest_test_enabled)
		return 0;

	if (sbi_probe_extension(PV_TEST_EXT) <= 0) {
		pr_err("PMP.Virt VS-HS-VS FAIL: lkvm test extension unavailable\n");
		return -EOPNOTSUPP;
	}

	pv_guest_test_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!pv_guest_test_page) {
		pr_err("PMP.Virt GUEST PROBE FAIL: allocate page\n");
		return -ENOMEM;
	}

	memcpy(page_address(pv_guest_test_page), code, sizeof(code));
	/* A separate RX alias avoids making a direct-map huge page executable. */
	pv_guest_test_exec = vmap(&pv_guest_test_page, 1, VM_MAP,
				 PAGE_KERNEL_READ_EXEC);
	if (!pv_guest_test_exec) {
		__free_page(pv_guest_test_page);
		pv_guest_test_page = NULL;
		pr_err("PMP.Virt GUEST PROBE FAIL: map executable alias\n");
		return -ENOMEM;
	}

	gpa = page_to_phys(pv_guest_test_page);
	/* In a guest, page_to_phys yields GPA, not the host physical address. */
	pr_info("PMP.Virt GUEST PROBE PAGE: GPA=%pa size=%lu code_bytes=%zu\n",
		&gpa, PAGE_SIZE, sizeof(code));
	flush_icache_range((unsigned long)pv_guest_test_exec,
			   (unsigned long)pv_guest_test_exec + sizeof(code));
	execute = pv_guest_test_exec;
	result = execute();
	if (result != 42) {
		pr_err("PMP.Virt GUEST PROBE FAIL: result=%lu expected=42\n",
		       result);
		vunmap(pv_guest_test_exec);
		__free_page(pv_guest_test_page);
		pv_guest_test_exec = NULL;
		pv_guest_test_page = NULL;
		return -EINVAL;
	}

	pr_info("PMP.Virt VS BEFORE PASS: GPA=%pa result=%lu\n", &gpa, result);
	/* Synchronous SBI exit keeps this vCPU stopped during the HS probe. */
	ret = sbi_ecall(PV_TEST_EXT, PV_TEST_BEGIN, gpa, result, 0, 0, 0, 0);
	if (ret.error || ret.value) {
		pr_err("PMP.Virt VS-HS-VS FAIL: BEGIN error=%ld value=%ld\n",
		       ret.error, ret.value);
		rc = -EIO;
		goto cleanup;
	}

	flush_icache_range((unsigned long)pv_guest_test_exec,
			   (unsigned long)pv_guest_test_exec + sizeof(code));
	result = execute();
	if (result != 42) {
		pr_err("PMP.Virt VS-HS-VS FAIL: second result=%lu\n", result);
		sbi_ecall(PV_TEST_EXT, PV_TEST_ABORT, 0, 0, 0, 0, 0, 0);
		goto cleanup;
	}
	pr_info("PMP.Virt VS AFTER PASS: GPA=%pa result=%lu\n", &gpa, result);
	ret = sbi_ecall(PV_TEST_EXT, PV_TEST_COMPLETE, gpa, result, 0, 0, 0, 0);
	if (ret.error || ret.value) {
		pr_err("PMP.Virt VS-HS-VS FAIL: COMPLETE error=%ld value=%ld\n",
		       ret.error, ret.value);
		sbi_ecall(PV_TEST_EXT, PV_TEST_ABORT, 0, 0, 0, 0, 0, 0);
		rc = -EIO;
		goto cleanup;
	}
	pr_info("PMP.Virt VS-HS-VS SAME-PAGE PASS: GPA=%pa\n", &gpa);
	rc = 0;
cleanup:
	vunmap(pv_guest_test_exec);
	__free_page(pv_guest_test_page);
	pv_guest_test_exec = NULL;
	pv_guest_test_page = NULL;
	return rc;
}
late_initcall(pv_guest_test_init);
