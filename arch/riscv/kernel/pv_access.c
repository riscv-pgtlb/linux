/* Fixed-target boot/syscall access controls. Store the original byte unchanged. */
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>
#include <linux/irqflags.h>
#include <asm/cacheflush.h>
#include <asm/ptrace.h>
#include <asm/sections.h>
#include <asm/set_memory.h>

extern unsigned long pv_test_call(void *addr);
extern void pv_test_call_resume(void);
extern void pv_test_store(void *addr, unsigned long value);
extern void pv_test_store_insn(void), pv_test_store_resume(void);
bool pv_access_fixup(struct pt_regs *regs);
void pv_access_before(void);
void pv_access_after(void);

static void *code_alias, *text_alias, *ro_alias;
static struct task_struct *owner;
static bool armed;
static bool pv_boot_tests_done;
static unsigned long wanted_pc, wanted_addr, recovery_pc;
static unsigned long observed_cause, observed_pc, observed_addr;
static unsigned failures, observations;

struct pv_access_result {
    __u64 cause;
    __u64 before;
    __u64 after;
};

/* Called only for kernel-mode synchronous access errors/page faults.
 * A matching task, exact faulting PC, exact address, and class are mandatory.
 * This is temporary test instrumentation, never part of production policy.
 */
bool pv_access_fixup(struct pt_regs *regs)
{
    bool fetch;
    if (!READ_ONCE(armed) || user_mode(regs) || current != owner ||
        regs->epc != wanted_pc || regs->badaddr != wanted_addr)
        return false;
    fetch = wanted_pc == (unsigned long)code_alias;
    if (fetch ? (regs->cause != 1 && regs->cause != 12) :
                (regs->cause != 7 && regs->cause != 15))
        return false;
    observed_cause = regs->cause;
    observed_pc = regs->epc;
    observed_addr = regs->badaddr;
    WRITE_ONCE(armed, false);
    regs->epc = recovery_pc;
    regs->a0 = 0;
    return true;
}

static struct pv_access_result probe(const char *name, void *addr,
                                    bool execute, unsigned expected)
{
    unsigned long flags, value = 0;
    unsigned char original = READ_ONCE(*(unsigned char *)addr);
    struct pv_access_result result;
    owner = current;
    wanted_addr = (unsigned long)addr;
    wanted_pc = execute ? wanted_addr : (unsigned long)pv_test_store_insn;
    recovery_pc = execute ? (unsigned long)pv_test_call_resume :
                           (unsigned long)pv_test_store_resume;
    observed_cause = observed_pc = observed_addr = 0;
    local_irq_save(flags);
    WRITE_ONCE(armed, true);
    barrier();
    if (execute)
        value = pv_test_call(addr);
    else
        pv_test_store(addr, original);
    barrier();
    WRITE_ONCE(armed, false);
    local_irq_restore(flags);
    result.cause = observed_cause;
    result.before = original;
    result.after = READ_ONCE(*(unsigned char *)addr);
    observations++;
    if (observed_cause != expected ||
        (!expected && execute && value != 42) ||
        result.after != original) {
        failures++;
        pr_err("PMP.Virt TEST FAIL %s cause=%lu expected=%u pc=%lx tval=%lx value=%lu\n",
               name, observed_cause, expected, observed_pc, observed_addr, value);
    } else {
        pr_info("PMP.Virt TEST PASS %s cause=%lu pc=%lx tval=%lx\n",
                name, observed_cause, observed_pc, observed_addr);
    }
    return result;
}

void pv_access_before(void)
{
    struct page *page;
    /* set_memory_x needs vm_struct.pages; plain vmap lacks that metadata. */
    code_alias = vmalloc(PAGE_SIZE);
    page = pfn_to_page(__pa_symbol(_text) >> PAGE_SHIFT);
    text_alias = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
    page = pfn_to_page(__pa_symbol(__start_rodata) >> PAGE_SHIFT);
    ro_alias = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
    if (!code_alias || !text_alias || !ro_alias)
        panic("PMP.Virt test vmap failed");
    /* addi a0,zero,42; ret. Never alter the payload after it is warmed. */
    ((u32 *)code_alias)[0] = 0x02a00513;
    ((u32 *)code_alias)[1] = 0x00008067;
    if (set_memory_x((unsigned long)code_alias, 1))
        panic("PMP.Virt test executable mapping failed");
    flush_icache_range((unsigned long)code_alias, (unsigned long)code_alias + 8);
    probe("before HS RAM execute", code_alias, true, 0);
    probe("before text writable alias", text_alias, false, 0);
    probe("before rodata writable alias", ro_alias, false, 0);
    if (failures)
        panic("PMP.Virt before-seal controls failed");
}

void pv_access_after(void)
{
    /* Unchanged aliases and bytes: only M-mode PMP policy has changed. */
    probe("after HS RAM execute", code_alias, true, 1);
    probe("after text writable alias", text_alias, false, 7);
    probe("after rodata writable alias", ro_alias, false, 7);
    if (failures)
        panic("PMP.Virt access tests failed: %u/%u", failures, observations);
    pr_info("PMP.Virt ACCESS SUMMARY: PASS %u/6 (HS probes only)\n", observations);
    if (set_memory_nx((unsigned long)code_alias, 1))
        panic("PMP.Virt test mapping cleanup failed");
    vfree(code_alias);
    vunmap(text_alias);
    vunmap(ro_alias);
    WRITE_ONCE(pv_boot_tests_done, true);
}

/* Root-only, fixed-payload user-page probe; research instrumentation only. */
#include <linux/capability.h>
#include <linux/cpu.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <asm/processor.h>
#include <asm/pgtable.h>

struct pv_user_request {
    __u64 address;
    __u64 physical;
    __u64 cause;
};
#define PV_USER_PROBE _IOWR('V', 0x56, struct pv_user_request)
/* Output only: callers cannot select an address, instruction, or write value. */
struct pv_syscall_request {
    __u64 version;
    __u64 count;
    struct pv_access_result results[4];
};
#define PV_SYSCALL_PROBE _IOR('V', 0x58, struct pv_syscall_request)
static DEFINE_MUTEX(pv_user_lock);

#include <asm/tlbflush.h>

static int pv_enable_alias_exec(pte_t *pte, unsigned long address, void *data)
{
    struct page *page = data;
    pte_t entry = ptep_get(pte);
    unsigned long flags = pte_val(entry);
    unsigned long required = _PAGE_PRESENT | _PAGE_READ;

    if ((flags & required) != required ||
        (flags & (_PAGE_USER | _PAGE_WRITE)) ||
        pte_pfn(entry) != page_to_pfn(page))
        return -EINVAL;

    set_pte_at(&init_mm, address, pte,
               __pte(flags | _PAGE_EXEC));
    return 0;
}

static int pv_check_pte(pte_t *pte, unsigned long address, void *data)
{
    unsigned long flags = pte_val(ptep_get(pte));
    unsigned long required = _PAGE_PRESENT | _PAGE_READ | _PAGE_EXEC;
    pr_info("PMP.Virt USER PTE: flags=%lx required=%lx user=%lx write=%lx\n", flags, required, flags & _PAGE_USER, flags & _PAGE_WRITE);
    (void)address;
    (void)data;
    if ((flags & required) != required || (flags & (_PAGE_USER | _PAGE_WRITE)))
        { pr_err("PMP.Virt USER EINVAL line=%d\n", __LINE__); return -EINVAL; }
    return 0;
}

static int pv_check_write_alias(pte_t *pte, unsigned long address, void *data)
{
    pte_t entry = ptep_get(pte);
    unsigned long flags = pte_val(entry);
    unsigned long required = _PAGE_PRESENT | _PAGE_READ | _PAGE_WRITE;
    struct page *page = data;

    (void)address;
    if ((flags & required) != required || (flags & (_PAGE_USER | _PAGE_EXEC)) ||
        pte_pfn(entry) != page_to_pfn(page))
        return -EINVAL;
    return 0;
}

static long pv_syscall_ioctl(unsigned long arg)
{
    struct pv_syscall_request result = {.version = 1, .count = 4};
    struct page *text_page, *ro_page, *code_page;
    void *data = NULL, *code = NULL, *exec = NULL;
    void *text = NULL, *ro = NULL, *old_alias;
    pgprot_t prot;
    unsigned initial_failures;
    long rc;

    if (!capable(CAP_SYS_ADMIN))
        return -EPERM;
    if (!READ_ONCE(pv_boot_tests_done) || num_online_cpus() != 1)
        return -EBUSY;
    if (!arg || !access_ok((void __user *)arg, sizeof(result)))
        return -EFAULT;
    if (mutex_lock_interruptible(&pv_user_lock))
        return -EINTR;

    /* All targets are fixed by the kernel and all mappings are temporary.
     * Writable aliases bypass S-stage read-only PTEs, so cause 7 (not 15)
     * establishes that PMP denied the stores. Same-byte stores cannot patch
     * live code or read-only data even if the protection regresses.
     */
    data = vmalloc(PAGE_SIZE);
    code = vmalloc(PAGE_SIZE);
    text_page = pfn_to_page(__pa_symbol(_text) >> PAGE_SHIFT);
    ro_page = pfn_to_page(__pa_symbol(__start_rodata) >> PAGE_SHIFT);
    text = vmap(&text_page, 1, VM_MAP, PAGE_KERNEL);
    ro = vmap(&ro_page, 1, VM_MAP, PAGE_KERNEL);
    rc = -ENOMEM;
    if (!data || !code || !text || !ro)
        goto cleanup;
    *(unsigned char *)data = 0x5a;
    ((u32 *)code)[0] = 0x02a00513;
    ((u32 *)code)[1] = 0x00008067;
    rc = apply_to_page_range(&init_mm, (unsigned long)text, PAGE_SIZE,
                            pv_check_write_alias, text_page);
    if (rc)
        goto cleanup;
    rc = apply_to_page_range(&init_mm, (unsigned long)ro, PAGE_SIZE,
                            pv_check_write_alias, ro_page);
    if (rc)
        goto cleanup;
    /* Only change the temporary alias. set_memory_ro/x also changes the
     * linear mapping, which must remain RW/NX when the page is freed.
     */
    code_page = vmalloc_to_page(code);
    prot = __pgprot((pgprot_val(PAGE_KERNEL) | _PAGE_EXEC) & ~_PAGE_WRITE);
    exec = vmap(&code_page, 1, VM_MAP, prot);
    if (!exec) {
        rc = -ENOMEM;
        goto cleanup;
    }
    rc = apply_to_page_range(&init_mm, (unsigned long)exec, PAGE_SIZE,
                            pv_enable_alias_exec, code_page);
    if (rc)
        goto cleanup;
    flush_tlb_all();
    rc = apply_to_page_range(&init_mm, (unsigned long)exec, PAGE_SIZE,
                            pv_check_pte, NULL);
    if (rc)
        goto cleanup;
    flush_icache_range((unsigned long)exec, (unsigned long)exec + 8);
    initial_failures = failures;
    old_alias = code_alias;
    code_alias = exec;
    result.results[0] = probe("syscall ordinary data store control", data, false, 0);
    result.results[1] = probe("syscall HS RAM RX/U0 execute", exec, true, 1);
    result.results[2] = probe("syscall text writable alias", text, false, 7);
    result.results[3] = probe("syscall rodata writable alias", ro, false, 7);
    code_alias = old_alias;
    rc = failures == initial_failures ? 0 : -EIO;
    if (copy_to_user((void __user *)arg, &result, sizeof(result)))
        rc = -EFAULT;
cleanup:
    if (exec)
        vunmap(exec);
    if (ro)
        vunmap(ro);
    if (text)
        vunmap(text);
    vfree(code);
    vfree(data);
    mutex_unlock(&pv_user_lock);
    return rc;
}

static long pv_user_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct pv_user_request req;
    struct vm_area_struct *vma;
    struct page *page = NULL;
    void *alias = NULL, *old_alias;
    pgprot_t prot;
    long rc;
    unsigned initial_failures;
    const u32 payload[2] = {0x02a00513, 0x00008067};
    (void)file;
    if (cmd == PV_SYSCALL_PROBE)
        return pv_syscall_ioctl(arg);
    if (cmd != PV_USER_PROBE)
        return -ENOTTY;
    if (!capable(CAP_SYS_ADMIN))
        return -EPERM;
    if (!READ_ONCE(pv_boot_tests_done) || num_online_cpus() != 1)
        return -EBUSY;
    if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
        return -EFAULT;
    if (!req.address || (req.address & (PAGE_SIZE - 1)) ||
        req.address > TASK_SIZE - PAGE_SIZE)
        { pr_err("PMP.Virt USER EINVAL line=%d\n", __LINE__); return -EINVAL; }
    if (mutex_lock_interruptible(&pv_user_lock))
        return -EINTR;
    mmap_read_lock(current->mm);
    vma = vma_lookup(current->mm, req.address);
    if (!vma || vma->vm_end - req.address < PAGE_SIZE ||
        (vma->vm_flags & (VM_READ | VM_EXEC)) != (VM_READ | VM_EXEC) ||
        (vma->vm_flags & (VM_WRITE | VM_SHARED | VM_IO | VM_PFNMAP))) {
        pr_err("PMP.Virt USER EINVAL line=%d\n", __LINE__);
        rc = -EINVAL;
        goto unlock_mm;
    }
    rc = get_user_pages(req.address, 1, 0, &page);
    if (rc != 1) {
        rc = rc < 0 ? rc : -EFAULT;
        page = NULL;
        goto unlock_mm;
    }
    /* Explicit S-stage RX/U=0 alias to THE SAME pinned physical frame.
     * Do not call set_memory_x on vmap: that API needs vm_struct.pages.
     */
    prot = __pgprot((pgprot_val(PAGE_KERNEL) | _PAGE_EXEC) & ~_PAGE_WRITE);
    alias = vmap(&page, 1, VM_MAP, prot);
    if (!alias) {
        rc = -ENOMEM;
        goto unlock_mm;
    }
    if (memcmp(alias, payload, sizeof(payload))) {
        pr_err("PMP.Virt USER EINVAL line=%d\n", __LINE__);
        rc = -EINVAL;
        goto unlock_mm;
    }
    rc = apply_to_page_range(&init_mm, (unsigned long)alias, PAGE_SIZE,
                            pv_enable_alias_exec, page);
    if (rc)
        goto unlock_mm;
    flush_tlb_all();
    rc = apply_to_page_range(&init_mm, (unsigned long)alias, PAGE_SIZE,
                            pv_check_pte, NULL);
    if (rc)
        goto unlock_mm;
    req.physical = page_to_phys(page);
    flush_icache_range((unsigned long)alias, (unsigned long)alias + 8);
    old_alias = code_alias;
    code_alias = alias;
    initial_failures = failures;
    probe("user same-page HS RX/U0 execute", alias, true, 1);
    req.cause = observed_cause;
    code_alias = old_alias;
    pr_info("PMP.Virt USER frame: user_va=%llx physical=%llx kernel_alias=%lx cause=%llu\n",
            (unsigned long long)req.address, (unsigned long long)req.physical,
            (unsigned long)alias, (unsigned long long)req.cause);
    rc = failures == initial_failures ? 0 : -EIO;
unlock_mm:
    if (alias)
        vunmap(alias);
    if (page)
        put_page(page);
    mmap_read_unlock(current->mm);
    mutex_unlock(&pv_user_lock);
    if (!rc && copy_to_user((void __user *)arg, &req, sizeof(req)))
        return -EFAULT;
    return rc;
}

static const struct file_operations pv_user_ops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = pv_user_ioctl,
};
static struct miscdevice pv_user_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "pvtest",
    .fops = &pv_user_ops,
    .mode = 0600,
};
static int __init pv_user_init(void)
{
    return misc_register(&pv_user_device);
}
device_initcall(pv_user_init);
