// SPDX-License-Identifier: GPL-2.0-only
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include <asm/sbi.h>
#include <uapi/asm/stage2_virt_test.h>

#define STAGE2_VIRT_TEST_EXT		0x08000058UL
#define STAGE2_VIRT_SBI_BEGIN		0
#define STAGE2_VIRT_SBI_COMPLETE	1
#define STAGE2_VIRT_SBI_ABORT		2

static bool test_enabled;
static bool device_open;
static bool session_active;
static bool vs_probe_passed;
static struct page *test_page;
static DEFINE_MUTEX(test_lock);

static int __init stage2_virt_test_setup(char *value)
{
	if (!value || kstrtobool(value, &test_enabled))
		return -EINVAL;

	return 0;
}
early_param("stage2virt_guest_test", stage2_virt_test_setup);

static int stage2_virt_sbi_call(unsigned long function,
				phys_addr_t gpa, unsigned long size)
{
	struct sbiret ret;

	ret = sbi_ecall(STAGE2_VIRT_TEST_EXT, function,
			gpa, size, 0, 0, 0, 0);

	switch (ret.error) {
	case SBI_SUCCESS:
		return 0;
	case SBI_ERR_NOT_SUPPORTED:
		return -EOPNOTSUPP;
	case SBI_ERR_INVALID_PARAM:
		return -EINVAL;
	default:
		return -EIO;
	}
}

static int stage2_virt_abort_locked(void)
{
	int ret;

	if (!session_active)
		return 0;

	ret = stage2_virt_sbi_call(STAGE2_VIRT_SBI_ABORT, 0, 0);
	session_active = false;
	vs_probe_passed = false;
	return ret;
}

static int stage2_virt_test_open(struct inode *inode, struct file *file)
{
	int ret = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	mutex_lock(&test_lock);
	if (device_open)
		ret = -EBUSY;
	else {
		device_open = true;
		ret = nonseekable_open(inode, file);
		if (ret)
			device_open = false;
	}
	mutex_unlock(&test_lock);

	return ret;
}

static int stage2_virt_test_release(struct inode *inode, struct file *file)
{
	mutex_lock(&test_lock);
	stage2_virt_abort_locked();
	device_open = false;
	mutex_unlock(&test_lock);
	return 0;
}

static int stage2_virt_test_mmap(struct file *file,
				 struct vm_area_struct *vma)
{
	unsigned long length = vma->vm_end - vma->vm_start;

	if (!test_page || length != PAGE_SIZE || vma->vm_pgoff)
		return -EINVAL;
	if (!(vma->vm_flags & VM_SHARED) ||
	    !(vma->vm_flags & VM_WRITE) ||
	    (vma->vm_flags & VM_EXEC))
		return -EINVAL;

	vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP | VM_DONTCOPY);
	return vm_insert_page(vma, vma->vm_start, test_page);
}

static int stage2_virt_vs_probe(u8 expected)
{
	u8 replacement = expected ^ 0xff;
	u8 *address = page_address(test_page);
	long ret;

	if (READ_ONCE(*address) != expected)
		return -EINVAL;

	ret = copy_to_kernel_nofault(address, &replacement,
				     sizeof(replacement));
	if (ret != -EFAULT)
		return ret ? (int)ret : -EACCES;
	if (READ_ONCE(*address) != expected)
		return -EIO;

	return 0;
}

static long stage2_virt_test_ioctl(struct file *file,
				   unsigned int command,
				   unsigned long argument)
{
	struct stage2_virt_test_info info;
	struct stage2_virt_test_value value;
	phys_addr_t gpa;
	int ret = 0;

	if (!test_page)
		return -ENODEV;

	gpa = page_to_phys(test_page);
	switch (command) {
	case STAGE2_VIRT_TEST_IOC_GET_INFO:
		info.gpa = gpa;
		info.size = PAGE_SIZE;
		if (copy_to_user((void __user *)argument, &info, sizeof(info)))
			return -EFAULT;
		return 0;

	case STAGE2_VIRT_TEST_IOC_BEGIN:
		mutex_lock(&test_lock);
		if (session_active) {
			ret = -EBUSY;
			goto out_unlock;
		}

		clear_highpage(test_page);
		ret = stage2_virt_sbi_call(STAGE2_VIRT_SBI_BEGIN,
					   gpa, PAGE_SIZE);
		if (!ret) {
			session_active = true;
			vs_probe_passed = false;
			pr_info("Stage2Virt Guest BEGIN: GPA=%pa size=%lu\n",
				&gpa, PAGE_SIZE);
		}
		goto out_unlock;

	case STAGE2_VIRT_TEST_IOC_VS_PROBE:
		if (copy_from_user(&value, (void __user *)argument,
				   sizeof(value)))
			return -EFAULT;
		if (memchr_inv(value.reserved, 0, sizeof(value.reserved)))
			return -EINVAL;

		mutex_lock(&test_lock);
		if (!session_active) {
			ret = -EINVAL;
			goto out_unlock;
		}
		if (vs_probe_passed) {
			ret = -EALREADY;
			goto out_unlock;
		}

		ret = stage2_virt_vs_probe(value.expected);
		if (!ret) {
			vs_probe_passed = true;
			pr_info("Stage2Virt Guest VS PROBE PASS: GPA=%pa expected=0x%02x fault=-EFAULT\n",
				&gpa, value.expected);
		}
		goto out_unlock;

	case STAGE2_VIRT_TEST_IOC_COMPLETE:
		if (copy_from_user(&value, (void __user *)argument,
				   sizeof(value)))
			return -EFAULT;
		if (memchr_inv(value.reserved, 0, sizeof(value.reserved)))
			return -EINVAL;

		mutex_lock(&test_lock);
		if (!session_active || !vs_probe_passed) {
			ret = -EINVAL;
			goto out_unlock;
		}
		if (READ_ONCE(*(u8 *)page_address(test_page)) != value.expected) {
			ret = -EINVAL;
			goto out_unlock;
		}

		ret = stage2_virt_sbi_call(STAGE2_VIRT_SBI_COMPLETE,
					   gpa, PAGE_SIZE);
		session_active = false;
		vs_probe_passed = false;
		if (!ret)
			pr_info("Stage2Virt Guest VU-VS-VU SAME-PAGE PASS: GPA=%pa final=0x%02x\n",
				&gpa, value.expected);
		goto out_unlock;

	case STAGE2_VIRT_TEST_IOC_ABORT:
		mutex_lock(&test_lock);
		ret = stage2_virt_abort_locked();
		goto out_unlock;

	default:
		return -ENOTTY;
	}

out_unlock:
	mutex_unlock(&test_lock);
	return ret;
}

static const struct file_operations stage2_virt_test_fops = {
	.owner			= THIS_MODULE,
	.open			= stage2_virt_test_open,
	.release		= stage2_virt_test_release,
	.unlocked_ioctl		= stage2_virt_test_ioctl,
	.mmap			= stage2_virt_test_mmap,
};

static struct miscdevice stage2_virt_test_device = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "stage2_virt_test",
	.fops	= &stage2_virt_test_fops,
	.mode	= 0600,
};

static int __init stage2_virt_guest_test_init(void)
{
	phys_addr_t gpa;
	int ret;

	if (!test_enabled)
		return 0;
	if (sbi_probe_extension(STAGE2_VIRT_TEST_EXT) <= 0) {
		pr_err("Stage2Virt Guest: SBI extension unavailable\n");
		return -EOPNOTSUPP;
	}

	test_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!test_page)
		return -ENOMEM;

	ret = misc_register(&stage2_virt_test_device);
	if (ret) {
		__free_page(test_page);
		test_page = NULL;
		return ret;
	}

	gpa = page_to_phys(test_page);
	pr_info("Stage2Virt Guest device ready: /dev/stage2_virt_test GPA=%pa size=%lu\n",
		&gpa, PAGE_SIZE);
	return 0;
}
late_initcall(stage2_virt_guest_test_init);
