/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_ASM_RISCV_STAGE2_VIRT_TEST_H
#define _UAPI_ASM_RISCV_STAGE2_VIRT_TEST_H

#include <linux/ioctl.h>
#include <linux/types.h>

struct stage2_virt_test_info {
	__u64 gpa;
	__u64 size;
};

struct stage2_virt_test_value {
	__u8 expected;
	__u8 reserved[7];
};

#define STAGE2_VIRT_TEST_IOC_MAGIC	'G'

#define STAGE2_VIRT_TEST_IOC_GET_INFO				\
	_IOR(STAGE2_VIRT_TEST_IOC_MAGIC, 0x00,			\
	     struct stage2_virt_test_info)
#define STAGE2_VIRT_TEST_IOC_BEGIN				\
	_IO(STAGE2_VIRT_TEST_IOC_MAGIC, 0x01)
#define STAGE2_VIRT_TEST_IOC_VS_PROBE				\
	_IOW(STAGE2_VIRT_TEST_IOC_MAGIC, 0x02,			\
	     struct stage2_virt_test_value)
#define STAGE2_VIRT_TEST_IOC_COMPLETE				\
	_IOW(STAGE2_VIRT_TEST_IOC_MAGIC, 0x03,			\
	     struct stage2_virt_test_value)
#define STAGE2_VIRT_TEST_IOC_ABORT				\
	_IO(STAGE2_VIRT_TEST_IOC_MAGIC, 0x04)

#endif
