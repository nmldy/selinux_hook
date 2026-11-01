/*
 * Copyright (C) 2024. All Rights Reserved.
 * SELinux Magisk Filter — Header
 */

#ifndef __SELINUX_HOOK_H
#define __SELINUX_HOOK_H

#include <hook.h>
#include <ksyms.h>
#include <linux/errno.h>
#include <linux/printk.h>

#define MAX_KEY_LEN 128

// 修改1：将 %llx 改为 %px（内核标准指针打印格式，防编译警告）
#define lookup_name(func)                                  \
    func = 0;                                              \
    func = (typeof(func))kallsyms_lookup_name(#func);      \
    pr_info("kernel function %s addr: %px\n", #func, func); \
    if (!func) {                                           \
        return -ENOENT;                                    \
    }

#define hook_func(func, argv, before, after, udata)                        \
    if (!func) {                                                           \
        return -EINVAL;                                                    \
    }                                                                      \
    hook_err_t hook_err_##func = hook_wrap(func, argv, before, after, udata); \
    if (hook_err_##func) {                                                 \
        pr_err("hook %s error: %d\n", #func, hook_err_##func);             \
        func = 0;                                                          \
        return -ENOSYS;                                                    \
    } else {                                                               \
        pr_info("hook %s success\n", #func);                               \
    }

// 修改2：删除了 is_bad_address（新版 APatch 某些版本不提供此函数，极易报未定义错误）
#define unhook_func(func)           \
    if (func) {                     \
        unhook(func);               \
        pr_info("unhook %s\n", #func); \
        func = 0;                   \
    }

#endif /* __SELINUX_HOOK_H */
