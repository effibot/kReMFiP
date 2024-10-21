//
// Created by effi on 21/10/24.
//

#ifndef LOGGERFS_H
#define LOGGERFS_H
#ifdef __KERNEL__
// ---------------------------------- Kernel ----------------------------------
#define INFO(fmt, ...)                                                                \
printk(KERN_INFO "[%s::%s::%s::%d]: " fmt, MODNAME, __FILE__, __func__, __LINE__, \
##__VA_ARGS__);
#define WARNING(fmt, ...)                                                                \
printk(KERN_WARNING "[%s::%s::%s::%d]: " fmt, MODNAME, __FILE__, __func__, __LINE__, \
##__VA_ARGS__);

// ---------------------------------- Kernel ----------------------------------
#endif
#endif //LOGGERFS_H
