#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

typedef int pid_t;

struct lock fileLock;

void syscall_init (void);
#endif /* userprog/syscall.h */
