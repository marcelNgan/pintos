#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdio.h>
#include "threads/thread.h"

typedef int pid_t;

struct lock fileLock;

void syscall_init (void);
int fd_allocation(void);
struct file_descriptor *get_current_file (int fd);
bool is_valid_pointer(const void *pointer);
void close_current_file (int fd);
void close_owned_file (tid_t tid);

#endif /* userprog/syscall.h */
