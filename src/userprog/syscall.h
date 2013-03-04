#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdio.h>
#include "threads/thread.h"

typedef int pid_t;

struct file_descriptor
{
  int fd_num;
  tid_t file_owner;
  struct file *file;
  struct list_elem file_elem;  
};

struct list open_file_list; 
struct lock fileLock;

void syscall_init (void);
int fd_allocation(void);
struct file_descriptor *get_current_file (int fd);
bool is_valid_pointer(const void *);
void close_current_file (int fd);

#endif /* userprog/syscall.h */
