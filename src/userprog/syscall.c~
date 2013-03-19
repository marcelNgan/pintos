#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "threads/synch.h"

struct file_descriptor
{
  int fd_num;
  tid_t file_owner;
  struct file *file;
  struct list_elem elem;  
};

static void syscall_handler (struct intr_frame *);

/*Possible system calls*/
static void halt (void);
static void exit (int);
static pid_t exec (const char *);
static int wait (pid_t);
static bool create (const char *, unsigned);
static bool remove (const char *);
static int open (const char *);
static int filesize (int);
static int read (int, void *, unsigned);
static int write (int, const void *, unsigned);
static void seek (int, unsigned);
static unsigned tell (int);
static void close (int);

bool is_valid_pointer (const void *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&fileLock);
}

static void
syscall_handler (struct intr_frame *f) 
{
  uint32_t *esp;
  esp = f->esp;

  if (!is_valid_pointer (esp) || !is_valid_pointer (esp + 1) ||
                 !is_valid_pointer (esp + 2) || !is_valid_pointer (esp + 3))
  {
    exit (-1);
  }
  else
  {
    int syscall_number = *esp;
    switch (syscall_number)
      {
      case SYS_HALT:
        halt ();
        break;
      case SYS_EXIT:
        exit (*(esp + 1));
        break;
      case SYS_EXEC:
        f->eax = exec ((char *) *(esp + 1));
        break;
      case SYS_WAIT:
        f->eax = wait (*(esp + 1));
        break;
      case SYS_CREATE:
        f->eax = create ((char *) *(esp + 1), *(esp + 2));
        break;
      case SYS_REMOVE:
        f->eax = remove ((char *) *(esp + 1));
        break;
      case SYS_OPEN:
        f->eax = open ((char *) *(esp + 1));
        break;
      case SYS_FILESIZE:
        f->eax = filesize (*(esp + 1));
        break;
      case SYS_READ:
        f->eax = read (*(esp + 1), (void *) *(esp + 2), *(esp + 3));
        break;
      case SYS_WRITE:
        f->eax = write (*(esp + 1), (void *) *(esp + 2), *(esp + 3));
        break;
      case SYS_SEEK:
        seek (*(esp + 1), *(esp + 2));
        break;
      case SYS_TELL:
        f->eax = tell (*(esp + 1));
        break;
      case SYS_CLOSE:
        close (*(esp + 1));
        break;
      default:
        break;
      }
  }
}

static void 
halt (void) {
  shutdown_power_off();
}

static void 
exit (int status) {
  struct child *child;
  struct thread *cur;
  struct thread *parent;
  cur = thread_current();
  printf("%s: exit(%d)\n", cur->name, status);
  parent = get_thread(cur->pid);
  if (parent != NULL)
  {
    struct list_elem *e;
    e = list_tail(&parent->children);
    while ((e = list_prev(e)) != list_head(&parent->children))
    {
      child = list_entry(e, struct child, elem_child);
      if (child->cid == cur->tid)
      {
        lock_acquire (&parent->child_lock);
        child->exit_call = true;
        child->exit_status = status;
        lock_release (&parent->child_lock);
      }
    }
  }
  thread_exit();
}

static pid_t exec (const char *cmd_line){
  tid_t tid;
  struct thread *cur;
  if (!is_valid_pointer(cmd_line))
  {
    exit(-1);
  }
  cur = thread_current();
  cur->child_load_success = 0;
  tid = process_execute(cmd_line);
  lock_acquire(&cur->child_lock);
  while (cur->child_load_success == 0)
    cond_wait(&cur->child_cond, &cur->child_lock);
  if (cur->child_load_success == -1)
    tid = -1;
  lock_release(&cur->child_lock);
  return tid;
}

static int wait (pid_t pid){
  return process_wait(pid);
}

static bool create (const char *file, unsigned initial_size){
  bool status;

  if (!is_valid_pointer(file))
    exit(-1);
  lock_acquire(&fileLock);
  status = filesys_create(file, initial_size);
  lock_release(&fileLock);
  return status;
}

static bool remove (const char *file){
  bool status;

  if (!is_valid_pointer(file))
    exit(-1);
  lock_acquire(&fileLock);
  status = filesys_remove(file);
  lock_release(&fileLock);
  return status;
}

static int open (const char *file){

  struct file *f;
  struct file_descriptor *fd;
  int status = -1;

  if (!is_valid_pointer(file))
    exit(-1);
  
  lock_acquire(&fileLock);
  f = filesys_open(file);
  if (f != NULL)
  {
    fd = calloc (1, sizeof *fd);
    fd->fd_num = fd_allocation();
  } else
    status = -1;
  lock_release(&fileLock); 
  return status;
}

static int filesize (int fd){
  return 0;
}

static int read (int fd, void *buffer, unsigned size){
  return 0;
}

static int write (int fd, const void *buffer, unsigned size){
  return 0;
}

static void seek (int fd, unsigned position){

}

static unsigned tell (int fd){
  return 0;
}

static void close (int fd){

}

bool is_valid_pointer(const void *pointer)
{
  struct thread *cur;
  cur = thread_current();
  if (pointer != NULL && is_user_vaddr (pointer) &&
      pagedir_get_page (cur->pagedir, pointer) != NULL)
    return true;
  else
    return false;
}

int fd_allocation()
{
  static int fd_current = 1;
  return ++fd_current;
}




