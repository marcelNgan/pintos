#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/synch.h"
#include "filesys/file.h"
#include "lib/kernel/hash.h"
#include "vm/page.h"




/* States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /* Running thread. */
    THREAD_READY,       /* Not running but ready to run. */
    THREAD_BLOCKED,     /* Waiting for an event to trigger. */
    THREAD_DYING        /* About to be destroyed. */
  };

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
typedef int mapid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

#define NICE_MIN -20
#define NICE_MAX 20
#define NICE_DEFAULT 0

#define RECENT_CPU_DEFAULT 0

/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */

struct child{
  tid_t cid;                             /*child id*/
  bool exit_call;
  bool wait_call;
  int exit_status;
  struct list_elem elem_child;
};

struct thread
  {
    /* Owned by thread.c. */
    tid_t tid;                          /* Thread identifier. */
    enum thread_status status;          /* Thread state. */
    char name[16];                      /* Name (for debugging purposes). */
    uint8_t *stack;                     /* Saved stack pointer. */
    int priority;                       /* Priority. */
    struct list_elem allelem;           /* List element for all threads list. */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /* List element. */


#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint32_t *pagedir;                  /* Page directory. */
    tid_t pid;                           /*parent id*/
    int child_load_success;
    struct lock child_lock;
    struct condition child_cond;

    /*a list of children of type child*/
    struct list children;
    struct file *file;
    
    //this indicated the next mapid allocator
    mapid_t mapid_alloc;
    
    //supplementary hash table
    struct hash spt;
    
    //the hash table for memory mapped files
    struct hash mmfs;
    
#endif

    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */

    int64_t wakeup_tick;       /* used by Alarm clock to wake up the thread */
    //struct semaphore timer_sema;
    int prev_priority;     /* the thread's priority before donation */
    bool donated;             /* check if the thread's priority is donated */
    struct list lock_list;  /* a list of all the locks held by the thread */
    struct lock *locker;    /*the lock blocking the thread */   


   int nice;               /*The nice value of the thread*/
   int recent_cpu;        /*The amount of cpu used by the thread recently*/ 
  };

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

void thread_sleep (int64_t ticks);
void thread_wakeup (void);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);
/* This does what thread yield used to do except it works with any thread */
void thread_specific_yield (struct thread *t); 

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

int thread_get_priority (void);
void thread_set_priority (int);
/* This does what thread_set_priority used to do except it works with any 
   thread and also priority donation is checked
*/
void thread_specific_set_priority (int new_priority, struct thread *t, bool donated);

// BSD functions
void calculate_load_avg (void);
void thread_calculate_BSD_priority (void);
void calculate_BSD_priority_all(void);
void calculate_BSD_priority (struct thread *cur, void *aux UNUSED);
void thread_calculate_recent_cpu (void);
void calculate_recent_cpu_all (void);
void calculate_recent_cpu (struct thread *cur, void *aux UNUSED);


int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);
struct thread * get_thread(tid_t);
#endif /* threads/thread.h */
