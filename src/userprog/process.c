#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/frame.h"
#include "vm/page.h"


struct mmf
{
  struct hash_elem elem;
  struct file *file;
  void* addr;
  unsigned pg_num;
  
  //id for the mmf
  mapid_t mapid;
}; 



static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
void close_owned_file (tid_t tid);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */

//memory mapping hash functions and freeing functions
unsigned mmf_hash (const struct hash_elem *, void *);
bool mmf_less (const struct hash_elem *, const struct hash_elem *, void *);
void free_mmfs (struct hash *);
static void free_mmfs_entry (struct hash_elem *, void *);
static void mmfs_free_entry (struct mmf* );
static mapid_t mapid_allocation (void);   

tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;
  struct child *child;
  struct thread *cur;


  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Split fn_copy into program name and arguments */
  char *prog_name, *args;
  prog_name = strtok_r (fn_copy, " ", &args);

  /* Create a new thread to execute FILE_NAME. */
  /*  tid = thread_create (file_name, PRI_DEFAULT, start_process, fn_copy);*/
  tid = thread_create (prog_name, PRI_DEFAULT, start_process, args);
  
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy);
  else
  {
    cur = thread_current();
    child = calloc (1,sizeof *child);
    if (child != NULL)
    {
      child->cid = tid;
      child->exit_call = false;
      child->wait_call = false;
      list_push_back(&cur->children, &child->elem_child);
    }
  }
  
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;
  int load_success;
  struct thread *cur = thread_current();
  struct thread *parent;
  
  
  //initialise the supplementary table
  hash_init(&cur->spt, supple_hash_ptable, supple_less, NULL);
  
  //initialise the supplementary table
  hash_init(&cur->mmfs, mmf_hash, mmf_less, NULL);
   
 /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);
  /* If load failed, quit. */
  //palloc_free_page (file_name);
  if (!success)
    load_success = -1;
  else
    load_success = 1;

  parent = get_thread(cur->pid);
  if (parent != NULL)
  {
    lock_acquire(&parent->child_lock);
    parent->child_load_success = load_success;
    cond_signal(&parent->child_cond, &parent->child_lock);
    lock_release(&parent->child_lock);    
  }
  if (!success)
    thread_exit ();

  palloc_free_page(pg_round_down(file_name));
  
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{

  int status;
  struct thread *cur;
  struct list_elem *e;
  if (child_tid != TID_ERROR)
  {
    struct child *child;
    cur = thread_current();
    e = list_tail (&cur->children);
    while ((e = list_prev(e)) != list_head(&cur->children))
    {
      child = list_entry(e, struct child, elem_child);
      if (child->cid == child_tid)
        break;
    }
    if (child == NULL)
      status = -1;
    else
    {
      lock_acquire(&cur->child_lock);
     while(get_thread(child_tid)!= NULL)
        cond_wait (&cur->child_cond, &cur->child_lock);
      if (!child->exit_call || child->wait_call)
        status = -1;
      else
      {
        status = child->exit_status;
        child->wait_call = true;
      }
      lock_release(&cur->child_lock);
    }
    
  } else
    status = TID_ERROR;
  return status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  struct thread *parent;
  struct list_elem *e;
  struct list_elem *temp;
  
  
  free_mmfs(&cur->mmfs);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }

  e = list_begin(&cur-> children);
  while (e!= list_tail(&cur-> children))
    {
    struct child *child;
	  temp = list_next(e);
	  child = list_entry(e, struct child, elem_child);
	  list_remove(e);
    free(child);
	  e = temp;
    }
  if (cur->file != NULL)
    file_allow_write(cur->file);
  close_owned_file(cur->tid);
  
  //free supplementary page table
  free_supple_table (&cur->spt);
  
  parent = get_thread(cur->pid);
  if (parent != NULL)
    {
	  lock_acquire(&parent->child_lock);
	  if (parent->child_load_success == 0)
	    parent->child_load_success = -1;
	  cond_signal(&parent->child_cond, &parent->child_lock);
	  lock_release(&parent->child_lock);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, const char *file_name);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);
static bool lazy_loading (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes, 
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  /*file = filesys_open (file_name);*/
  file = filesys_open (t->name);
  if (file == NULL) 
    {
      /*printf ("load: %s: open failed\n", file_name);*/
      printf ("load: %s: open failed\n", t->name);
      file_close(file);
      goto done; 
    }
  t->file = file;
  file_deny_write(file);
  

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      /*printf ("load: %s: error loading executable\n", file_name);*/
	  printf ("load: %s: error loading executable\n", t->name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          {
		  bool validation = validate_segment (&phdr, file);
          if (validation) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
              {
                /* Normal segment.
                   Read initial part from disk and zero the rest. */
                read_bytes = page_offset + phdr.p_filesz;
                zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                              - read_bytes);
              }
              else 
              {
                /* Entirely zero.
                   Don't read anything from disk. */
                read_bytes = 0;
                zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
              }
              if (!lazy_loading (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
          }
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, file_name))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = allocate_frame (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          free_vm_frame (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          free_vm_frame (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/*
    loading the segments lazily
*/
static bool lazy_loading (struct file *file, off_t ofs, uint8_t *upage,
                     uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);
  //file_seek (file, ofs);
  size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
  size_t page_zero_bytes = PGSIZE - page_read_bytes;
  for (; read_bytes > 0 || zero_bytes > 0; 
       read_bytes-=page_read_bytes, zero_bytes-=page_zero_bytes) 
  {
    /* Calculate how to fill this page.
       We will read PAGE_READ_BYTES bytes from FILE
       and zero the final PAGE_ZERO_BYTES bytes. */
    page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    page_zero_bytes = PGSIZE - page_read_bytes;
    if(!insert_file(file, ofs, upage, page_read_bytes, page_zero_bytes, 
        writable))
      return false; 
        
    upage += PGSIZE;
    ofs += page_read_bytes;      
      
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
/* Transforming setup_stack so it setups our stack here
   We push everything in the order shown in 4.5.1*/
static bool
setup_stack (void **esp, const char *file_name) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = allocate_frame (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
  {
    success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
	  {
      *esp = PHYS_BASE;
	    uint8_t *argstr_head;
      char *prog_name = thread_current ()->name;
      int strlength;
      int total_length = 0;
      /*needed as we have no idea how many arguments are there in total*/
      int argc = 0;

      /*pushing file_name(argv[3][...], argv[2][...], argv[1][...])*/
      strlength = strlen(file_name) + 1;
      *esp -= strlength;
      memcpy(*esp, file_name, strlength);
      total_length += strlength;

      /*pushing argv[0][...]*/
      strlength = strlen(prog_name) + 1;
      *esp -= strlength;
      argstr_head = *esp;
      memcpy(*esp, prog_name, strlength);
      total_length += strlength;

      /*word-align*/
      *esp -= 4 - total_length % 4;

      /*pushing argv[argc] = null into the stack* (argv[4])*/
      *esp -= 4;
      * (uint32_t *) *esp = (uint32_t) NULL;

      /*Setting up the alignment, changing all the ' ' to '\0'*/
      int i = total_length - 1;
      /*omitting the starting space and '\0' */
      while (*(argstr_head + i) == ' ' ||  *(argstr_head + i) == '\0')
      {
        if (*(argstr_head + i) == ' ')
        {
          *(argstr_head + i) = '\0';
        }
        i--;
      }

      /*pushing arguments' address into the stack(argv[3], argv[2], argv[1])*/
      char *mark;
      for (mark = (char *)(argstr_head + i); i > 0;
           i--, mark = (char*)(argstr_head+i))
      {
        if ( (*mark == '\0' || *mark == ' ') &&
            (*(mark+1) != '\0' && *(mark+1) != ' '))
        {
          *esp -= 4;
          * (uint32_t *) *esp = (uint32_t) mark + 1;
          argc++;
        }
        /* We replace all the ' ' to '\0' as shown in the example*/
        if (*mark == ' ')
          *mark = '\0';
      }

      /*push one more arg, which is the command name, into stack*/
      *esp -= 4;
      * (uint32_t *) *esp = (uint32_t) argstr_head;
      argc++;

      /*push argv*/
      * (uint32_t *) (*esp - 4) = *(uint32_t *) esp;
      *esp -= 4;

      /*push argc*/
      *esp -= 4;
      * (int *) *esp = argc;

      /*push return address*/
      *esp -= 4;
      * (uint32_t *) *esp = 0x0;
    } else
      free_vm_frame (kpage);
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

void close_owned_file (tid_t tid)
{
	struct list_elem *e;
	struct list_elem *next;
	struct file_descriptor *fd_struct;
	e = list_begin (&open_file_list);
	while (e != list_tail (&open_file_list))
	{
		next = list_next (e);
		fd_struct = list_entry (e, struct file_descriptor, file_elem);
		if (fd_struct->file_owner == tid)
		{
			list_remove (e);
			file_close (fd_struct->file);
			free (fd_struct);
		}
		e = next;
	}
}

unsigned
mmf_hash (const struct hash_elem *elem, void *aux UNUSED)
{
  const struct mmf *mmf = hash_entry (elem, struct mmf, elem);
  return hash_bytes (&mmf->mapid, sizeof mmf->mapid);
}

//allocating the ids to the the mmfs
static mapid_t mapid_allocation()
{
  struct thread *t = thread_current();
  return t->mapid_alloc++;
}


//helper function for finding the value
bool
mmf_less(const struct hash_elem *a, const struct hash_elem *b,
                   void *aux UNUSED) 
{


   const struct mmf *mmfA = hash_entry(a, struct mmf, elem);
   const struct mmf *mmfB = hash_entry(b, struct mmf, elem);

   return (mmfA->mapid < mmfB->mapid);
}
// used to free the hash table
void 
free_mmfs (struct hash *mmfs)
{
  hash_destroy (mmfs, free_mmfs_entry);
}
//used to free specific hash entries
static void
free_mmfs_entry (struct hash_elem *e, void *aux UNUSED)
{
  struct mmf *mmf;
  mmf = hash_entry (e, struct mmf, elem);
  mmfs_free_entry (mmf);
}
// used to iteratively free the mmf entries
static void
mmfs_free_entry (struct mmf* mmf_ptr)
{
  struct thread *t = thread_current ();
  struct hash_elem *e;
  int pg_num;
  struct supple_page_table_entry entry;
  struct supple_page_table_entry *entry_ptr;
  int ofs;

  pg_num = mmf_ptr->pg_num;
  ofs = 0;
  while (pg_num-- > 0)
    {
      entry.uvpaddr = mmf_ptr->addr + ofs;
      e = hash_delete (&t->spt, &entry.elem);
      if (e != NULL)
	    {
	      entry_ptr = hash_entry (e, struct supple_page_table_entry, elem);
	      if (entry_ptr->is_loaded
	                        && pagedir_is_dirty (t->pagedir, entry_ptr->uvpaddr))
	      {
	        lock_acquire (&fileLock);
	        file_seek (entry_ptr->mmf_page.file, entry_ptr->mmf_page.ofset);
	        file_write (entry_ptr->mmf_page.file, 
			    entry_ptr->uvpaddr,
			    entry_ptr->mmf_page.reads);
	        lock_release (&fileLock);
	      }
	      free (entry_ptr);
	    }
      ofs += PGSIZE;
    }

  lock_acquire (&fileLock);
  file_close (mmf_ptr->file);
  lock_release (&fileLock);

  free (mmf_ptr);
}



// inserting the mmf file into the hash table of the mmf files
mapid_t add_mmf (void *addr, struct file* file, int32_t length)
{
  struct thread *t = thread_current ();
  struct mmf *mmf;
  struct hash_elem *elem;
  int ofs;
  int pg_num;

  mmf = calloc (1, sizeof *mmf);
  if (mmf == NULL)
    return -1;

  mmf->mapid = mapid_allocation ();
  mmf->file = file;
  mmf->addr = addr;

  ofs = 0;
  pg_num = 0;
  while (length > 0)
  {
    size_t read_bytes = PGSIZE;
    if(length<PGSIZE)
      read_bytes = length;
    if (!insert_mmf (file, ofs, addr, read_bytes))
	    return -1;

    ofs += PGSIZE;
    length -= PGSIZE;
    addr += PGSIZE;
    pg_num++;
  }

  mmf->pg_num = pg_num;  

  elem = hash_insert (&t->mmfs, &mmf->elem);
  if (elem != NULL)
    return -1;

  return mmf->mapid;
}

//deleting the element and freeing it from the hash table
void
remove_mmfs (mapid_t mapid)
{
  struct thread *cur = thread_current ();
  struct mmf mmf;
  struct mmf *mmf_ptr;
  struct hash_elem *elem;

  mmf.mapid = mapid;
  elem = hash_delete (&cur->mmfs, &mmf.elem);
  if (elem != NULL)
    {
      mmf_ptr = hash_entry (elem, struct mmf, elem);
      mmfs_free_entry (mmf_ptr);
    }
}




