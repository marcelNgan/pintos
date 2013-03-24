#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/pte.h"
#include "lib/kernel/list.h"
#include "userprog/pagedir.h"  
#include "vm/page.h" 
#include "vm/frame.h"
#include "vm/swap.h"

static struct lock frame_lock;
static struct lock evict_lock;

/* addding and deleting from frames */
static bool insert_frame (void *);
static void delete_frame (void *);

//lookup function to find frames
static struct frame *get_frame (void *);

// eviction
static struct frame *choose_eviction(void);
static bool store_eviction(struct frame *);

void
init_vm_frame ()
{
  list_init (&frames);
  lock_init (&frame_lock);
  lock_init (&evict_lock);
}
void *allocate_frame (enum palloc_flags pflags)
{
  void *frame = NULL;

  /* allocating a page */
  if (pflags & PAL_USER)
    {
      if (pflags & PAL_ZERO)
        frame = palloc_get_page (PAL_USER | PAL_ZERO);
      else
        frame = palloc_get_page (PAL_USER);
    }

  /* if it succeeds, add to frames list
     otherwise fail the allocator for now */
  if (frame != NULL)
    insert_frame (frame);
  else 
  {
    frame = evict();
    if (frame == NULL)
      PANIC ("Failed to evict a frame!");
  }

  return frame;
}


void free_vm_frame (void *frame)
{
  //delete the frame from the table
  delete_frame(frame);
  //free the memory
  palloc_free_page (frame);
  
  
}

void set_frame_usr (void* frame, uint32_t *page_table_entry, void *paddr)
{ 
  struct frame *frame_vm;
  frame_vm = get_frame (frame);
  if (frame_vm != NULL)
    {
      frame_vm->page_table_entry = page_table_entry;
      frame_vm->uvpaddr = paddr;
    }
}


static bool insert_frame (void *frame)
{
  struct frame* vm_frame;
  vm_frame = calloc(1, sizeof *vm_frame);
  
  if(vm_frame ==NULL)
    return false;
    
  vm_frame->tid = thread_current()->tid;
  vm_frame->frame = frame;
  
  lock_acquire(&frame_lock);
  list_push_back(&frames, &vm_frame->frame_elem);
  lock_release(&frame_lock);
  
  return true;
}
static void delete_frame (void *frame)
{
  struct frame* vm_frame;
  struct list_elem *elem ;
  
  lock_acquire(&frame_lock);
  elem = list_head (&frames);
  while ((elem = list_next(elem)) != list_tail(&frames))
  {
    vm_frame = list_entry(elem, struct frame, frame_elem);
    if(vm_frame->frame == frame)
    {
      list_remove (elem);
      free(vm_frame);
      break;
    }  
  }
  lock_release(&frame_lock);

}
static struct frame *get_frame (void *frame)
{  
  struct frame* vm_frame;
  struct list_elem *elem;
  
  lock_acquire(&frame_lock);
  elem =list_head (&frames);
  while ((elem = list_next(elem)) != list_tail(&frames))
  {
    vm_frame = list_entry(elem, struct frame, frame_elem);
    if(vm_frame->frame == frame)
      break;
    vm_frame = NULL;
      
  }
  lock_release(&frame_lock);
  
  return vm_frame;
}

void *
evict()
{
  bool result;
  struct frame *vm_frame;
  struct thread *cur = thread_current ();

  lock_acquire (&evict_lock);

  vm_frame = choose_eviction();
  if (vm_frame == NULL)
    PANIC ("Could not find a frame to evict!");

  result = store_eviction(vm_frame);
  if (!result)
    PANIC ("Evicted frame was not saved!");
  
  vm_frame->tid = cur->tid;
  vm_frame->page_table_entry = NULL;
  vm_frame->uvpaddr = NULL;

  lock_release (&evict_lock);

  return vm_frame->frame;
}


static bool
store_eviction (struct frame *vm_frame)
{
  struct thread *thread;
  struct supple_page_table_entry *entry;

  thread = get_thread (vm_frame->tid);

  entry = find_supple_entry (&thread->spt, vm_frame->uvpaddr);
   
  if (entry == NULL)
  {
    entry = calloc(1, sizeof *entry);
    entry->uvpaddr = vm_frame->uvpaddr;
    entry->type = SWAP;
    if (!insert_supple_page_table_entry(&thread->spt, entry))
      return false;
  }

  size_t swap_slot;

  if (pagedir_is_dirty (thread->pagedir, entry->uvpaddr)
      && (entry->type == MMF))
  {
    write_unlocked_file (entry);
  }
  else if (pagedir_is_dirty (thread->pagedir, entry->uvpaddr)
      || (entry->type != FILE))
  {
    swap_slot = swap_page_in (entry->uvpaddr);
    if (swap_slot == SWAP_ERROR)
      return false;

    entry->type = entry->type | SWAP;
  }

  memset (vm_frame->frame, 0, PGSIZE);
  entry->swap_slot = swap_slot;
  entry->is_writable = *(vm_frame->page_table_entry) & PTE_W;
  
  entry->is_loaded = false;
  
  pagedir_clear_page (thread->pagedir, entry->uvpaddr);
  return true;
}

static struct frame*
choose_eviction () {
  sruct frame *vm_frame;
  struct thread *thread;
  struct list_elem *elem;
  struct frame *temp_frame = NULL;
  int count = 1;
  bool done = false;

  while (!found)
  {
	elem = list_head (&frames);
	while (elem = list_next(elem)) != list_tail(&frames))
	{
	  vm_frame = list_entry (elem, struct frame, frame_elem);
	  thread = get_thread(vm_frame->tid);
	  bool is_accessed = pagedir_is_accessed (thread->pagedir, vm_frame->uvpaddr);
	  if (!is_accessed)
	  {
	    temp_frame = vm_frame;
		list_remove (elem);
		list_push_back (frames,elem);
		break;
	  } else
	  {
	    pagedir_set_accessed (thread->pagedir, frame->uvpaddr, false);
	  }
	}
	round_count++;
	if (temp_frame != NULL)
	  found = true;
	else if (round_count == 2)
	  found = true;
  }
  return temp_frame;
}
