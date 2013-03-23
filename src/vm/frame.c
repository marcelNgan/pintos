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
  struct thread *t = thread_current();
  vm_frame = calloc(1, sizeof *vm_frame);
  
  if(vm_frame ==NULL)
    return false;
    
  vm_frame->thread = t->tid;
  vm_frame->frame = frame;
  
  lock_acquire(&frame_lock);
  list_push_back(&frames, &vm_frame->frame_elem);
  lock_release(&frame_lock);
  
  return true;
}
static void delete_frame (void *frame)
{
  struct frame* vm_frame;
  struct list_elem *frame_elem =list_head (&frames) ;
  
  lock_acquire(&frame_lock);
  while ((frame_elem = list_next(frame_elem)) != list_tail(&frames))
  {
    vm_frame = list_entry(frame_elem, struct frame, frame_elem);
    if(vm_frame->frame == frame)
    {
      list_remove (frame_elem);
      free(vm_frame);
      break;
    }  
  }
  lock_release(&frame_lock);

}
static struct frame *get_frame (void *frame)
{  
  struct frame* vm_frame;
  struct list_elem *frame_elem =list_head (&frames) ;
  
  lock_acquire(&frame_lock);
  while ((frame_elem = list_next(frame_elem)) != list_tail(&frames))
  {
    vm_frame = list_entry(frame_elem, struct frame, frame_elem);
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
  struct frame *frame;
  struct thread *thread = thread_current ();

  lock_acquire (&evict_lock);

  frame = choose_eviction();
  if (frame == NULL)
    PANIC ("Could not find a frame to evict!");

  result = store_eviction(frame);
  if (!result)
    PANIC ("Evicted frame was not saved!");
  
  frame->thread = thread->tid;
  frame->page_table_entry = NULL;
  frame->uvpaddr = NULL;

  lock_release (&evict_lock);

  return frame->frame;
}


static bool
store_eviction (struct frame *frame)
{
  struct thread *thread;
  struct supple_page_table_entry *entry;

  thread = get_thread (frame->thread);

  entry = find_supple_entry (&thread->spt, frame->uvpaddr);
   
  if (entry == NULL)
  {
    entry = calloc(1, sizeof *entry);
    entry->uvpaddr = frame->uvpaddr;
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

  memset (frame->frame, 0, PGSIZE);
  entry->swap_slot = swap_slot;
  entry->is_writable = *(frame->page_table_entry) & PTE_W;
  
  entry->is_loaded = false;
  
  pagedir_clear_page (thread->pagedir, entry->uvpaddr);
  return true;
}

static struct frame*
choose_eviction () {
  struct list_elem *e = list_head (&frames);
  struct frame *frame = list_entry (e, struct frame, frame_elem);
  return frame;
}
