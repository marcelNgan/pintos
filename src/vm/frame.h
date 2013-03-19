#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/thread.h"

struct frame {
  tid_t thread;   // which thread it is in
  void *uvpaddr;  //user virtual page address
  struct list_elem frame_elem;  // adding and finding the frame in the list.
  uint32_t page_table_entry;  //where it is in page table
  void *frame; // not sure!!!!!! 

};

struct list frames;

//basic functions for frames.
void init_vm_frame(void);
void *allocate_frame (enum palloc_flags pflags);
void free_vm_frame (void *);

//setting which user has which frame
void set_frame_usr (void*, uint32_t *, void *);



#endif
