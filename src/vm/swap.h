
#ifndef VM_SWAP_H
#define VM_SWAP_H

#define SWAP_ERROR SIZE_MAX

void swap_init (void);

size_t swap_page_in (const void *);
void swap_page_out (size_t, void *);

void clear_slot (size_t);

#endif
