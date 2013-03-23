#include <stdbool.h>
#include <stddef.h>
#include "devices/block.h"
#include <inttypes.h>
#include "threads/vaddr.h"
#include "threads/synch.h"
#include <bitmap.h>
#include "vm/swap.h"

/* keep track of sizes */
static size_t SECTORS_IN_PAGE = PGSIZE / BLOCK_SECTOR_SIZE;
static size_t total_swap_pages (void);

/* device and map for the swaps */
static struct bitmap *swap_bitmap;
struct block *swap_block;


/* init the device, and bitmap for swaps */
void 
swap_init() {
  swap_block = block_get_role(BLOCK_SWAP);
  if (swap_block == NULL)
    PANIC ("Swap device failed to initialise!");

  swap_bitmap = bitmap_create (total_swap_pages());
  if (swap_bitmap == NULL)
    PANIC ("Swap bitmap failed to initialise!");

  bitmap_set_all (swap_bitmap, true);
}

/* copy data into a swap slot */
size_t 
swap_page_in(const void *uva)
{
  /* find a valid slot, return SWAP_ERROR if none */
  size_t chosen_slot = bitmap_scan_and_flip (swap_bitmap, 0, 1, true);
  
  if (chosen_slot == BITMAP_ERROR)
    return SWAP_ERROR;

  /* load the data into the slot */
  size_t sector = 0;
  while (sector < SECTORS_IN_PAGE) 
  {
    block_write (swap_block, chosen_slot * SECTORS_IN_PAGE + sector, 
		   uva + sector * BLOCK_SECTOR_SIZE);
    sector++;
  }

  return chosen_slot;
}

/* copy data out of swap slot into main memory */
void
swap_page_out(size_t slot, void *uva) {

  size_t sector = 0;
  while (sector < SECTORS_IN_PAGE)
    {
      block_read (swap_block, slot * SECTORS_IN_PAGE + sector,
		  uva + sector * BLOCK_SECTOR_SIZE);
      sector++;
    }

  bitmap_flip (swap_bitmap, slot);  
}

/* clear a slot by unmarking it in the bitmap */
void 
clear_slot (size_t slot)
{
  bitmap_flip (swap_bitmap, slot);  
}

/* Total number of slots in the swap device */
static size_t
total_swap_pages()
{
  return block_size (swap_block) / SECTORS_IN_PAGE;
}
