#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdio.h>
#include "threads/thread.h"
#include "threads/palloc.h"
#include "lib/kernel/hash.h"
#include "filesys/file.h"

#define STACK_SIZE (8 * (1 << 20))

enum supple_type
{
  SWAP = 001,
  FILE = 002,
  MMF  = 004
};

struct file_page
{
    struct file * file;
    off_t ofset;
    uint32_t reads;
    uint32_t zeros;
    bool is_writable;
};
struct mmf_page 
{
    struct file *file;
    off_t ofset;
    uint32_t reads;
};

struct supple_page_table_entry
{
  struct hash_elem elem;

  void *uvpaddr;   //user virtual page address
  enum supple_type type;
  struct file_page file_page;
  struct mmf_page mmf_page;
  bool is_loaded;

  size_t swap_slot;
  bool is_writable;

};


void init_page (void);

//basic functionalities for the hash table
unsigned supple_hash_ptable (const struct hash_elem *, 
                                     void* UNUSED);
bool supple_less(const struct hash_elem *, const struct hash_elem *,
                                            void * UNUSED);
//inserting an entry to the hash table
bool insert_supple_page_table_entry (struct hash *, 
                                        struct supple_page_table_entry *);
                                        
//inserting a file
bool insert_file (struct file *, off_t, uint8_t *, uint32_t, 
                                                  uint32_t, bool);
//inserting a mmf
bool insert_mmf (struct file *, off_t, uint8_t *, uint32_t);

//normal lookup function for a hash table
struct supple_page_table_entry *find_supple_entry (struct hash *, void *);

//write a dirty file back to the address
void write_unlocked_file (struct supple_page_table_entry*);

//frees up the hash table
void free_supple_table (struct hash *);

//load the data from the entry
bool load_data (struct supple_page_table_entry *);

// grow the stack as you add more data to it.
void increase_stack (void *);
#endif 
