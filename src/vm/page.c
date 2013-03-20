#include "vm/page.h"
#include "threads/pte.h"
#include "vm/frame.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "string.h"
#include "userprog/syscall.h"


static bool load_file(struct supple_page_table_entry *);
static bool load_mmf(struct supple_page_table_entry *);
static void free_entries (struct hash_elem *, void * UNUSED);

void init_page (void){
   return;
}

unsigned supple_hash_ptable (const struct hash_elem * elem, void *aux UNUSED)
{                                     

  const struct supple_page_table_entry *entry = hash_entry(elem, 
                                        struct supple_page_table_entry, elem);
                                        
  return hash_bytes (&entry->uvpaddr, sizeof entry->uvpaddr);                                                                        
}                         

          
bool supple_less(const struct hash_elem *a, const struct hash_elem *b,
                                            void *aux UNUSED)
{
   ASSERT(a!=NULL);
   ASSERT(b!=NULL);

   const struct supple_page_table_entry *entryA = hash_entry(a, 
                                         struct supple_page_table_entry, elem);
   const struct supple_page_table_entry *entryB = hash_entry(b, 
                                         struct supple_page_table_entry, elem);

   return (entryA->uvpaddr < entryB->uvpaddr);
}
                                            
                                            
bool insert_supple_page_table_entry (struct hash * table, 
                                        struct supple_page_table_entry * entry)
{
  struct hash_elem *elem;
  if (entry ==NULL)
    return false;
  elem = hash_insert (table, &entry->elem);
  if(elem == NULL)
    return true;
    
  else 
    return false;
                                            
} 
                                        
bool insert_file (struct file *f, off_t ofset, uint8_t * userp, 
                               uint32_t reads, uint32_t zeros, bool writable)
{
  struct supple_page_table_entry *entry;
  struct thread *current = thread_current();
  struct hash_elem * elem;
  
  entry = calloc (1, sizeof *entry);
  if(entry == NULL)
    return false;
  
    entry->uvpaddr = userp;
    entry->type = FILE;
    entry->file_page.ofset = ofset;
    entry->file_page.file = f;
    entry->file_page.reads = reads;
    entry->file_page.zeros = zeros;
    entry->file_page.is_writable = writable;
//    entry->mmf_page = NULL;
    entry->is_loaded = false;
    
    
    elem = hash_insert (&current->spt, &entry->elem);
    
    if (elem == NULL)
      return true;
    
    return false;

  
  
                                            
}                                                   
bool insert_mmf (struct file *f, off_t ofset, uint8_t * userp, 
                                                      uint32_t reads)
{
  struct supple_page_table_entry *entry;
  struct thread *current = thread_current();
  struct hash_elem * elem;
  
  entry = calloc (1, sizeof *entry);
  if(entry == NULL)
    return false;
  else
  {
    entry->uvpaddr = userp;
    entry->type = MMF;
    entry->mmf_page.ofset = ofset;
    entry->mmf_page.file = f;
    entry->mmf_page.reads = reads;
 //   entry->file_page = NULL;
    entry->is_loaded = false;
    
    
    elem = hash_insert (&current->spt, &entry->elem);
    
    if (elem == NULL)
      return true;
    
    return false;

  }
                                            
} 
struct supple_page_table_entry *find_supple_entry (struct hash * table, 
                                                                void *address)
{
  struct supple_page_table_entry entry;
  struct hash_elem *elem;
  
  
  entry.uvpaddr = address;
  elem = hash_find (table, &entry.elem);
  if(elem==NULL)
    return NULL;
  return hash_entry(elem, struct supple_page_table_entry, elem);
                                            
} 
void write_unlocked_file (struct supple_page_table_entry *entry)
{
  if(entry->type == MMF)
    {
    file_seek(entry->mmf_page.file, entry->mmf_page.ofset);
    file_write(entry->mmf_page.file,entry->uvpaddr, entry->mmf_page.reads);
    }
                                            
} 
void free_supple_table (struct hash * table)
{
  hash_destroy (table, free_entries);                                            
} 

static void free_entries(struct hash_elem *e, void *aux UNUSED)
{
  struct supple_page_table_entry *entry = hash_entry (e, 
                                        struct supple_page_table_entry, elem);
  
  
  free(entry);

}
bool load_data (struct supple_page_table_entry *entry)
{
  bool result = false;
  switch (entry-> type)
  {
    case MMF:
      result = load_mmf(entry);
      break;
    case FILE:
      result = load_file(entry);
      break;    
    default:
      break;
  }
  return result;
                                            
} 

static bool load_file(struct supple_page_table_entry *entry)
{
  bool result;
  struct thread *t = thread_current();

  file_seek (entry->file_page.file, entry->file_page.ofset);
  //get memory from the user pool
  uint8_t *page;
  page = allocate_frame(PAL_USER);
  if(page == NULL) return false;
  
  int fileRead = file_read(entry->file_page.file,page, entry->file_page.reads);
  int read = (int) entry ->file_page.reads;
  if(fileRead != read)
  {
    free_vm_frame (page);
    return false;
  }
  memset (page + entry->file_page.reads,0,entry->file_page.zeros);
  result = pagedir_set_page (t->pagedir, entry->uvpaddr, page,
                                              entry->file_page.is_writable);
  if(!result)
  {
    free_vm_frame (page);
    return false;
  }
  entry->is_loaded = result;
  return result;
}

static bool load_mmf (struct supple_page_table_entry *entry)
{
  bool result;

  struct thread *t = thread_current();

  file_seek (entry->mmf_page.file, entry->mmf_page.ofset);
  //get memory from the user pool
  uint8_t *page;
  page =  allocate_frame(PAL_USER);
  if(page == NULL) return false;

  int fileRead = file_read(entry->mmf_page.file,page, entry->mmf_page.reads);
  int read = (int) entry ->mmf_page.reads;
  if(fileRead != read)
  {
    free_vm_frame (page);
    return false;
  }
  memset (page + entry->mmf_page.reads,0,PGSIZE - entry->mmf_page.reads);
  result = pagedir_set_page (t->pagedir, entry->uvpaddr, page, true);
  if(!result)
  {
    free_vm_frame (page);
    return false;
  }
  entry->is_loaded = result;
  return result;
}
void increase_stack (void *address)
{
  void *page; 
  page = allocate_frame(PAL_USER | PAL_ZERO);
  if(page==NULL)
    return;

  else
  {
    struct thread *t = thread_current();
    bool success = pagedir_set_page(t->pagedir, pg_round_down (address), page, true);
    if(!success)
    {

      free_vm_frame(page);
    }

  }
                                            
} 