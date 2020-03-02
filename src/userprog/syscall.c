#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);

struct lock fileLock;

static bool
get_int_arg (const uint8_t *uaddr, int pos, int *pi)
{
  return read_int (uaddr + sizeof (int) * pos, pi);
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int int_no = *((int *) f->esp); // dereference stack pointer because arg0 is stored there
  switch (int_no) {
    case SYS_HALT:
      shutdown_power_off();
      break;
    case SYS_EXIT:
    {
      int * ec = pagedir_get_page(thread_current()->pagedir, f->esp + INSTRUCTION_SIZE4);
      if(ec == NULL){
        exit(-1);
      }
      exit(*(ec));
      break;
    }
    case SYS_WRITE:
    {
    }
    default:
      printf("Unhandled system call %d!\n", int_no);
      thread_exit();
  }
}

void exit (int status){
  thread_current()->exit_status = status;
  printf("%s: exit(%i)\n", thread_current()->name, status);
  thread_exit();
}

//fd = open file
//buffer = bytes to be written
//size = size of buffer
int write(int fd, const void * buffer, unsigned size){
  unsigned written = -1;   //counter for bytes written
  unsigned maxSize;   //max size to be sent to putbuf()

  if(get_file_map(fd) == NULL)
      return written;

  if(fd == 1){
    putbuf(buffer, size);
    written = size;
  }
  else{
    struct file_map * f = getFileFrom(fd);
    if(f == NULL)
      return -1;
    lock_acquire(&fileLock);
    written = file_write(f->filename, buffer, size);
    lock_release(&fileLock);
  }


  return written;
}

struct file_map * getFileFrom(int fd){
  struct thread * cur = thread_current();
  struct list_elem * e;

  for(e = list_begin(&cur->files); e != list_end(&cur->files); e = list_next(e)){
    struct file_map * m = list_entry(e, struct file_map, elem);
    if(m->file_id == fd){
      return m;
    }
  }

  return NULL;
}