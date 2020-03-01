#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "process.h"

static void syscall_handler (struct intr_frame *);

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
        exit(RETURN_ERROR);
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
  if(status == 0){
    thread_current()->exit_status = 0;
    printf("%s: exit(%i)\n", thread_current()->name, status);
    thread_exit();
  }

  thread_current()->exit_status = status;
  printf("%s: exit(%i)\n", thread_current()->name, status);
  thread_exit();
}