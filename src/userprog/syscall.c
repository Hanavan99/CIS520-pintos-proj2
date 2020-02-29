#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

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
      int exit_code = *((int *) f->esp + 1);
      thread_current()->exit_code = exit_code;
      thread_exit();
      break;
    }
    default:
      printf("Unhandled system call %d!\n", int_no);
      thread_exit();
  }
}