#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <stdlib.h>

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
      get_stack_arguments(f, &args[0], 1);

				/* We pass exit the status code of the process. */
			exit(args[0]);
      break;
    }
    default:
      printf("Unhandled system call %d!\n", int_no);
      thread_exit();
  }
}