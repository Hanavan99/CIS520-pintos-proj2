#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "lib/user/syscall.h"
#include "userprog/pagedir.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

struct lock lock_filesys;

static void syscall_handler (struct intr_frame *);

static void sys_exit(int);

void
syscall_init (void) 
{
  lock_init(&lock_filesys);

  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// checks if a pointer is valid for the current thread
bool check_pointer(void * ptr) {
  struct thread * t = thread_current();
  return pagedir_get_page(t->pagedir, ptr) != NULL;
}

void read_user_mem(void * addr, void * dest, size_t size) {
  // TODO use virtual memory
  int i;
  for (i = 0; i < size; i++) {
    if (!check_pointer(addr + i)) {
      // invalid access
      sys_exit(-1);
    }
    *((char *) dest + i) = *((char *) addr + i);
  }
}

// --------- START OF SYSCALL HANDLERS ---------

void sys_halt() {
  shutdown_power_off();
}

void sys_exit(int exit_code) {
  thread_current()->exit_code = exit_code;
  printf ("%s: exit(%d)\n", thread_current()->name, exit_code);
  thread_exit();
}

pid_t sys_exec(const char * cmd) {
  return 0;
}

int sys_wait(pid_t pid) {
  return process_wait(pid);
}

bool sys_create(const char * filename, unsigned int size) {

  lock_acquire(&lock_filesys);
  bool exit_code = filesys_create(filename, size);
  lock_release(&lock_filesys);
  return exit_code;
}

bool sys_remove(const char * filename) {

  lock_acquire(&lock_filesys);
  bool exit_code = filesys_remove(filename);
  lock_release(&lock_filesys);
  return exit_code;
}

int sys_open(const char * filename) {
  /* Make sure that only one process can get ahold of the file system at one time. */
  lock_acquire(&lock_filesys);

  struct file* f = filesys_open(filename);

  /* If no file was created, then return -1. */
  if(f == NULL)
  {
    lock_release(&lock_filesys);
    return -1;
  }

  /* Create a struct to hold the file/fd, for use in a list in the current process.
     Increment the fd for future files. Release our lock and return the fd as an int. */
  struct thread_file *new_file = malloc(sizeof(struct thread_file));
  new_file->file_addr = f;
  int fd = thread_current ()->cur_fd;
  thread_current ()->cur_fd++;
  new_file->file_descriptor = fd;
  list_push_front(&thread_current ()->file_descriptors, &new_file->file_elem);
  lock_release(&lock_filesys);
  return fd;
}

int sys_filesize(int fd) {
  struct list_elem *temp;

  lock_acquire(&lock_filesys);

  /* If there are no files associated with this thread, return -1 */
  if (list_empty(&thread_current()->file_descriptors))
  {
    lock_release(&lock_filesys);
    return -1;
  }

  /* Check to see if the given fd is open and owned by the current process. If so, return
     the length of the file. */
  for (temp = list_front(&thread_current()->file_descriptors); temp != NULL; temp = temp->next)
  {
      struct thread_file *t = list_entry (temp, struct thread_file, file_elem);
      if (t->file_descriptor == fd)
      {
        lock_release(&lock_filesys);
        return (int) file_length(t->file_addr);
      }
  }

  lock_release(&lock_filesys);

  /* Return -1 if we can't find the file. */
  return -1;
}

void sys_seek(int fd, unsigned int position) {
/* list element to iterate the list of file descriptors. */
  struct list_elem *temp;

  lock_acquire(&lock_filesys);

  /* If there are no files to seek through, then we immediately return. */
  if (list_empty(&thread_current()->file_descriptors))
  {
    lock_release(&lock_filesys);
    return;
  }

  /* Look to see if the given fd is in our list of file_descriptors. IF so, then we
     seek through the appropriate file. */
  for (temp = list_front(&thread_current()->file_descriptors); temp != NULL; temp = temp->next)
  {
      struct thread_file *t = list_entry (temp, struct thread_file, file_elem);
      if (t->file_descriptor == fd)
      {
        file_seek(t->file_addr, position);
        lock_release(&lock_filesys);
        return;
      }
  }

  lock_release(&lock_filesys);

  /* If we can't seek, return. */
  return;
}

unsigned int sys_tell(int fd) {
  /* list element to iterate the list of file descriptors. */
  struct list_elem *temp;

  lock_acquire(&lock_filesys);

  /* If there are no files in our file_descriptors list, return immediately, */
  if (list_empty(&thread_current()->file_descriptors))
  {
    lock_release(&lock_filesys);
    return -1;
  }

  /* Look to see if the given fd is in our list of file_descriptors. If so, then we
     call file_tell() and return the position. */
  for (temp = list_front(&thread_current()->file_descriptors); temp != NULL; temp = temp->next)
  {
      struct thread_file *t = list_entry (temp, struct thread_file, file_elem);
      if (t->file_descriptor == fd)
      {
        unsigned position = (unsigned) file_tell(t->file_addr);
        lock_release(&lock_filesys);
        return position;
      }
  }

  lock_release(&lock_filesys);

  return -1;
}

void sys_close(int fd) {
  struct list_elem *temp;

  lock_acquire(&lock_filesys);

  /* Check to see if the given fd is open and owned by the current process. */
  for (temp = list_front(&thread_current()->file_descriptors); temp != NULL; temp = temp->next)
  {
      struct thread_file *t = list_entry (temp, struct thread_file, file_elem);
      if (t->file_descriptor == fd)
      {
        file_close(t);
        list_remove(&(temp));
        palloc_free_page(t);
        lock_release(&lock_filesys);
        break;
      }
  }

  lock_release(&lock_filesys);
}

int sys_read(int fd, void * buffer, unsigned int size) {
  /* list element to iterate the list of file descriptors. */
  struct list_elem *temp;

  lock_acquire(&lock_filesys);

  /* If fd is one, then we must get keyboard input. */
  if (fd == 0)
  {
    lock_release(&lock_filesys);
    return (int) input_getc();
  }

  /* We can't read from standard out, or from a file if we have none open. */
  if (fd == 1 || list_empty(&thread_current()->file_descriptors))
  {
    lock_release(&lock_filesys);
    return 0;
  }

  /* Look to see if the fd is in our list of file descriptors. If found,
     then we read from the file and return the number of bytes written. */
  for (temp = list_front(&thread_current()->file_descriptors); temp != NULL; temp = temp->next)
  {
      struct thread_file *t = list_entry (temp, struct thread_file, file_elem);
      if (t->file_descriptor == fd)
      {
        lock_release(&lock_filesys);
        int bytes = (int) file_read(t->file_addr, buffer, size);
        return bytes;
      }
  }

  lock_release(&lock_filesys);

  /* If we can't read from the file, return -1. */
  return -1;
}

int sys_write(int fd, const void * buffer, unsigned int size) {
  struct list_elem * temp;

  lock_acquire(&lock_filesys);

  // see if we need to write to stdout
  if (fd == 1) {
    putbuf(buffer, size);
    lock_release(&lock_filesys);
    return size;
  }

  if (fd == 0 || list_empty(&thread_current()->file_descriptors)) {
    lock_release(&lock_filesys);
    return 0;
  }

  for (temp = list_front(&thread_current()->file_descriptors); temp != NULL; temp = temp->next) {
    struct thread_file * t = list_entry(temp, struct thread_file, file_elem);
    if (t->file_descriptor == fd) {
      int bytes_written = (int) file_write(t->file_addr, buffer, size);
      lock_release(&lock_filesys);
      return bytes_written;
    }
  }

  lock_release(&lock_filesys);
  return 0;
}

// ---------- END OF SYSCALL HANDLERS ----------

static void
syscall_handler (struct intr_frame *f) 
{
  int int_no;
  read_user_mem(f->esp, &int_no, sizeof(int_no)); // dereference stack pointer because arg0 is stored there
  switch (int_no) {
    case SYS_HALT:
      sys_halt();
      break;
    case SYS_EXIT:
      {
        int exit_code;
        read_user_mem(f->esp + 4, &exit_code, sizeof(exit_code));
        sys_exit(exit_code);
      }
      break;
    case SYS_EXEC:
      {
        void * cmd;
        read_user_mem(f->esp + 4, &cmd, sizeof(cmd));
        int return_code = sys_exec((const char *) cmd);
        f->eax = (uint32_t) return_code;
      }
      break;
    case SYS_WAIT:
      {
        pid_t pid;
        read_user_mem(f->esp + 4, &pid, sizeof(pid));
        int return_code = sys_wait(pid);
        f->eax = (uint32_t) return_code;
      }
      break;
    case SYS_CREATE:
      {
        const char * filename;
        unsigned int initial_size;
        bool return_code;
        read_user_mem(f->esp + 4, &filename, sizeof(filename));
        read_user_mem(f->esp + 8, &initial_size, sizeof(initial_size));
        return_code = sys_create(filename, initial_size);
        f->eax = (uint32_t) return_code;
      }
      break;
    case SYS_REMOVE:
      {
        const char * filename;
        bool return_code;
        read_user_mem(f->esp + 4, &filename, sizeof(filename));
        return_code = sys_remove(filename);
        f->eax = (uint32_t) return_code;
      }
      break;
    case SYS_OPEN:
      {
        const char * filename;
        int return_code;
        read_user_mem(f->esp + 4, &filename, sizeof(filename));
        return_code = sys_open(filename);
        f->eax = (uint32_t) return_code;
      }
      break;
    case SYS_FILESIZE:
      {
        int fd, return_code;
        read_user_mem(f->esp + 4, &fd, sizeof(fd));
        return_code = sys_filesize(fd);
        f->eax = (uint32_t) return_code;
      }
      break;
    case SYS_READ:
      {
        int fd, return_code;
        void * buffer;
        unsigned int size;
        read_user_mem(f->esp + 4, &fd, sizeof(fd));
        read_user_mem(f->esp + 8, &buffer, sizeof(buffer));
        read_user_mem(f->esp + 12, &size, sizeof(size));
        f->eax = (uint32_t) sys_read(fd, buffer, size);
      }
      break;
    case SYS_WRITE:
      {
        int fd;
        unsigned int size;
        const void * buffer;
        read_user_mem(f->esp + 4, &fd, sizeof(fd));
        read_user_mem(f->esp + 8, &buffer, sizeof(buffer));
        read_user_mem(f->esp + 12, &size, sizeof(size));
        f->eax = (uint32_t) sys_write(fd, buffer, size);
      }
      break;
    case SYS_SEEK:
      {
        int fd;
        unsigned int position;
        read_user_mem(f->esp + 4, &fd, sizeof(fd));
        read_user_mem(f->esp + 8, &position, sizeof(position));
        sys_seek(fd, position);
      }
      break;
    case SYS_TELL:
      {
        int fd;
        unsigned int return_code;
        read_user_mem(f->esp + 4, &fd, sizeof(fd));
        return_code = sys_tell(fd);
        f->eax = (uint32_t) return_code;
      }
      break;
    case SYS_CLOSE:
      {
        int fd;
        read_user_mem(f->esp + 4, &fd, sizeof(fd));
        sys_close(fd);
      }
      break;
    default:
      printf("Unhandled system call %d!\n", int_no);
      sys_exit(-1);
  }
}