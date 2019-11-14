#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "lib/user/syscall.h"
#include "threads/vaddr.h"
static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

bool is_valid_access(uint32_t * addr);

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf ("system call!\n");
  uint32_t *esp = (uint32_t *)(f->esp); // system call #
  
  /* vefity esp */
  if(!is_valid_access(esp)) return;
  
  int syscall_num = *esp;
 
  //printf("syscall: %d\n",syscall_num);
  switch(syscall_num){
    /* 0 argument */
    case SYS_HALT:
      break;
    case SYS_EXIT:
      if(!is_valid_access(esp+1))return;
      exit(*(esp+1));
      break;
    case SYS_EXEC:
      //const char * arg0 = *(esp+1);
      //result = exec(arg0);
      break;
    case SYS_WAIT:
      break;
    case SYS_CREATE:
      break; 
    case SYS_REMOVE:
      break;
    case SYS_OPEN:
      break;
    case SYS_FILESIZE:
      break;
    case SYS_READ:
      break;
    case SYS_WRITE:
      //printf("arg0: %d\n",*(int *)(esp+1));
      //printf("arg1: %p\n",*(esp+2));
      //printf("arg2: %u\n",*(esp+3));
      write(*(int *)(esp+1), *(esp+2), *(unsigned *)(esp+3));
      break;
    case SYS_SEEK:
      break;
    case SYS_TELL:
      break;
    case SYS_CLOSE:
      break;
    
    default:
      break;
  }
   
  //f->eax = result;
}

// 1) access kernel space 2) access under user virtual addr
bool
is_valid_access(uint32_t *addr)
{
  if( addr >= (uint32_t *)PHYS_BASE || (uint32_t)addr<= 0x08048000){
    exit(-1);
    return false;
  }
  else
    return true;
}
  

void
exit(int status)
{
  printf("%s: exit(%d)\n",thread_name(),status);
  thread_exit();
}

int write(int fd, const void *buffer, unsigned size)
{
  printf("fd: %d\n",fd);
  printf("ptr: %p\n",buffer);
  printf("size: %d\n",size);
  // write to console
  if(fd==1)
    putbuf((char *)buffer,size);
  return size;
}
