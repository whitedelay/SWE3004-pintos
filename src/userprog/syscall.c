#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include "lib/user/syscall.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/off_t.h"


struct semaphore filesys_lock;

static void syscall_handler (struct intr_frame *);
void check_valid_vaddr(void * vaddr);
struct file_elem * find_file_by_fd(int fd);

void
syscall_init (void) 
{ 
  sema_init(&filesys_lock,1);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf ("system call!\n");
  uint32_t *esp = f->esp; // system call #
  
  /* vefity esp */
  check_valid_vaddr(esp);
  
  int syscall_num = *esp;
  
  //printf("syscall: %d\n",syscall_num);
  switch(syscall_num){
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      check_valid_vaddr(esp+1);
      exit(*(esp+1));
      break;
    case SYS_EXEC:
      f->eax = exec((char *)*(esp+1));
      break;
    case SYS_WAIT:
      f->eax = wait(*(pid_t *)(esp+1));
      break;
    case SYS_CREATE:
      f->eax = create((char *)*(esp+1),*(unsigned *)(esp+2));
      break; 
    case SYS_REMOVE:
      f->eax = remove((char *)*(esp+1));
      break;
    case SYS_OPEN:
      f->eax = open((char *)*(esp+1));
      break;
    case SYS_FILESIZE:
      f->eax = filesize(*(int *)(esp+1));
      break;
    case SYS_READ:
      check_valid_vaddr((char *)*(esp+2));
      f->eax = read(*(int *)(esp+1), (char *)*(esp+2), *(unsigned *)(esp+3));
      break;
    case SYS_WRITE:
      check_valid_vaddr((char *)*(esp+2));
      f->eax = write(*(int *)(esp+1), (char *)*(esp+2), *(unsigned *)(esp+3));
      break;
    case SYS_SEEK:
      seek(*(int *)(esp+1),*(unsigned *)(esp+3));
      break;
    case SYS_TELL:
      f->eax = tell(*(int *)(esp+1));
      break;
    case SYS_CLOSE:
      close(*(int *)(esp+1));
      break;
    
    default:
      break;
  }
  
}

// check whether accessing kernel space
void
check_valid_vaddr(void *vaddr)
{
  if(!is_user_vaddr(vaddr) || vaddr < (void *)0x08048000)
    exit(-1);
  
}

struct file_elem * find_file_by_fd(int fd)
{
  struct list * file_list = &thread_current()->file_list;
    for(struct list_elem * e = list_begin(file_list); e!=list_end(file_list);e=list_next(e))
    {
      struct file_elem * elem = list_entry(e,struct file_elem,elem);
      if(elem->fd == fd){
        return elem;
    }
  }
  return NULL;
}
 
void halt(void)
{
  
  shutdown_power_off();
}  

void
exit(int status)
{
  struct thread * cur = thread_current();
  printf("%s: exit(%d)\n",thread_name(),status);
  //sema_down(&cur->parent->exit_lock);
  cur->exit_status = status;
  thread_exit();
}

pid_t exec(const char *cmd_line)
{ 
  //printf("syscall - execute\n");
  pid_t pid = process_execute(cmd_line); 
  return pid; 
}

int wait(pid_t pid)
{
  return process_wait(pid);
}

bool
create(const char *file, unsigned initial_size)
{
  
  if(file==NULL) exit(-1);
  sema_down(&filesys_lock);
  bool res = filesys_create(file,initial_size);
  sema_up(&filesys_lock);
  return res;
}

bool
remove(const char *file)
{ 
  if(file==NULL) exit(-1);
  sema_down(&filesys_lock);
  bool res = filesys_remove(file);
  sema_up(&filesys_lock);
  return res;
}

int
open(const char *file)
{
  
  if(file==NULL) return -1;
  sema_down(&filesys_lock);
  //printf("open : %s\n",file);
  struct file * f = filesys_open(file);
  if(f){   
    /* add file to file_list in this thread */
    struct file_elem * fe = (struct file_elem *)malloc(sizeof(struct file_elem));    
    fe->fd = thread_current()->next_fd++;
    fe->f = f;
    list_push_back(&thread_current()->file_list,&fe->elem);
    
    //file_deny_write(f);
    sema_up(&filesys_lock);
    return fe->fd;
  }
  sema_up(&filesys_lock);
  return -1;
}

int
filesize(int fd)
{
  sema_down(&filesys_lock);
  struct file_elem * elem = find_file_by_fd(fd);
  if(elem!=NULL){
    int res = file_length(elem->f);
    sema_up(&filesys_lock);
    return res;
  }
  sema_up(&filesys_lock);
  return -1;
}

int read(int fd, void *buffer, unsigned size)
{
  sema_down(&filesys_lock);
  if(fd==STDIN_FILENO)
  {
    unsigned cnt = size;
    while(cnt--)
      *((char *)buffer++) = input_getc();
    sema_up(&filesys_lock);
    return size;
  }
   
  struct file_elem * elem = find_file_by_fd(fd);
  //check_valid_vaddr(buffer);
  if(elem!=NULL){ 
    //file_deny_write(elem->f);
    size = file_read(elem->f,buffer,size);
    //file_allow_write(elem->f);
    sema_up(&filesys_lock);
    return size;
  }
  sema_up(&filesys_lock);
  return -1;
}

int write(int fd, const void *buffer, unsigned size)
{
  sema_down(&filesys_lock);
  if(fd== STDOUT_FILENO){
    putbuf((char *)buffer,size);
    sema_up(&filesys_lock);
    return size;
  }
  struct file_elem * elem = find_file_by_fd(fd);
  
  //check_valid_vaddr(buffer);
  if(elem!=NULL){
    int res = file_write(elem->f,buffer,size); 
    sema_up(&filesys_lock);
    return res;
  }
  sema_up(&filesys_lock);
  return 0;
}

void seek(int fd, unsigned position)
{
  struct file_elem *elem = find_file_by_fd(fd);
  if(elem!=NULL){
    sema_down(&filesys_lock);
    file_seek(elem->f, position);
    sema_up(&filesys_lock);
  }
}

unsigned tell(int fd)
{
  struct file_elem * elem = find_file_by_fd(fd);
  if(elem!=NULL){
    sema_down(&filesys_lock);
    unsigned res = file_tell(elem->f);
    sema_up(&filesys_lock);
    return res;
  }
  return -1;
}

void close(int fd)
{
  struct file_elem *elem = find_file_by_fd(fd);
  if(elem!=NULL){
    sema_down(&filesys_lock);
    file_close(elem->f);
    sema_up(&filesys_lock);
    list_remove(&elem->elem);
    free(elem);
  }
}



