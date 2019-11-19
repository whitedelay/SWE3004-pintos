#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include "lib/user/syscall.h"
#include "userprog/syscall.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/shutdown.h"


struct file_elem{
  struct list_elem elem;
  struct file * f;
  int fd;
};

static struct lock filesys_lock;

static void syscall_handler (struct intr_frame *);
void check_valid_vaddr(uint32_t * vaddr);
struct file_elem * find_file_by_fd(int fd);

void
syscall_init (void) 
{ 
  lock_init(filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf ("system call!\n");
  uint32_t *esp = (uint32_t *)(f->esp); // system call #
  
  /* vefity esp */
  check_valid_vaddr(esp);
  
  int syscall_num = *esp;
  
  //printf("syscall: %d\n",syscall_num);
  switch(syscall_num){
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      check_valid_vaddr(esp+1);:ㅂ
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
      check_valid_vaddr(*(esp+2));
      f->eax = read(*(int *)(esp+1), (char *)*(esp+2), *(unsigned *)(esp+3));
      break;
    case SYS_WRITE:
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
   
  //f->eax = result;
}

// check whether accessing kernel space
void
check_valid_vaddr(uint32_t *vaddr)
{
  if(!is_user_vaddr(vaddr))
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
  printf("%s: exit(%d)\n",thread_name(),status);
  thread_exit();
}

pid_t exec(const char *cmd_line)
{
  pid_t pid = process_execute(cmd_line);
  
}

int wait(pid_t pid)
{

}

bool
create(const char *file, unsigned initial_size)
{
  if(file==NULL) exit(-1);
  return filesys_create(file,initial_size);
}

bool
remove(const char *file)
{
  if(file==NULL) exit(-1);
  return filesys_remove(file);
}

int
open(const char *file)
{
  if(file==NULL) return -1;

  struct file * f = filesys_open(file);
  if(f){
    struct file_elem * fe = (struct file_elem *)malloc(sizeof(struct file_elem));    
    fe->fd = thread_current()->next_fd++;
    fe->f = f;
    list_push_back(&thread_current()->file_list,&fe->elem);

    return fe->fd;
  }
  return -1;
}

int
filesize(int fd)
{
  struct file_elem * elem = find_file_by_fd(fd);
  if(elem!=NULL){
    return inode_length(file_get_inode(elem->f));
  } 
  return -1;
}

int read(int fd, void *buffer, unsigned size)
{
  if(fd==STDIN_FILENO)
  {
    printf("read from keyboard\n");
  }
  
  struct file_elem * elem = find_file_by_fd(fd);
  if(elem!=NULL){
    return file_read(elem->f,buffer,size);
  }
   return -1;
}

int write(int fd, const void *buffer, unsigned size)
{
  if(fd== STDOUT_FILENO){
    putbuf((char *)buffer,size);
    return size;
  }
  
  struct file_elem * elem = find_file_by_fd(fd);
  if(elem!=NULL){
    return file_write(elem->f,buffer,size);
  } 
  return -1;
}

void seek(int fd, unsigned position)
{
  struct file_elem *elem = find_file_by_fd(fd);
  if(elem!=NULL)
    file_seek(elem->f, position);
}

unsigned tell(int fd)
{
  struct file_elem * elem = find_file_by_fd(fd);
  if(elem!=NULL)
    return file_tell(elem->f);
  return -1;
}

void close(int fd)
{
  struct file_elem *elem = find_file_by_fd(fd);
  if(elem!=NULL){
    file_close(elem->f);
    list_remove(&elem->elem);
    free(elem);  
  }
}



