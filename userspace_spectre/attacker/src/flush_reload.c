#include "flush_reload.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>

#include "timing.h"

void flush(void * a)
{
    asm volatile(
        "dc civac, %0\n\t"
        :
        : "r" ((uint64_t)a)
        : "memory"
    );
}


char * alloc_flush_reload()
{
    char* buffer =
    mmap(NULL, 
        FLUSH_RELOAD_SIZE * FLUSH_RELOAD_ENTRY_SIZE, 
      	PROT_READ|PROT_WRITE, 
        MAP_SHARED|MAP_ANONYMOUS,
        -1, 
        0);
  if (buffer == MAP_FAILED) {
    perror("mmap");
    exit(EXIT_FAILURE);
  }
  return buffer;
}



void flush_buffer(char * flush_reload)
{
    full_fence();
    for(size_t i = 0; i < FLUSH_RELOAD_SIZE ; i++)
    {
        flush(flush_reload + i * FLUSH_RELOAD_ENTRY_SIZE);
    }
    full_fence();
}


void reload(char * flush_reload, uint64_t * atimes)
{
    for(size_t k = 0; k < FLUSH_RELOAD_SIZE ; k++)
    {
        size_t i = ((k * 167) + 13) & 0xff;
        atimes[i] = time_access(flush_reload + i * FLUSH_RELOAD_ENTRY_SIZE);
    }
}