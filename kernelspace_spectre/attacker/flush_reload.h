#pragma once

#include <stdint.h>

#define FLUSH_RELOAD_SIZE 256
#define FLUSH_RELOAD_ENTRY_SIZE 128

void flush(void * a);
char * alloc_flush_reload();
void flush_buffer(char * flush_reload);
void reload(char * flush_reload, uint64_t * atimes);