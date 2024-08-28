#include "utils.h"

#include <stdlib.h>
#include <sys/mman.h>

void create_pointer_chase(size_t n_intermediate_nodes, void *** intermediate_nodes, void * dest)
{
    intermediate_nodes[0] = mmap(
        NULL,
        128, // one cacheline size
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0
    );
    for(size_t i = 0; i < n_intermediate_nodes-1; i++)
    {
        intermediate_nodes[i+1] = mmap(
            NULL,
            128, // one cacheline size
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANONYMOUS,
            -1,
            0
        );
        intermediate_nodes[i][0] = intermediate_nodes[i+1];
    }
    intermediate_nodes[n_intermediate_nodes-1][0] = dest;
}