/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* A (reverse) trie with fine-grained (per node) locks. 
 *
 * Hint: We recommend using a hand-over-hand protocol to order your locks,
 * while permitting some concurrency on different subtrees.
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "trie.h"

void init(int numthreads) {
    /* Your code here */
}

void shutdown_delete_thread() {
    /* Your code here */
    return;
}

int insert (const char *string, size_t strlen, int32_t ip4_address) {
    /* Your code here */
    return 0;
}

int search  (const char *string, size_t strlen, int32_t *ip4_address) {
    /* Your code here */
    return 0;
}
int delete  (const char *string, size_t strlen) {
    /* Your code here */
    return 0;
}

void check_max_nodes  () {
    /* Your code here */
    return;
}

void print() {
    /* Your code here */
}