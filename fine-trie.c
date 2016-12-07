/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */
/* A simple, (reverse) trie.  Only for use with 1 thread. */

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "trie.h"
#include <pthread.h>

struct trie_node {
    struct trie_node *next;  /* parent list */
    unsigned int strlen; /* Length of the key */
    int32_t ip4_address; /* 4 octets */
    struct trie_node *children; /* Sorted list of children */
    char key[64]; /* Up to 64 chars */
    pthread_mutex_t fine_mutex;
 };

//linked list to hold the path taken to delete a trie-node
 struct delete_node{
    struct delete_node *next;
    struct trie_node *cur;
 };

static struct trie_node * root = NULL;
static int node_count = 0;
static int max_count = 10;  //Try to stay at no more than 100 nodes
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t coarse_mutex = PTHREAD_MUTEX_INITIALIZER;
extern int separate_delete_thread;

struct trie_node * new_leaf (const char *string, size_t strlen, int32_t ip4_address) {
    struct trie_node *new_node = malloc(sizeof(struct trie_node));
    pthread_mutex_init(&(new_node->fine_mutex), NULL);
    pthread_mutex_lock(&(new_node->fine_mutex));
    node_count++;
    if (!new_node) {

        printf ("WARNING: Node memory allocation failed.  Results may be bogus.\n");
        return NULL;
    }
    assert(strlen < 64);
    assert(strlen > 0);
    new_node->next = NULL;
    new_node->strlen = strlen;
    strncpy(new_node->key, string, strlen);
    new_node->key[strlen] = '\0';
    new_node->ip4_address = ip4_address;
    new_node->children = NULL;

    pthread_mutex_unlock(&(new_node->fine_mutex));
    return new_node;
}

int compare_keys (const char *string1, int len1, const char *string2, int len2, int *pKeylen) {
    int keylen, offset;
    char scratch[64];
    assert (len1 > 0);
    assert (len2 > 0);
    // Take the max of the two keys, treating the front as if it were 
    // filled with spaces, just to ensure a total order on keys.
    if (len1 < len2) {
        keylen = len2;
        offset = keylen - len1;
        memset(scratch, ' ', offset);
        memcpy(&scratch[offset], string1, len1);
        string1 = scratch;
    } else if (len2 < len1) {
        keylen = len1;
        offset = keylen - len2;
        memset(scratch, ' ', offset);
        memcpy(&scratch[offset], string2, len2);
        string2 = scratch;
    } else
        keylen = len1; // == len2
      
    assert (keylen > 0);
    if (pKeylen)
        *pKeylen = keylen;
    return strncmp(string1, string2, keylen);
}

int compare_keys_substring (const char *string1, int len1, const char *string2, int len2, int *pKeylen) {
    int keylen, offset1, offset2;
    keylen = len1 < len2 ? len1 : len2;
    offset1 = len1 - keylen;
    offset2 = len2 - keylen;
    assert (keylen > 0);
    if (pKeylen)
        *pKeylen = keylen;
    return strncmp(&string1[offset1], &string2[offset2], keylen);
}

void init(int numthreads) {
    if (numthreads < 1)
        printf("WARNING: Negative threads?!?!?  You have %d!!!\n", numthreads);

    //lock whole tree
    pthread_mutex_lock(&coarse_mutex);
    root = NULL;
    pthread_mutex_unlock(&coarse_mutex);
}

void shutdown_delete_thread() {
    if(separate_delete_thread)
        pthread_cond_signal(&cond);
    return;
}

/* Recursive helper function.
 * Returns a pointer to the node if found.
 * Stores an optional pointer to the 
 * parent, or what should be the parent if not found.
 * 
 */
struct trie_node * 
_search (struct trie_node *node, struct trie_node *parent, const char *string, size_t strlen) {
     
    int keylen, cmp;

    // First things first, check if we are NULL 
    if (node == NULL)
    {
        //If parent exists unlock it
        if(parent)
            pthread_mutex_unlock(&(parent->fine_mutex));
        return NULL;
    }

    pthread_mutex_lock(&(node->fine_mutex));
    if(parent)
        pthread_mutex_unlock(&(parent->fine_mutex));

    assert(node->strlen < 64);

    // See if this key is a substring of the string passed in
    cmp = compare_keys_substring(node->key, node->strlen, string, strlen, &keylen);
    if (cmp == 0) {
        // Yes, either quit, or recur on the children

        // If this key is longer than our search string, the key isn't here
        if (node->strlen > keylen) {
            pthread_mutex_unlock(&(node->fine_mutex));
            return NULL;
        } else if (strlen > keylen) {
            // Recur on children list
            return _search(node->children, node, string, strlen - keylen);
        } else {
            assert (strlen == keylen);
            pthread_mutex_unlock(&(node->fine_mutex));
            return node;
        }

    } else {
        cmp = compare_keys(node->key, node->strlen, string, strlen, &keylen);
        if (cmp < 0) {
            // No, look right (the node's key is "less" than the search key)
            return _search(node->next, node, string, strlen);
        } else {
            // Quit early
            pthread_mutex_unlock(&(node->fine_mutex));
            return 0;
        }
    }
}


int search  (const char *string, size_t strlen, int32_t *ip4_address) 
{
    //lock entire tree
    // pthread_mutex_lock(&coarse_mutex);
    int ret;

    struct trie_node *found;

    // Skip strings of length 0
    if (strlen == 0)
        ret = 0;

    found = _search(root, NULL, string, strlen);
  
    if (found && ip4_address)
        *ip4_address = found->ip4_address;

     ret = (found != NULL);

    //unlock entire tree
    // pthread_mutex_unlock(&coarse_mutex);
    return ret;
}

//assumes parent node is already locked
/* Recursive helper function */
int _insert (const char *string, size_t strlen, int32_t ip4_address, 
             struct trie_node *node, struct trie_node *parent, struct trie_node *left) 
{

    int cmp, keylen;

    // First things first, check if we are NULL 
    assert (node != NULL);
    assert (node->strlen < 64);

    //lock the current node
    pthread_mutex_lock(&(node->fine_mutex));

    // Take the minimum of the two lengths
    cmp = compare_keys_substring (node->key, node->strlen, string, strlen, &keylen);
    if (cmp == 0) 
    {
        // Yes, either quit, or recur on the children

        // If this key is longer than our search string, we need to insert
        // "above" this node
        if (node->strlen > keylen) 
        {
            struct trie_node *new_node;

            assert(keylen == strlen);
            assert((!parent) || parent->children == node);

            new_node = new_leaf (string, strlen, ip4_address);
            //lock the newly created node
            pthread_mutex_lock(&(new_node->fine_mutex));

            node->strlen -= keylen;
            new_node->children = node;
            new_node->next = node->next;
            node->next = NULL;

            assert ((!parent) || (!left));

            if (parent) 
            {
                parent->children = new_node;
            } 

            else if (left) 
            {
                left->next = new_node;
            } 

            else if ((!parent) || (!left)) 
            {
                root = new_node;
            }

            //on return unlock all locks
            if(parent)
                pthread_mutex_unlock(&parent->fine_mutex);
            pthread_mutex_unlock(&(node->fine_mutex));
            pthread_mutex_unlock(&(new_node->fine_mutex));
            return 1;
        } 

        else if (strlen > keylen) 
        {
            if (node->children == NULL) 
            {
                // Insert leaf here
                struct trie_node *new_node = new_leaf (string, strlen - keylen, ip4_address);

                //lock the newly created node
                pthread_mutex_lock(&(new_node->fine_mutex));
                node->children = new_node;

                //on return unlock all locks
                if(parent)
                    pthread_mutex_unlock(&parent->fine_mutex);
                pthread_mutex_unlock(&(new_node->fine_mutex));
                pthread_mutex_unlock(&(node->fine_mutex));
                return 1;
            } 

            else 
            {
                // Recur on children list, store "parent" (loosely defined)
                //on recurse unlock current parent, keep current node locked because it will become the next parent
                pthread_mutex_unlock(&(parent->fine_mutex));
                return _insert(string, strlen - keylen, ip4_address, node->children, node, NULL);
            }
        } 

        else 
        {
            assert (strlen == keylen);
            if (node->ip4_address == 0) 
            {
                node->ip4_address = ip4_address;

                //on return unlock all locked nodes
                if(parent)
                    pthread_mutex_unlock(&parent->fine_mutex);
                pthread_mutex_unlock(&(node->fine_mutex));
                return 1;
            } 

            else 
            {
                //on return unlock all locked nodes
                if(parent)
                    pthread_mutex_unlock(&parent->fine_mutex);
                pthread_mutex_unlock(&(node->fine_mutex));
                return 0;
            }
        }
    } 

    else 
    {
        /* Is there any common substring? */
        int i, cmp2, keylen2, overlap = 0;
        for (i = 1; i < keylen; i++) 
        {
            cmp2 = compare_keys_substring (&node->key[i], node->strlen - i, &string[i], strlen - i, &keylen2);
            assert (keylen2 > 0);
            if (cmp2 == 0) 
            {
                overlap = 1;
                break;
            }
        }

        if (overlap) 
        {
            // Insert a common parent, recur
            int offset = strlen - keylen2;
            struct trie_node *new_node = new_leaf (&string[offset], keylen2, 0);

            //lock the newly created node
            pthread_mutex_lock(&(new_node->fine_mutex));
            assert ((node->strlen - keylen2) > 0);
            node->strlen -= keylen2;
            new_node->children = node;
            new_node->next = node->next;
            node->next = NULL;
            assert ((!parent) || (!left));

            if (node == root) 
            {
                //lock the root so we can update it
                pthread_mutex_lock(&(root->fine_mutex));
                root = new_node;
                pthread_mutex_unlock(&(root->fine_mutex));
            } 

            else if (parent) 
            {
                assert(parent->children == node);
                parent->children = new_node;
            } 

            else if (left) 
            {
                //lock left so we can update it
                pthread_mutex_lock(&(left->fine_mutex));
                left->next = new_node;
                pthread_mutex_unlock(&(left->fine_mutex));
            } 

            else if ((!parent) && (!left)) 
            {
                //lock the root so we can update it
                pthread_mutex_lock(&(root->fine_mutex));
                root = new_node;
                pthread_mutex_unlock(&(root->fine_mutex));
            }

            //unlock the newly created node and parent node before recurse
            if(parent)
                pthread_mutex_unlock(&parent->fine_mutex);
            pthread_mutex_unlock(&(new_node->fine_mutex));
            return _insert(string, offset, ip4_address,
                           node, new_node, NULL);
        }

        else 
        {
            cmp = compare_keys (node->key, node->strlen, string, strlen, &keylen);
            if (cmp < 0) 
            {
                // No, recur right (the node's key is "less" than  the search key)
                if (node->next)
                {
                    //unlock the parent before recurring 
                    if(parent)
                        pthread_mutex_unlock(&parent->fine_mutex);
                    return _insert(string, strlen, ip4_address, node->next, NULL, node);
                }

                else 
                {
                    // Insert here
                    struct trie_node *new_node = new_leaf (string, strlen, ip4_address);

                    //lock the newly created node
                    pthread_mutex_lock(&(new_node->fine_mutex));
                    node->next = new_node;
                    //unlock all locked nodes before returning
                    if(parent)
                        pthread_mutex_unlock(&parent->fine_mutex);
                    pthread_mutex_unlock(&(new_node->fine_mutex));
                    pthread_mutex_unlock(&(node->fine_mutex));
                    return 1;
                }
            } 

            else 
            {
                // Insert here
                struct trie_node *new_node = new_leaf (string, strlen, ip4_address);
                pthread_mutex_lock(&(new_node->fine_mutex));
                new_node->next = node;

                if (node == root)
                {
                    pthread_mutex_lock(&(root->fine_mutex));
                    root = new_node;
                    pthread_mutex_unlock(&(root->fine_mutex));
                }

                else if (parent && parent->children == node)
                    parent->children = new_node;

                else if (left && left->next == node)
                {
                    pthread_mutex_lock(&(left->fine_mutex));
                    left->next = new_node;
                    pthread_mutex_unlock(&(left->fine_mutex));
                }

                pthread_mutex_unlock(&(new_node->fine_mutex));
            }
        }

        //unlock all locked nodes before returning
        if(parent)
            pthread_mutex_unlock(&parent->fine_mutex); 
        pthread_mutex_unlock(&(node->fine_mutex));
        return 1;
    }
}

int insert (const char *string, size_t strlen, int32_t ip4_address) 
{
    int ret;

    // Skip strings of length 0
    if (strlen == 0)
        ret =  0;

    /* Edge case: root is null */
    if (root == NULL) {
        root = new_leaf (string, strlen, ip4_address);
        ret = 1;
    }

    if(node_count > max_count)
        pthread_cond_signal(&cond); 

    ret = _insert (string, strlen, ip4_address, root, NULL, NULL);

    return ret;
}

/* Recursive helper function.
 * Returns a pointer to the node if found.
 * Stores an optional pointer to the 
 * parent, or what should be the parent if not found.
 * 
 */
struct trie_node * 
_delete (struct trie_node *node, const char *string, 
         size_t strlen, struct delete_node *delete_root) {
    int keylen, cmp;

    // First things first, check if we are NULL 
    if (node == NULL) return NULL;

    if (strlen == 0)
        return NULL;

    assert(node->strlen < 64);

    //lock the current node, it will be unlocked after delete returns
    pthread_mutex_lock(&(node->fine_mutex));

    //add the current node to the linked list
    delete_root->cur = node;
    delete_root->next = malloc(sizeof(struct delete_node));
    delete_root = delete_root->next;

    // See if this key is a substring of the string passed in
    cmp = compare_keys_substring (node->key, node->strlen, string, strlen, &keylen);
    if (cmp == 0) {
        // Yes, either quit, or recur on the children

        // If this key is longer than our search string, the key isn't here
        if (node->strlen > keylen) {
            return NULL;
        } else if (strlen > keylen) {
            struct trie_node *found =  _delete(node->children, string, strlen - keylen, delete_root);
            if (found) {
                /* If the node doesn't have children, delete it.
                 * Otherwise, keep it around to find the kids */
                if (found->children == NULL && found->ip4_address == 0) {
                    assert(node->children == found);
                    node->children = found->next;
                    free(found);
                    node_count--;
                }
    
                /* Delete the root node if we empty the tree */
                if (node == root && node->children == NULL && node->ip4_address == 0) {
                    root = node->next;
                    free(node);
                    node_count--;
                }
    
                return node; /* Recursively delete needless interior nodes */
            } else 
                return NULL;
        } else {
            assert (strlen == keylen);

            /* We found it! Clear the ip4 address and return. */
            if (node->ip4_address) {
                node->ip4_address = 0;

                /* Delete the root node if we empty the tree */
                if (node == root && node->children == NULL && node->ip4_address == 0) {
                    root = node->next;
                    free(node);
                    node_count--;
                    return (struct trie_node *) 0x100100; /* XXX: Don't use this pointer for anything except 
                                                           * comparison with NULL, since the memory is freed.
                                                           * Return a "poison" pointer that will probably 
                                                           * segfault if used.
                                                           */
                }
                return node;
            } else {
                /* Just an interior node with no value */
                return NULL;
            }
        }

    } else {
        cmp = compare_keys (node->key, node->strlen, string, strlen, &keylen);
        if (cmp < 0) {
            // No, look right (the node's key is "less" than  the search key)
            struct trie_node *found = _delete(node->next, string, strlen, delete_root);
            if (found) {
                /* If the node doesn't have children, delete it.
                 * Otherwise, keep it around to find the kids */
                if (found->children == NULL && found->ip4_address == 0) {
                    assert(node->next == found);
                    node->next = found->next;
                    free(found);
                    node_count--;
                }       
    
                return node; /* Recursively delete needless interior nodes */
            }
            return NULL;
        } else {
            // Quit early
            return NULL;
        }
    }
}

int delete(const char *string, size_t strlen) 
{
    int ret;

    //create a new linked list
    struct delete_node *delete_root = malloc(sizeof(struct delete_node));

    // Skip strings of length 0
    if (strlen == 0)
        ret = 0;

    assert(strlen < 64);

    ret = (NULL != _delete(root, string, strlen, delete_root));

    //free every node in the path
    do 
    {
        struct trie_node *cur = delete_root->cur;
        pthread_mutex_unlock(&(cur->fine_mutex));

        //advance to next child in list if it exists. If it doesnt, break the loop
        if(delete_root->next != NULL)
        {
            delete_root = delete_root->next;
        }
        else 
            break;

    } while(1);

    return ret;
}


/* Find one node to remove from the tree. 
 * Use any policy you like to select the node.
 */
int drop_one_node() 
{
    printf("Before Drop: \n");
    print();
    int i, full_len = 0;
    struct trie_node *cur_node = root;
    struct delete_node *delete_root = malloc(sizeof(struct delete_node));
    char full_string[6400] = ""; //max_node->key * max_count

    do 
    {
        char temp[6400];
        pthread_mutex_lock(&(cur_node->fine_mutex));
        strncpy(temp, cur_node->key, cur_node->strlen);

        //insert temp into the end of full_string in reverse
        for(i = 0; i < cur_node->strlen; i++)
            full_string[full_len+i] = temp[cur_node->strlen - i - 1];

        temp[cur_node->strlen] = '\0';
        printf("temp: %s\n", temp);

        full_len += cur_node->strlen;

        //advance to next child in list if it exists. If it doesnt, break the loop
        if(cur_node->children != NULL)
        {
            pthread_mutex_unlock(&(cur_node->fine_mutex));
            cur_node = cur_node->children;
        }
        else 
        {
            pthread_mutex_unlock(&(cur_node->fine_mutex));
            break;
        }

    } while(1);

    //reverse full_string
    for(i = 0; i<full_len/2; i++)
    {
        char temp;
        temp = full_string[i];
        full_string[i] = full_string[full_len-i-1];
        full_string[full_len-i-1] = temp;
    }

    _delete(root, full_string, full_len, delete_root);

    return 0;
}

/* Check the total node count; see if we have exceeded a the max.
 */
void check_max_nodes() 
{
    if(separate_delete_thread)
    {
        while (node_count > max_count)
            pthread_cond_wait (&cond, &coarse_mutex);

        while (node_count > max_count)
            drop_one_node();
    }

    else 
    {
        while (node_count > max_count)
        { 
            drop_one_node();
        }
    }
}


void _print (struct trie_node *node) {
    printf ("Node at %p.  Key %.*s, IP %d.  Next %p, Children %p\n", 
            node, node->strlen, node->key, node->ip4_address, node->next, node->children);
    if (node->children)
        _print(node->children);
    if (node->next)
        _print(node->next);
}

void print() {
    printf ("Root is at %p\n", root);
    /* Do a simple depth-first search */
    if (root)
        _print(root);
}
