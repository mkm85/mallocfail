#define _GNU_SOURCE

#include "mallocfail.h"
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <stdbool.h>
#include <errno.h>


void *(*libc_malloc)(size_t) = NULL;
void *(*libc_calloc)(size_t, size_t) = NULL;
void *(*libc_realloc)(void *, size_t) = NULL;

static char tmpbuf[4096];
static size_t tmppos = 0;
static pthread_mutex_t mutex;

static __thread int no_hook = 0;

static void __attribute__((constructor)) init(void)
{
    libc_calloc = (void *(*) (size_t, size_t)) dlsym (RTLD_NEXT, "calloc");
    libc_malloc = (void *(*) (size_t)) dlsym (RTLD_NEXT, "malloc");
    libc_realloc = (void *(*) (void *, size_t)) dlsym (RTLD_NEXT, "realloc");
    no_hook = 1;
    pthread_mutex_init(&mutex, NULL);
    no_hook = 0;
}

void* simple_malloc(size_t size) {
    void* retptr;
    if(tmppos + size >= sizeof(tmpbuf)) exit(1);

    retptr = tmpbuf + tmppos;
    tmppos += size;
    return retptr;
}

bool use_libc_malloc()
{
    bool result;
    {
        pthread_mutex_lock(&mutex);
        result = !should_malloc_fail();
        pthread_mutex_unlock(&mutex);
    }
    return result;
}

void *malloc(size_t size)
{
    void *retptr;

    if (libc_malloc == NULL) {
        return simple_malloc(size);
    }

    if (no_hook) {
        return libc_malloc(size);
    }

    no_hook = 1;
    if (use_libc_malloc()){
        retptr = libc_malloc(size);
    } else {
        retptr = NULL;
        errno = ENOMEM;
    }
    no_hook = 0;
    return retptr;
}


void *calloc(size_t nmemb, size_t size)
{
    void *retptr;

    if (libc_calloc == NULL) {
        size_t allocSize = nmemb * size;
        retptr = simple_malloc(allocSize);
        for (size_t i = 0; i < allocSize; i++) {
            (((uint8_t*)retptr)[i]) = 0;
        }
        return retptr;
    }

    if (no_hook) {
        return libc_calloc(nmemb, size);
    }

    no_hook = 1;
    if (use_libc_malloc()) {
        retptr = libc_calloc(nmemb, size);
    } else {
        retptr = NULL;
        errno = ENOMEM;
    }
    no_hook = 0;
    return retptr;
}

void *realloc(void *ptr, size_t size)
{
    void* retptr;
    if (no_hook) {
        return libc_realloc(ptr, size);
    }

    no_hook = 1;
    if (use_libc_malloc()){
        retptr = libc_realloc(ptr, size);
    } else {
        retptr = NULL;
        errno = ENOMEM;
    }
    no_hook = 0;
    return retptr;
}
