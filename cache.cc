/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#ifndef NDEBUG
#include <signal.h>
#endif

#include "cache.h"

#ifndef NDEBUG
static constexpr uint64_t redzone_pattern = 0xdeadbeefcafebabe;
int cache_error = 0;
#endif

static constexpr int initial_pool_size = 64;

cache_t* cache_create(const char *name, size_t bufsize, size_t align,
                      cache_constructor_t* constructor,
                      cache_destructor_t* destructor) {
    cache_t* ret = static_cast<cache_t*>(calloc(1, sizeof(cache_t)));
    char* nm = strdup(name);
    void** ptr = static_cast<void**>(calloc(initial_pool_size, sizeof(void*)));
    if (ret == nullptr || nm == nullptr || ptr == nullptr ||
        pthread_mutex_init(&ret->mutex, nullptr) == -1) {
        free(ret);
        free(nm);
        free(ptr);
        return nullptr;
    }

    ret->name = nm;
    ret->ptr = ptr;
    ret->freetotal = initial_pool_size;
    ret->constructor = constructor;
    ret->destructor = destructor;

#ifndef NDEBUG
    ret->bufsize = bufsize + 2 * sizeof(redzone_pattern);
#else
    ret->bufsize = bufsize;
#endif

    return ret;
}

static inline void* get_object(void *ptr) {
#ifndef NDEBUG
    uint64_t *pre = static_cast<uint64_t*>(ptr);
    return static_cast<void*>(pre + 1);
#else
    return static_cast<void*>(ptr);
#endif
}

void cache_destroy(cache_t *cache) {
    while (cache->freecurr > 0) {
        void *ptr = cache->ptr[--cache->freecurr];
        if (cache->destructor) {
            cache->destructor(get_object(ptr), NULL);
        }
        free(ptr);
    }
    free(cache->name);
    free(cache->ptr);
    pthread_mutex_destroy(&cache->mutex);
    free(cache);
}

void* cache_alloc(cache_t *cache) {
    void *ret;
    pthread_mutex_lock(&cache->mutex);
    ret = do_cache_alloc(cache);
    pthread_mutex_unlock(&cache->mutex);
    return ret;
}

void* do_cache_alloc(cache_t *cache) {
    void *ret;
    void *object;
    if (cache->freecurr > 0) {
        ret = cache->ptr[--cache->freecurr];
        object = get_object(ret);
    } else {
        object = ret = malloc(cache->bufsize);
        if (ret != nullptr) {
            object = get_object(ret);

            if (cache->constructor != nullptr &&
                cache->constructor(object, nullptr, 0) != 0) {
                free(ret);
                object = nullptr;
            }
        }
    }

#ifndef NDEBUG
    if (object != nullptr) {
        /* add a simple form of buffer-check */
        uint64_t *pre = static_cast<uint64_t*>(ret);
        *pre = redzone_pattern;
        ret = pre+1;
        memcpy(((char*)ret) + cache->bufsize - (2 * sizeof(redzone_pattern)),
               &redzone_pattern, sizeof(redzone_pattern));
    }
#endif

    return object;
}

void cache_free(cache_t *cache, void *ptr) {
    pthread_mutex_lock(&cache->mutex);
    do_cache_free(cache, ptr);
    pthread_mutex_unlock(&cache->mutex);
}

void do_cache_free(cache_t *cache, void *ptr) {
#ifndef NDEBUG
    /* validate redzone... */
    if (memcmp(((char*)ptr) + cache->bufsize - (2 * sizeof(redzone_pattern)),
               &redzone_pattern, sizeof(redzone_pattern)) != 0) {
        raise(SIGABRT);
        cache_error = 1;
        return;
    }
    uint64_t *pre = static_cast<uint64_t*>(ptr);
    --pre;
    if (*pre != redzone_pattern) {
        raise(SIGABRT);
        cache_error = -1;
        return;
    }
    ptr = pre;
#endif
    if (cache->freecurr < cache->freetotal) {
        cache->ptr[cache->freecurr++] = ptr;
    } else {
        /* try to enlarge free connections array */
        const size_t newtotal = cache->freetotal * 2;
        void **new_free = static_cast<void**>(realloc(cache->ptr, sizeof(char *) * newtotal));
        if (new_free) {
            cache->freetotal = newtotal;
            cache->ptr = new_free;
            cache->ptr[cache->freecurr++] = ptr;
        } else {
            if (cache->destructor) {
                cache->destructor(ptr, NULL);
            }
            free(ptr);

        }
    }
}
