#pragma once

#include "interception/interception.h"
#include <pthread.h>
#include <stdio.h>

namespace __interception {

struct pthread_create_interceptor_t {
  void (*callback)(pthread_t *, const pthread_attr_t *, void *(*&start_routine)(void *), void *&arg);
  pthread_create_interceptor_t *next;
};

extern pthread_create_interceptor_t *pthread_create_interceptors;

void intercept_pthread_create(pthread_create_interceptor_t *interceptor);

}
