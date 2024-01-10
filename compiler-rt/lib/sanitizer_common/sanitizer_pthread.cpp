#include "sanitizer_pthread.h"

namespace __interception {

pthread_create_interceptor_t *pthread_create_interceptors = nullptr;

void intercept_pthread_create(pthread_create_interceptor_t *interceptor) {
  // fprintf(stderr, "%s@%p: registering %p\n", __FUNCTION__, (void *) intercept_pthread_create, interceptor);
  interceptor->next = pthread_create_interceptors;
  pthread_create_interceptors = interceptor;
}

INTERCEPTOR(int, pthread_create, pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg) {
  // fprintf(stderr, "sanitizer pthread interceptor running\n");
  // NHM-FIXME: Need lock?!?!?
  static bool interceptors_inited = false;
  if (!interceptors_inited) {
    interceptors_inited = true;
    INTERCEPT_FUNCTION(pthread_create);
  }

  for (pthread_create_interceptor_t *interceptor = pthread_create_interceptors; interceptor; interceptor = interceptor->next) {
    interceptor->callback(thread, attr, start_routine, arg);
  }

  volatile void *x = (void *) intercept_pthread_create;

  return REAL(pthread_create)(thread, attr, start_routine, arg);
}


}
