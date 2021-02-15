#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <assert.h>
#include <time.h>

#include <pthread.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <sys/syscall.h>
#include <sys/time.h>

#include <bcc/libbpf.h>

#include "probes.h"

/* Time in nanoseconds */
static uint64_t bench_time()
{
  struct timespec ts;
  int ret = clock_gettime(CLOCK_MONOTONIC, &ts);
  assert(ret == 0);
  return (1000000000ull) * ((uint64_t)ts.tv_sec) + ts.tv_nsec;
}

struct context_t
{
  pthread_t tid;

  int64_t retval;

  uint64_t count;
  uint64_t elapsed1; // to emit USDT events
  uint64_t elapsed2; // to to lookup and delete a BPF object
  uint64_t control; // control group (calling time(2))
};

void *work(void *_ctx)
{
  struct context_t *ctx = _ctx;

  uint64_t tid = pthread_self();

  int fd = bpf_obj_get("/sys/fs/bpf/hello_map");
  if (fd < 0)
  {
    perror("main: bpf_lookup_elem failed");
    pthread_exit(NULL);
  }

  int64_t value = 0;

  uint64_t elapsed1 = 0;
  uint64_t elapsed2 = 0;
  uint64_t control = 0;

  uint64_t count = 10000;
  for (uint64_t i = 0; i < count; i++)
  {
    usleep(1);

    uint64_t t0 = bench_time();

    HELLO_INCR(tid, value);

    uint64_t t1 = bench_time();

    if (bpf_lookup_elem(fd, &tid, &value) != 0)
    {
      perror("main: bpf_lookup_elem failed");
      pthread_exit(NULL);
    }
    bpf_delete_elem(fd, &tid);

    uint64_t t2 = bench_time();

    (void)time(NULL); // for the control group

    uint64_t t3 = bench_time();

    elapsed1 += t1 - t0;
    elapsed2 += t2 - t1;
    control += t3 - t2;
    //printf("main: [%d] bpf_lookup_elem: value = %" PRId64 "\n", i, value);
  }

  ctx->retval = value;

  ctx->elapsed1 = elapsed1;
  ctx->elapsed2 = elapsed2;
  ctx->control = control;
  ctx->count = count;

  return NULL;
}

int main()
{
  printf("main: pid=%d, tid=%" PRIu64 " \n", getpid(), pthread_self());

  // wait for tracer to be attached to this process
  while (!HELLO_INCR_ENABLED())
  {
    usleep(1000);
  }

  // wait for the BPF pinned object file to be created
  int fd;
  do
  {
    fd = bpf_obj_get("/sys/fs/bpf/hello_map");
    if (fd < 0 && errno != ENOENT)
    {
      perror("bpf_obj_get failed");
      exit(1);
    }
    usleep(1000);
  } while (fd < 0);

  if (close(fd) != 0)
  {
    perror("main: close failed");
  }

  usleep(1000);

  struct context_t contexts[32] = {};
  for (size_t i = 0; i < (sizeof(contexts) / sizeof(*contexts)); i++)
  {
    struct context_t *ctx = &contexts[i];
    if (pthread_create(&ctx->tid, NULL, &work, ctx) != 0)
    {
      perror("pthread_create failed");
      exit(1);
    }
  }

  for (size_t i = 0; i < (sizeof(contexts) / sizeof(*contexts)); i++)
  {
    struct context_t *ctx = &contexts[i];
    pthread_join(ctx->tid, NULL);
  }

  for (size_t i = 0; i < (sizeof(contexts) / sizeof(*contexts)); i++)
  {
    struct context_t *ctx = &contexts[i];
    printf("thread[%" PRIu64 "] value=%" PRIu64 " emit=%" PRIu64 "ns, bpf_map_*=%" PRIu64 "ns (time(2)=%" PRIu64 "ns)\n",
           ctx->tid, ctx->retval, ctx->elapsed1 / ctx->count, ctx->elapsed2 / ctx->count, ctx->control / ctx->count);
  }

  printf("main: exiting\n");
  return 0;
}
