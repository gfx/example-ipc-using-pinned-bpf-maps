#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <assert.h>

#include <unistd.h>
#include <sys/sysinfo.h>
#include <sys/syscall.h>
#include <pthread.h>

#include <bcc/libbpf.h>

#include "probes.h"

int main()
{
  printf("main: pid=%d, tid=%" PRIu64 " \n", getpid(), pthread_self());

  // wait for tracer to be attached to this process
  while (!HELLO_INCR_ENABLED())
  {
    usleep(1000);
  }

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

  int64_t value = 0;
  for (int i = 0; i < 10; i++)
  {
    usleep(1000);
    uint64_t tid = pthread_self();

    HELLO_INCR(tid, value);

    if (bpf_lookup_elem(fd, &tid, &value) != 0)
    {
      perror("main: bpf_lookup_elem failed");
      exit(1);
    }
    bpf_delete_elem(fd, &tid);

    printf("main: [%d] bpf_lookup_elem: value = %" PRId64 "\n", i, value);
  }

  if (close(fd) != 0)
  {
    perror("main: close failed");
  }

  printf("main: exiting\n");
  return 0;
}
