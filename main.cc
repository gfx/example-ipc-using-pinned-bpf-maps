#include <cstdio>
#include <cstdlib>
#include <cinttypes>
#include <cerrno>
#include <cassert>

#include <bcc/libbpf.h>

extern "C"
{
#include <unistd.h>
#include <sys/sysinfo.h>
}

#include "probes.h"

using namespace std;

int main()
{
  printf("main: pid=%d\n", getpid());

  // wait for tracer to be attached to this process
  while (!HELLO_ADD_ENABLED())
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

  for (auto i = 0; i < 3; i++)
  {
    int64_t x = 10 + i;
    int64_t y = 20 + i;
    usleep(1000);
    printf("main: before HELLO_ADD(%" PRId64 ", %" PRId64 ")\n", x, y);
    HELLO_ADD((int64_t)x, (int64_t)y);
    printf("main: after HELLO_ADD(%" PRId64 ", %" PRId64 ")\n", x, y);

    int *keys = (int*)calloc(8, sizeof(int));
    int64_t *values = (int64_t*)calloc(8, sizeof(int64_t));

    if (bpf_lookup_elem(fd, keys, values) != 0)
    {
      perror("main: bpf_lookup_elem failed");
      //exit(1);
    }
    for (int i = 0; i < 8; i++)
    {
      printf("main: bpf_lookup_elem[%d]: %" PRId64 " + %" PRId64 " = %" PRId64 "\n", i, x, y, values[i]);
    }

    free(keys);
    free(values);
  }

  if (close(fd) != 0)
  {
    perror("main: close failed");
  }

  printf("main: exiting\n");
  return 0;
}
