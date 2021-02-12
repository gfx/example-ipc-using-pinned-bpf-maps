#include <cstdlib>
#include <cstdio>
#include <cassert>
#include <cinttypes>

extern "C"
{
#include <unistd.h>
#include <poll.h>
}

#include <bcc/BPF.h>

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif

using namespace std;

const char *bpf_program = R"(
BPF_PERF_OUTPUT(events);

BPF_HASH(hash, uint64_t, int64_t, 1024);

struct event_t {
  uint64_t key;
  int64_t value;
};

int handle_incr(struct pt_regs *ctx)
{
  struct event_t ev = {};

  bpf_usdt_readarg(1, ctx, &ev.key);
  bpf_usdt_readarg(2, ctx, &ev.value);

  ev.value++;
  hash.insert(&ev.key, &ev.value);

  events.perf_submit(ctx, &ev, sizeof(ev));
  return 0;
}
)";

struct event_t
{
  uint64_t key;
  int64_t value;
};

static void event_cb(void *, void *data, int len)
{
  assert(sizeof(event_t) <= (uint64_t)len);
  auto ev = static_cast<const event_t *>(data);
  printf("tracer: key=%" PRIu64 " value+1=%" PRId64 "\n", ev->key, ev->value);
}

static int sys_pidfd_open(int pid, unsigned int flags)
{
  return syscall(__NR_pidfd_open, pid, flags);
}

static bool proc_is_alive(int fd)
{
  struct pollfd pollfd = {
      .fd = fd,
      .events = POLLIN,
  };

  int ret;
  while ((ret = poll(&pollfd, 1, 0)) < 0 && errno == EINTR)
    ;
  return ret == 0;
}

int main(int argc, char **argv)
{
  if (argc <= 1)
  {
    fprintf(stderr, "usage: %s pid\n", argv[0]);
    exit(1);
  }
  pid_t pid = atoi(argv[1]);

  unlink("/sys/fs/bpf/hello_map"); // make sure it's removed before attaching USDTs

  vector<ebpf::USDT> usdts = {
      ebpf::USDT(pid, "hello", "incr", "handle_incr"),
  };

  ebpf::BPF bpf;
  {
    auto ret = bpf.init(bpf_program, {}, usdts);
    if (!ret.ok())
    {
      fprintf(stderr, "tracer: error: init: %s\n", ret.msg().c_str());
      exit(1);
    }
  }

  printf("tracer: initialized\n");

  int pid_fd = sys_pidfd_open(pid, 0);
  if (pid_fd < 0)
  {
    perror("pidfd_open failed");
    exit(1);
  }

  {
    const auto ret = bpf.attach_usdt_all();
    if (!ret.ok())
    {
      fprintf(stderr, "tracer: error: attach_usdt_all: %s\n", ret.msg().c_str());
      exit(1);
    }
  }
  printf("tracer: attached\n");

  {
    auto ret = bpf.open_perf_buffer("events", event_cb);
    if (ret.code() != 0)
    {
      fprintf(stderr, "tracer: error: open_perf_buffer: %s\n", ret.msg().c_str());
      return EXIT_FAILURE;
    }
  }

  if (bpf_obj_pin(bpf.get_table("hash").get_fd(), "/sys/fs/bpf/hello_map") != 0)
  {
    perror("tracer: bpf_obj_pin failed");
  }

  auto perf_buffer = bpf.get_perf_buffer("events");
  assert(perf_buffer != nullptr);

  printf("tracer: polling the perf buffer\n");
  while (true)
  {
    perf_buffer->poll(100);

    if (!proc_is_alive(pid_fd)) {
      break;
    }
  }
  printf("tracer: detected the attaching process has exited\n");

  unlink("/sys/fs/bpf/hello_map"); // make sure it's removed before attaching USDTs
  close(pid_fd);

  return 0;
}
