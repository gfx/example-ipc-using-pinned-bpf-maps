#include <cstdlib>
#include <cstdio>
#include <cassert>
#include <cinttypes>

extern "C"
{
#include <unistd.h>
#include <poll.h>
#include <sys/syscall.h>
}

#include <bcc/BPF.h>

using namespace std;

const char *bpf_program = R"(
#include <linux/sched.h>

BPF_PERF_OUTPUT(events);

// size=400 seems enough for 32 threads in main.c
BPF_F_TABLE("lru_hash", pid_t, int64_t, hash, 1024, 0);

struct event_t {
  pid_t tid;
  int64_t value;
};

int handle_incr(struct pt_regs *ctx)
{
  struct event_t ev = {};
  bpf_usdt_readarg(1, ctx, &ev.tid);
  bpf_usdt_readarg(2, ctx, &ev.value);

  ev.value++;

  int64_t ret = hash.insert(&ev.tid, &ev.value);
  if (ret != 0) {
    bpf_trace_printk("failed to insert with errno=%ld\n", -ret);
  }

  events.perf_submit(ctx, &ev, sizeof(ev));
  return 0;
}
)";

struct event_t
{
  pid_t tid;
  int64_t value;
};

static void event_cb(void *, void *data, int len)
{
  assert(sizeof(event_t) <= (uint64_t)len);
  auto ev = static_cast<const event_t *>(data);

  if (false) {
    printf("tracer: [tid=%" PRIu64 "] value+1=%" PRId64 "\n",
          (uint64_t)ev->tid, ev->value);
  }
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
    auto ret = bpf.open_perf_buffer("events", event_cb, nullptr, nullptr, 256);
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

    if (!proc_is_alive(pid_fd))
    {
      break;
    }
  }
  printf("tracer: detected the attaching process has exited\n");

  //unlink("/sys/fs/bpf/hello_map"); // make sure it's removed before attaching USDTs
  close(pid_fd);
  bpf.detach_usdt_all();

  return 0;
}
