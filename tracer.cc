#include <cstdlib>
#include <cstdio>
#include <cassert>
#include <cinttypes>

extern "C"
{
#include <unistd.h>
}

#include <bcc/BPF.h>

using namespace std;

const char *bpf_program = R"(
BPF_PERF_OUTPUT(events);

BPF_ARRAY(ary, int64_t, 1024);

struct event_t {
  int64_t x;
  int64_t y;
};

int handle_add(struct pt_regs *ctx)
{
  struct event_t ev = {};
  bpf_usdt_readarg(1, ctx, &ev.x);
  bpf_usdt_readarg(2, ctx, &ev.y);

  int key = 0;
  int64_t val = ev.x + ev.y;
  ary.update(&key, &val);

  events.perf_submit(ctx, &ev, sizeof(ev));

  return 0;
}

)";

struct event_t {
  int64_t x;
  int64_t y;
};
#include <iostream>
static void event_cb(void *, void *data, int len)
{
  assert(sizeof(event_t) <= (uint64_t)len);
  auto ev = static_cast<const event_t*>(data);
  printf("tracer: x=%" PRId64 " y=%" PRId64 "\n", ev->x, ev->y);
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
      ebpf::USDT(pid, "hello", "add", "handle_add"),
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

  auto ary = bpf.get_array_table<int64_t>("ary");
  if (bpf_obj_pin(ary.get_fd(), "/sys/fs/bpf/hello_map") != 0)
  {
    perror("tracer: bpf_obj_pin failed");
  }

  auto perf_buffer = bpf.get_perf_buffer("events");
  assert(perf_buffer != nullptr);

  printf("tracer: polling the perf buffer\n");
  while (true)
  {
    perf_buffer->poll(1000);
  }

  return 0;
}
