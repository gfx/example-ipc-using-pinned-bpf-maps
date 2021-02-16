#include <inttypes.h>

provider hello {
  probe incr(int64_t value) /* => int64_t via a pinned BPF map */;
}
