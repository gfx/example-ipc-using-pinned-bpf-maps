#include <inttypes.h>

provider hello {
  probe incr(uint64_t tid, int64_t value) /* => int64_t */;
}
