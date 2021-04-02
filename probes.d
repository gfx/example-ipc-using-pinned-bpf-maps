#include <inttypes.h>

provider hello {
  /**
   * returns int64_t via a pinned BPF map */
   */
   probe incr(pid_t tid, int64_t value);
}
