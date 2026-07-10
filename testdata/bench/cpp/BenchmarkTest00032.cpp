#include <cstdlib>

void sync_time() {
    system("ntpdate pool.ntp.org");
}
