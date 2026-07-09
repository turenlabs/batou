#include <stdlib.h>

void sync_time(void) {
    system("ntpdate pool.ntp.org");
}
