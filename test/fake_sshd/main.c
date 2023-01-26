#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

int main () {
    char buf [4096] = {0x00};
    int fd = open("/root/.ssh/authorized_keys", O_RDONLY);
    if (fd < 0) {
        printf("ERROR OPEN FILE");
    }
    memset(buf, 0 , sizeof(buf));
    if (read(fd, &buf, 4096) > 0) {
        printf("%s", buf);
    }
    close(fd);
    return 0;
}