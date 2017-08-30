#include "server.h"

int main (int argc, char *argv[])
{
    int r;

    if (argc == 2 && strncmp(argv[1], "-v", strlen("-v") + 1) == 0) {
        printf("version: %s %s\n", __DATE__, __TIME__);
        exit(0);
    }

    if (argc != 5)
    {
        printf("Not enough args specified\n");
        exit(1);
    }

    r = server_run(get_server(), argv[1], strtoul(argv[2], NULL, 10), strtoul(argv[3], NULL, 10), argv[4]);
    exit(r);
}