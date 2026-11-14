#include <stdio.h>
#include <string.h>

__thread int tls_counter = 17;

int main(int argc, char **argv)
{
    /*
     * This sample is a tad more robust than test.c
     *
     * It checks three things at once:
     *   1. argc survived the packed file handoff
     *   2. argv strings survived the packed file handoff
     *   3. direct entry TLS still behaves like normal process TLS
     */
    if (argc != 3) {
        return 101;
    }

    if (strcmp(argv[1], "alpha") != 0 || strcmp(argv[2], "beta") != 0) {
        return 102;
    }

    tls_counter += argc; /* exercise writable TLS, not just a read only lookup */
    printf("argv/tls ok %d\n", tls_counter);
    return 7;
}
