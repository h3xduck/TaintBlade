#include <stdio.h>
#include <unistd.h>

int main( int argc, char *argv[] )
{
        printf("getsid: %d\n", getsid(getpid()));
        printf("getppid: %d\n", getppid());

        if(getsid(getpid()) != getppid())
        {
                printf("traced!\n");
                _exit(-1);
        }

        printf("OK\n");

        return 0;
}
