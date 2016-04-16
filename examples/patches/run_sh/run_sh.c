#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int __attribute__((section("my_hook"))) main(void)
{
    char *sh = "/bin/sh";
    char *argv[] = {sh, NULL};

    execve(sh, argv, NULL);

    return 0;
}
