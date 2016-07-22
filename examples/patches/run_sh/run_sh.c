#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>

int __attribute__((section("hook_run_sh"))) execve_wrap(const char *filename, char *const argv[], char *const envp[]);

char sh[] = "/bin/sh";
int __attribute__((section("hook_run_sh"))) main(void)
{
    /*char sh[20] = {'/', 'b', 'i', 'n', '/', 's', 'h', '\0'};*/
    char *argv[] = {sh, NULL};

    execve_wrap(sh, argv, NULL);
    /*execve_ptr = (execve_t)0x7ffff7ad77b0;*/

    /*(*execve_ptr)(sh, argv, NULL);*/

    return 0;
}

int __attribute__((section("hook_run_sh"))) execve_wrap(const char *filename, char *const argv[], char *const envp[])
{
    asm("mov $0x3b, %eax\n\t"
        "syscall\n\t");
    return 0;
}

