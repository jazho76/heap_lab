#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>


void win(void)
{
    static const char msg[] = "[win] control flow hijacked\n";
    write(1, msg, sizeof msg - 1);
}

int main(void)
{
    return 0;
}

