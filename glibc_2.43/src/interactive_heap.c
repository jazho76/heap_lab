#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SLOTS 10

static void *allocations[SLOTS];

void win(void)
{
    static const char msg[] = "[win] control flow hijacked\n";
    write(1, msg, sizeof msg - 1);
}

static int read_index(void)
{
    int index;

    printf("Index: ");
    if (scanf("%d", &index) != 1)
        return -1;

    if (index < 0 || index >= SLOTS) {
        printf("[!] index out of range (0-%d)\n", SLOTS - 1);
        return -1;
    }

    return index;
}

static void do_malloc(void)
{
    size_t size;

    int index = read_index();
    if (index < 0)
        return;

    printf("Size: ");
    if (scanf("%zu", &size) != 1)
        return;

    allocations[index] = malloc(size);
    printf("[*] allocations[%d] = malloc(%zu)\n", index, size);
    printf("[*] allocations[%d] = %p\n", index, allocations[index]);
}

static void do_free(void)
{
    int index = read_index();
    if (index < 0)
        return;

    free(allocations[index]);
    printf("[*] free(allocations[%d])\n", index);
}

static void do_puts(void)
{
    int index = read_index();
    if (index < 0)
        return;

    printf("[*] puts(allocations[%d])\n", index);
    printf("Data: ");
    puts(allocations[index]);
}

static void do_scanf(void)
{
    char fmt[16];
    unsigned int size;

    int index = read_index();
    if (index < 0)
        return;

    printf("Size: ");
    if (scanf("%u", &size) != 1)
        return;

    snprintf(fmt, sizeof fmt, "%%%us", size);
    printf("[*] scanf(\"%%%us\", allocations[%d])\n", size, index);
    scanf(fmt, allocations[index]);
}

int main(void)
{
    char cmd[16];

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    for (;;) {
        printf("\n[*] Function (malloc/free/puts/scanf/quit): ");
        if (scanf("%15s", cmd) != 1)
            break;

        if (strcmp(cmd, "malloc") == 0)
            do_malloc();
        else if (strcmp(cmd, "free") == 0)
            do_free();
        else if (strcmp(cmd, "puts") == 0)
            do_puts();
        else if (strcmp(cmd, "scanf") == 0)
            do_scanf();
        else if (strcmp(cmd, "quit") == 0)
            break;
        else
            printf("[!] unknown command\n");
    }

    return 0;
}
