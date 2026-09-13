#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define GLOBAL_BUF_SIZE 0x100
#define STACK_BUF_SIZE  0x100

#define RESP "[*] "
#define PROMPT "heap> "

_Alignas(16) static unsigned char global_buf[GLOBAL_BUF_SIZE];

static uint64_t parse_hex(const char *s)
{
	return (uint64_t) strtoull(s, NULL, 16);
}

static void cmd_malloc(uint64_t size)
{
	void *p = malloc(size);
	printf(RESP "%p\n", p);
}

static void cmd_calloc(uint64_t nmemb, uint64_t size)
{
	void *p = calloc(nmemb, size);
	printf(RESP "%p\n", p);
}

static void cmd_free(uint64_t addr)
{
	free((void *)(uintptr_t) addr);
	printf(RESP "freed %p\n", (void *)(uintptr_t) addr);
}

static size_t read_exact(void *buf, size_t len)
{
	size_t got = 0;
	while (got < len) {
		size_t n = fread((char *) buf + got, 1, len - got, stdin);
		if (n == 0)
			break;
		got += n;
	}
	return got;
}

static void cmd_write(uint64_t addr, uint64_t len)
{
	void *dst = (void *)(uintptr_t) addr;
	size_t got = read_exact(dst, len);
	printf(RESP "wrote %#zx\n", got);
}

static void cmd_read(uint64_t addr, uint64_t len)
{
	fputs(RESP, stdout);
	fwrite((const void *)(uintptr_t) addr, 1, len, stdout);
}

static void usage(void)
{
	printf(RESP
		"commands (addresses/sizes hex):\n"
		"  malloc <size>\n"
		"  calloc <nmemb> <size>\n"
		"  free   <addr>\n"
		"  write  <addr> <len>   then send <len> raw bytes on stdin\n"
		"  read   <addr> <len>   emits <len> raw bytes on stdout\n");
}

int main(void)
{
	_Alignas(16) unsigned char stack_buf[STACK_BUF_SIZE];

	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);

	printf(RESP "pid %d\n", getpid());
	printf(RESP "stack %p\n", (void *) stack_buf);
	printf(RESP "global %p\n", (void *) global_buf);

	char line[0x400];
	char cmd[0x40], a1[0x40], a2[0x40], a3[0x40];

	while (1) {
		fputs(PROMPT, stdout);
		if (!fgets(line, sizeof(line), stdin))
			break;
		int n = sscanf(line, "%63s %63s %63s %63s", cmd, a1, a2, a3);
		if (n < 1)
			continue;

		if (strcmp(cmd, "malloc") == 0 && n >= 2)
			cmd_malloc(parse_hex(a1));
		else if (strcmp(cmd, "calloc") == 0 && n >= 3)
			cmd_calloc(parse_hex(a1), parse_hex(a2));
		else if (strcmp(cmd, "free") == 0 && n >= 2)
			cmd_free(parse_hex(a1));
		else if (strcmp(cmd, "write") == 0 && n >= 3)
			cmd_write(parse_hex(a1), parse_hex(a2));
		else if (strcmp(cmd, "read") == 0 && n >= 3)
			cmd_read(parse_hex(a1), parse_hex(a2));
		else
			usage();
	}
	return 0;
}

