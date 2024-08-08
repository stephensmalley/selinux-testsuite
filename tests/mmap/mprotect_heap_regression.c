/* Contributed by Marc Reisner */
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <signal.h>

int main(void)
{
	uintptr_t raw_addr = 0x25085000;

	int length = 512 * 1024 * 1024;
	void *pointer = mmap((void *)raw_addr, length, PROT_NONE,
			     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (!pointer) {
		perror("mmap");
		return 1;
	}

	if (mprotect(pointer, length, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
		perror("mprotect");
		return 1;
	}

	return 0;
}
