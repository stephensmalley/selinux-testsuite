#include <unistd.h>
#include <fcntl.h>

#include <sys/mman.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>

int main(int argc, const char **argv)
{
	const char *file;
	void *ptr;
	int rdonly, execmem, flags, prot, fd, ret;

	if (argc != 3 || (strcmp(argv[2], "R_OK") && strcmp(argv[2], "W_OK") &&
			  strcmp(argv[2], "EXECMEM"))) {
		fprintf(stderr, "Usage %s <file> R_OK|W_OK|EXECMEM\n", argv[0]);
		return EINVAL;
	}

	file = argv[1];
	rdonly = strcmp(argv[2], "W_OK") != 0;
	execmem = strcmp(argv[2], "EXECMEM") == 0;
	flags = execmem ? MAP_PRIVATE : MAP_SHARED;
	prot = PROT_READ | (!rdonly ||
			    execmem ? PROT_WRITE : 0) | (execmem ? PROT_EXEC : 0);

	fd = open(file, rdonly ? O_RDONLY : O_RDWR);
	if (fd == -1) {
		perror("open");
		return 2;
	}

	/* try direct mmap */
	ptr = mmap(NULL, 1, prot, flags, fd, 0);
	if (ptr == MAP_FAILED) {
		perror("mmap");
		return 3;
	}
	munmap(ptr, 1);

	/* try mmap with PROT_NONE followed by mprotect with full access */
	ptr = mmap(NULL, 1, PROT_NONE, flags, fd, 0);
	if (ptr == MAP_FAILED) {
		perror("mmap PROT_NONE");
		return 4;
	}

	ret = mprotect(ptr, 1, prot);
	if (ret == -1) {
		perror("mprotect");
		return 5;
	}

	munmap(ptr, 1);
	close(fd);
	return 0;
}
