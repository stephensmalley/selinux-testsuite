#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <selinux/selinux.h>
#include <selinux/context.h>

int main(int argc, char **argv)
{
	int pid, rc, status;
	char *context_s;
	context_t context;

	if (argc != 3) {
		fprintf(stderr, "usage:  %s newdomain program\n", argv[0]);
		exit(-1);
	}

	rc = getcon(&context_s);
	if (rc < 0) {
		fprintf(stderr, "%s:  unable to get my context\n", argv[0]);
		exit(-1);

	}

	context = context_new(context_s);
	if (!context) {
		fprintf(stderr, "%s:  unable to create context structure\n", argv[0]);
		exit(-1);
	}

	if (context_type_set(context, argv[1])) {
		fprintf(stderr, "%s:  unable to set new type\n", argv[0]);
		exit(-1);
	}

	freecon(context_s);
	context_s = context_str(context);
	if (!context_s) {
		fprintf(stderr, "%s:  unable to obtain new context string\n", argv[0]);
		exit(-1);
	}

	rc = setexeccon(context_s);
	if (rc < 0) {
		fprintf(stderr, "%s:  unable to set exec context to %s\n", argv[0], context_s);
		exit(-1);
	}

	pid = fork();
	if (pid < 0) {
		perror("fork");
		exit(-1);
	} else if (pid == 0) {
		signal(SIGTRAP, SIG_IGN);
		rc =  ptrace(PTRACE_TRACEME, 0, 0, 0);
		if (rc < 0) {
			perror("ptrace: PTRACE_TRACEME");
			exit(-1);
		}
		execv(argv[2], argv + 2);
		perror(argv[2]);
		exit(1);
	}

repeat:
	pid = wait(&status);
	if (pid < 0) {
		perror("wait");
		exit(-1);
	}

	if (WIFEXITED(status)) {
		fprintf(stderr, "Child exited with status %d.\n", WEXITSTATUS(status));
		exit(WEXITSTATUS(status));
	}

	if (WIFSTOPPED(status)) {
		fprintf(stderr, "Child stopped by signal %d.\n", WSTOPSIG(status));
		rc = getpidcon(pid, &context_s);
		if (rc < 0) {
			perror("getpidcon");
			exit(-1);
		}
		fprintf(stderr, "Child has context %s\n", context_s);
		fprintf(stderr, "..Resuming the child.\n");
		rc = ptrace(PTRACE_CONT, pid, 0, 0);
		if (rc < 0) {
			perror("ptrace: PTRACE_CONT");
			exit(-1);
		}
		goto repeat;
	}

	if (WIFSIGNALED(status)) {
		fprintf(stderr, "Child terminated by signal %d.\n", WTERMSIG(status));
		fprintf(stderr,
			"..This is consistent with a ptrace permission denial - check the audit message.\n");
		exit(1);
	}

	fprintf(stderr, "Unexpected exit status 0x%x\n", status);
	exit(-1);
}

