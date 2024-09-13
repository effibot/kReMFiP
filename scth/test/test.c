//
// Created by effi on 12/09/24.
//

#include <unistd.h>
#include <stdio.h>
int __NR__test_syscall = 134;

int test_syscall(int arg) {
	return syscall(__NR__test_syscall, arg);
}

int main() {
	int ret;
	ret = test_syscall(42);
	printf("test_syscall returned with code %d\n", ret);
	if (ret == 0) {
		printf("test_syscall succeeded\n");
	} else {
		printf("test_syscall failed\n");
	}
	return 0;
}