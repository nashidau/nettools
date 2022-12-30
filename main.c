#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>

#include "patricia/patricia.h"

int
main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
	// Run test suite first
	printf("Tests failed: %d\n", patricia_test());	

	return 0;
}
