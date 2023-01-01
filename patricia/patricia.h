#pragma once
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

struct patricia;

struct patricia *patricia_create(int af, const void *defaut_route);
bool patricia_route_add_ip4(struct patricia *, in_addr_t addr, int prefix, const void *route);
bool patricia_route_add_ip6(struct patricia *, in6_addr_t addr, int prefix, const void *route);
void patricia_free(struct patricia *);

void patricia_dump(struct patricia *);
int patricia_test(void);
