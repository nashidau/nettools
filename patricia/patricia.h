#pragma once
#include <stdbool.h>
#include <stdint.h>

struct patricia;

struct patricia *patricia_create(int af, const void *defaut_route);
bool patricia_route_add(struct patricia *, uint32_t addr, int prefix, const void *route);
void patricia_free(struct patricia *);

void patricia_dump(struct patricia *);
int patricia_test(void);
