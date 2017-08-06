#ifndef PARSING_H
#define PARSING_H

#include "common.h"
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "build.h"

// parse thernet header data
int parse_ethernet(const u_char *frame);
// parse arp header data
int parse_arp(const u_char *packet, struct arp_header *ahdr);
// parse ip header data
int parse_ip(const u_char *packet, struct ip *iphdr);

#endif // PARSING_H

