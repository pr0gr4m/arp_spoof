#include "parsing.h"

/*
 * Prototype : int parse_ethernet(const u_char *frame)
 * Last modified 2017/07/30
 * Written by pr0gr4m
 *
 * return ETHERTYPE
 */
int parse_ethernet(const u_char *frame)
{
    struct ether_header *ethdr;

    ethdr = (struct ether_header *)frame;

    return ntohs(ethdr->ether_type);
}

/*
 * Prototype : int parse_arp(const u_char *packet, struct arp_header *ahdr)
 * Last Modified 2017/07/30
 * Written by pr0gr4m
 *
 * store arp header by packet
 */
int parse_arp(const u_char *packet, struct arp_header *ahdr)
{
    memcpy(ahdr, packet, ARP_HEADER_LEN);

    return TRUE;
}

/*
 * Prototype : u_int8_t parse_ip(const u_char *packet, struct ip *iphdr)
 * Last Modified 2017/08/06
 * Written by pr0gr4m
 *
 * store ip header by packet
 * return protocol
 */
u_int8_t parse_ip(const u_char *packet, struct ip *iphdr)
{
    struct ip *tmp = packet;
    memcpy(iphdr, packet, tmp->ip_hl * 4);
    return iphdr->ip_p;
}
