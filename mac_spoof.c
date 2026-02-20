/* ================================================================
 * MAC Address Spoofer for Linux
 * Reads original MAC → Generates random local MAC → Applies it
 * Must be run as root (sudo)
 * ================================================================ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <net/if_arp.h>

static void print_mac(const char *label, const unsigned char *mac)
{
    printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n",
           label,
           mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
}

static int generate_random_mac(unsigned char *mac)
{
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (!urandom)
        return -1;
    if (fread(mac, 1, ETH_ALEN, urandom) != ETH_ALEN) {
        fclose(urandom);
        return -1;
    }
    fclose(urandom);

    /* Set locally administered bit (bit 1 of first octet) */
    mac[0] |= 0x02;
    /* Clear multicast bit (bit 0 of first octet) to keep it unicast */
    mac[0] &= ~0x01;
    return 0;
}

int main(int argc, char *argv[])
{
    const char *iface;
    int sock;
    struct ifreq ifr;
    unsigned char orig_mac[ETH_ALEN];
    unsigned char new_mac[ETH_ALEN];

    if (getuid() != 0) {
        fprintf(stderr, "Error: this program must be run as root (sudo).\n");
        return EXIT_FAILURE;
    }

    iface = (argc > 1) ? argv[1] : "eth0";

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    /* Read original MAC address */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFHWADDR)");
        close(sock);
        return EXIT_FAILURE;
    }

    memcpy(orig_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    print_mac("Original MAC", orig_mac);

    /* Generate a random locally administered unicast MAC */
    if (generate_random_mac(new_mac) < 0) {
        fprintf(stderr, "Error: failed to read from /dev/urandom.\n");
        close(sock);
        return EXIT_FAILURE;
    }
    print_mac("New MAC     ", new_mac);

    /* Apply the new MAC address */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    memcpy(ifr.ifr_hwaddr.sa_data, new_mac, ETH_ALEN);

    if (ioctl(sock, SIOCSIFHWADDR, &ifr) < 0) {
        perror("ioctl(SIOCSIFHWADDR)");
        close(sock);
        return EXIT_FAILURE;
    }

    printf("MAC address on '%s' successfully changed.\n", iface);

    close(sock);
    return EXIT_SUCCESS;
}
