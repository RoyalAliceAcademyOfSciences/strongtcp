#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <linux/netfilter.h>            /* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>

#ifdef DEBUG
#define LOG(x, ...) printf(x, ##__VA_ARGS__)
#else
#define LOG(x, ...) if (verbose) { printf(x, ##__VA_ARGS__); }
#endif
#define ERROR(x, ...) fprintf(stderr, x, ##__VA_ARGS__)

int queue_num = 0;
int verbose = 0;
int enable_checksum = 0;

void print_help() {
	printf("Usage:\n"
		"\tstrongtcp [--verbose | -v] [--checksum] [--queue num]\n");
}

void parse_arguments(int argc, char **argv)
{
	int i = 1;
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
			print_help();
			exit(0);
		} else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
			verbose = 1;
		} else if (strcmp(argv[i], "--checksum") == 0) {
			enable_checksum = 1;
		} else if (strcmp(argv[i], "--queue") == 0) {
			if (i + 1 < argc) {
				queue_num = atoi(argv[i + 1]);
				i++;
			} else {
				ERROR("Invalid arguments.\n");
				print_help();
				exit(0);
			}
		}
	}
}

static u_int16_t ip_cksum(u_int16_t *addr, int len)
{
	u_int16_t cksum;
	u_int32_t sum = 0;

	while (len > 1)
	{
		sum += *addr++;
		len -= 2;
	}
	if (len == 1)
	sum += *(u_int8_t*) addr;
	sum = (sum >> 16) + (sum & 0xffff);  //把高位的进位，加到低八位，其实是32位加法
	sum += (sum >> 16);  //add carry
	cksum = ~sum;   //取反
	return (cksum);
}

static u_int16_t tcp_cksum(char *pkg_data)
{
	struct iphdr *iph = (struct iphdr *) pkg_data;
	struct tcphdr *tcph = (struct tcphdr *) (pkg_data + (iph->ihl * 4));
	char tcpBuf[1500];

	struct pseudoTcpHeader {
    u_int32_t ip_src;
    u_int32_t ip_dst;
    u_int8_t zero;//always zero
    u_int8_t protocol;// = 6;//for tcp
    u_int16_t tcp_len;
	} psdh;

	psdh.ip_src = iph->saddr;
	psdh.ip_dst = iph->daddr;
	psdh.zero = 0;
	psdh.protocol = 6;
	psdh.tcp_len = htons(ntohs(iph->tot_len) - sizeof(struct ip));

//	printf("ip_len:%d tcplen:%d\n", ntohs(iph->tot_len), ntohs(psdh.tcp_len));
	memcpy(tcpBuf, &psdh, sizeof(struct pseudoTcpHeader));
	memcpy(tcpBuf + sizeof(struct pseudoTcpHeader), tcph, ntohs(psdh.tcp_len));

	return ip_cksum((u_int16_t *)tcpBuf,	sizeof(struct pseudoTcpHeader) + ntohs(psdh.tcp_len));
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
		struct nfq_data *nfa, void *data)
{

	struct nfqnl_msg_packet_hdr *ph;
	uint32_t id = 0;
	uint32_t pkg_data_len;

	unsigned char *pkg_data;

	LOG("entering callback\n");

	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph)
	{
		id = ntohl(ph->packet_id);
		LOG("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
	}

	pkg_data_len = nfq_get_payload(nfa, &pkg_data);
	if (pkg_data_len >= 0)
	{
		LOG("payload_len=%d\n", pkg_data_len);

		struct iphdr *iph = (struct iphdr *) pkg_data;
		struct tcphdr *tcph = (struct tcphdr *) (pkg_data + (iph->ihl * 4));
		u_int32_t xor = (*(u_int16_t *) ((char *)tcph + 12)) + ((*(u_int16_t *) ((char *)tcph + 12)) << 16);

		LOG("FLG XOR:0x%08x\n", ntohl(xor));
		LOG("BEF SEQ:0x%08x ACK:0x%08x SUM:0x%04x\n", ntohl(tcph->seq), ntohl(tcph->ack_seq), ntohs(tcph->check));

		tcph->seq ^= xor;
		tcph->ack_seq ^= xor;
		if (enable_checksum) {
			tcph->check = tcp_cksum(pkg_data);
		}

		LOG("AFT SEQ:0x%08x ACK:0x%08x SUM:0x%04x\n", ntohl(tcph->seq), ntohl(tcph->ack_seq), ntohs(tcph->check));

		return nfq_set_verdict(qh, id, NF_ACCEPT, pkg_data_len, (u_int8_t *) pkg_data);
	}

	return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	parse_arguments(argc, argv);

	LOG("opening library handle\n");
	h = nfq_open();
	if (!h)
	{
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	LOG("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0)
	{
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	LOG("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0)
	{
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	LOG("binding this socket to queue '%d'\n", queue_num);
	qh = nfq_create_queue(h, queue_num, &cb, NULL );
	if (!qh)
	{
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	LOG("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
	{
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0)
	{
		LOG("pkt received\n");
		nfq_handle_packet(h, buf, rv);
	}

	LOG("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	LOG("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	LOG("closing library handle\n");
	nfq_close(h);

	return 0;
}
