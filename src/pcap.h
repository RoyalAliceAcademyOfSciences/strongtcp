/*
 * pcap.h
 *
 *  Created on: Apr 28, 2016
 *      Author: root
 */

#ifndef PCAP_H_
#define PCAP_H_

#include <sys/types.h>
#include <stdio.h>

#define LINKTYPE_IPV4	228

typedef struct pcap_hdr_s {
        u_int32_t magic_number;   /* magic number */
        u_int16_t version_major;  /* major version number */
        u_int16_t version_minor;  /* minor version number */
        int32_t  thiszone;       /* GMT to local correction */
        u_int32_t sigfigs;        /* accuracy of timestamps */
        u_int32_t snaplen;        /* max length of captured packets, in octets */
        u_int32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
        u_int32_t ts_sec;         /* timestamp seconds */
        u_int32_t ts_usec;        /* timestamp microseconds */
        u_int32_t incl_len;       /* number of octets of packet saved in file */
        u_int32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

typedef FILE* pcap_dumpfile;

pcap_dumpfile pcap_dump_fileinit(char * path);
void pcap_dump(u_char *pkg_data, pcaprec_hdr_t pcaprec_hdr, pcap_dumpfile dumpfile);
void pcap_dump_close(pcap_dumpfile dumpfile);

#endif /* PCAP_H_ */
