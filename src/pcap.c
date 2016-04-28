/*
 * pcap.c
 *
 *  Created on: Apr 28, 2016
 *      Author: root
 */


#include "pcap.h"
#include <stdio.h>

pcap_dumpfile pcap_dump_fileinit(char * path)
{
	pcap_dumpfile fp = fopen(path, "a+");
	if(!fp)
		return NULL;

	fseek( fp, 0, SEEK_END );
	if(!ftell(fp))
	{
		pcap_hdr_t hdr;
		hdr.magic_number = 0xa1b2c3d4;	/* 0xa1b2c3d4 */
		hdr.version_major = 2;	/* current version is 2.4 */
		hdr.version_minor = 4;	/* current version is 2.4 */
		hdr.thiszone = 0;		/* In practice, time stamps are always in GMT, so thiszone is always 0. */
		hdr.sigfigs = 0;		/* in practice, all tools set it to 0. */
		hdr.snaplen = 0xffff;	/* typically 65535 or even more */
		hdr.network = LINKTYPE_IPV4;	/* IPv4 */

		fwrite(&hdr, sizeof(hdr), 1, fp);
		fflush(fp);
	}

	return fp;
}

void pcap_dump(u_char *pkg_data, pcaprec_hdr_t pcaprec_hdr, pcap_dumpfile dumpfile)
{
	fwrite(&pcaprec_hdr, sizeof(pcaprec_hdr), 1, dumpfile);
	fwrite(pkg_data, pcaprec_hdr.incl_len, 1, dumpfile);
	fflush(dumpfile);
}

void pcap_dump_close(pcap_dumpfile dumpfile)
{
	fclose(dumpfile);
	dumpfile = NULL;
}
