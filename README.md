# StrongTCP
A small program which DROP every packet from `--queue num` whose `pkg_data_len >= 0`

As an immediate consequence, all RST packets are DROPped, which is

## To achieve that, you will first need
`
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <linux/netfilter.h>            /* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>
`

## Then,

`
pkg_data_len = nfq_get_payload(nfa, &pkg_data);
  if (pkg_data_len >= 0)
  {
    blah(&manythings);
    tweak(&pkg_data,MAGICALLY);

    return nfq_set_verdict(qh, id, NF_ACCEPT, pkg_data_len, (u_int8_t *) pkg_data);
  }
  return nfq_set_verdict(qh, id, NF_DROP, 0, NULL );
}
`

## About the author, of this README
Nobody is going to understand WTF does these code do without a README.md, so I wrote one
