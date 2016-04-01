# StrongTCP

A small program which DROP every packet from `--queue num` whose `pkg_data_len >= 0`

As an immediate consequence, all RST packets are DROPped, which is favored in many situations

## To achieve that, you will first need

````c
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>            /* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>
````
I really wondered whether these libraries exist on OS X.

## Then,

````c
if (pkg_data_len >= 0)
{
  blah(&manythings);

  //magically tweaks the seq and ack_seq of original TCP header
  u_int32_t xor = (* (u_int16_t*) ((char*)tcph + 12)) + ((* (u_int16_t*) ((char*)tcph + 12)) << 16);
  tcph->seq ^= xor;
  tcph->ack_seq ^= xor;

  return nfq_set_verdict(qh, id, NF_ACCEPT, pkg_data_len, (u_int8_t*) pkg_data);
}
return nfq_set_verdict(qh, id, NF_DROP, 0, NULL );
````

## Build
### for Linux
````shell
cd src
make
````
### for Openwrt
````shell
make menuconfig
make
````
### for Android
````shell
ndk-build
````


## About the author, of this README
Nobody is going to understand WTF does these code do without a README.md, so I wrote one
