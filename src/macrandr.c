/*
 *
Copyright (c) 2019, Giacomo Picchiarelli <gpicchiarelli@gmail.com>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <err.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <arpa/inet.h>
#include <netinet/ip_ipsp.h>
#include <netinet/if_ether.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#include <net/pfvar.h>
#include <net/if_pfsync.h>
#include <net/if_pflow.h>
#include <net/if_pppoe.h>
#include <net/if_trunk.h>
#include <net/trunklacp.h>
#include <net/if_sppp.h>
#include <net/ppp_defs.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <errno.h>


#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/sockio.h>

#include <netinet/ip_carp.h>
#include <util.h>
#include <ifaddrs.h>

#define MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))
#define MAXIMUM(a, b) (((a) > (b)) ? (a) : (b))

#include "macrandr.h"

static void get_version();
static void usage();
static void printif(char *ifname, int ifaliases);

static int aflag = 1;
struct in6_ifreq ifr6;
struct ifreq ifr;
struct	in6_ifreq	in6_ridreq;
struct	ifreq		ifr, ridreq;
struct	in_aliasreq	in_addreq;
struct	in6_aliasreq	in6_addreq;

int	flags, xflags, setaddr, setipdst, doalias;
u_long	metric, mtu;
int	rdomainid;
int	llprio;
int	clearaddr, s;
int	newaddr = 0;
int	af = AF_INET;
int	explicit_prefix = 0;
int	Lflag = 1;
int	show_join = 0;

char	name[IFNAMSIZ];

void	in_status(int);
void	in_getaddr(const char *, int);
void	in_getprefix(const char *, int);
void	in6_fillscopeid(struct sockaddr_in6 *sin6);
void	in6_alias(struct in6_ifreq *);
void	in6_status(int);
void	in6_getaddr(const char *, int);
void	in6_getprefix(const char *, int);
void	ieee80211_status(void);
int	printgroup(char *, int);
void	status(int, struct sockaddr_dl *, int);
int getinfo(struct ifreq*, int);
void	in6_alias(struct in6_ifreq *);
void	in6_status(int);
void setiflladdr(void);

/* Known address families */
const struct afswtch {
	char *af_name;
	short af_af;
	void (*af_status)(int);
	void (*af_getaddr)(const char *, int);
	void (*af_getprefix)(const char *, int);
	u_long af_difaddr;
	u_long af_aifaddr;
	caddr_t af_ridreq;
	caddr_t af_addreq;
} afs[] = {
#define C(x) ((caddr_t) &x)
	{ "inet", AF_INET, in_status, in_getaddr, in_getprefix,
	    SIOCDIFADDR, SIOCAIFADDR, C(ridreq), C(in_addreq) },
	{ "inet6", AF_INET6, in6_status, in6_getaddr, in6_getprefix,
	    SIOCDIFADDR_IN6, SIOCAIFADDR_IN6, C(in6_ridreq), C(in6_addreq) },
	{ 0,	0,	    0,		0 }
};

const struct afswtch *afp;

static const struct {
	const char	*name;
	u_int		cipher;
} ciphers[] = {
	{ "usegroup",	IEEE80211_WPA_CIPHER_USEGROUP },
	{ "wep40",	IEEE80211_WPA_CIPHER_WEP40 },
	{ "tkip",	IEEE80211_WPA_CIPHER_TKIP },
	{ "ccmp",	IEEE80211_WPA_CIPHER_CCMP },
	{ "wep104",	IEEE80211_WPA_CIPHER_WEP104 }
};

int
main (int argc, char *argv[])
{
  int opt;

  if(argc == 1){
   		if (unveil("/", "") == -1)
			err(1, "unveil");
		if (unveil(NULL, NULL) == -1)
      err(1, "unveil");
    usage();
  }

  while ((opt = getopt(argc, argv, "dv")) != -1)
  {
         switch (opt) {
         case 'v':
            get_version();
           break;
         case 'd':
           printif(NULL,0);
           break;
         default:
           usage();
         }
  }
  return 0;
}

static void
usage()
{
	fprintf(stdout,"usage: macrandr [-dv] [-d Debug mode.] [-v Get version.]\n"
	);
	exit(255);
}

static void
get_version()
{
  fprintf(stdout,"A tiny MAC randomizer address for OpenBSD. \n");
  fprintf(stdout,"Version: %s. \n",MACRANDR_H_VERSION);
  fprintf(stdout,"Giacomo Picchiarelli <gpicchiarelli@gmail.com>. \n");
  exit(255);
}

/*ARGSUSED*/
void
setiflladdr()
{
	struct ether_addr *eap, eabuf;

	arc4random_buf(&eabuf, sizeof eabuf);
	/* Non-multicast and claim it is a hardware address */
	eabuf.ether_addr_octet[0] &= 0xfc;
	eap = &eabuf;
	strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	ifr.ifr_addr.sa_len = ETHER_ADDR_LEN;
	ifr.ifr_addr.sa_family = AF_LINK;
	bcopy(eap, ifr.ifr_addr.sa_data, ETHER_ADDR_LEN);
	if (ioctl(s, SIOCSIFLLADDR, (caddr_t)&ifr) == -1)
		warn("SIOCSIFLLADDR");
}

#define MASK 2
#define ADDR 1
#define SIN6(x) ((struct sockaddr_in6 *) &(x))
struct sockaddr_in6 *sin6tab[] = {
SIN6(in6_ridreq.ifr_addr), SIN6(in6_addreq.ifra_addr),
SIN6(in6_addreq.ifra_prefixmask), SIN6(in6_addreq.ifra_dstaddr)};

void
getsock(int naf)
{
	static int oaf = -1;

	if (oaf == naf)
		return;
	if (oaf != -1)
		close(s);
	s = socket(naf, SOCK_DGRAM, 0);
	if (s == -1)
		oaf = -1;
	else
		oaf = naf;
}






