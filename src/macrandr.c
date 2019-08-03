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
#include <sys/socket.h>
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

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/sockio.h>

#include <netinet/ip_carp.h>
#include <util.h>
#include <ifaddrs.h>

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

int	explicit_prefix = 0;

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


void
printif(char *ifname, int ifaliases)
{
	struct ifaddrs *ifap, *ifa;
	struct if_data *ifdata;
	const char *namep;
	char *oname = NULL;
	struct ifreq *ifrp;
	int count = 0, noinet = 1;
	size_t nlen = 0;

	if (aflag)
		ifname = NULL;
	if (ifname) {
		if ((oname = strdup(ifname)) == NULL)
			err(1, "strdup");
		nlen = strlen(oname);
		/* is it a group? */
		if (nlen && !isdigit((unsigned char)oname[nlen - 1]))
			if (printgroup(oname, ifaliases) != -1) {
				free(oname);
				return;
			}
	}

	if (getifaddrs(&ifap) != 0)
		err(1, "getifaddrs");

	namep = NULL;
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (oname) {
			if (nlen && isdigit((unsigned char)oname[nlen - 1])) {
				/* must have exact match */
				if (strcmp(oname, ifa->ifa_name) != 0)
					continue;
			} else {
				/* partial match OK if it ends w/ digit */
				if (strncmp(oname, ifa->ifa_name, nlen) != 0 ||
				    !isdigit((unsigned char)ifa->ifa_name[nlen]))
					continue;
			}
		}
		/* quickhack: sizeof(ifr) < sizeof(ifr6) */
		if (ifa->ifa_addr->sa_family == AF_INET6) {
			memset(&ifr6, 0, sizeof(ifr6));
			memcpy(&ifr6.ifr_addr, ifa->ifa_addr,
			    MINIMUM(sizeof(ifr6.ifr_addr), ifa->ifa_addr->sa_len));
			ifrp = (struct ifreq *)&ifr6;
		} else {
			memset(&ifr, 0, sizeof(ifr));
			memcpy(&ifr.ifr_addr, ifa->ifa_addr,
			    MINIMUM(sizeof(ifr.ifr_addr), ifa->ifa_addr->sa_len));
			ifrp = &ifr;
		}
		strlcpy(name, ifa->ifa_name, sizeof(name));
		strlcpy(ifrp->ifr_name, ifa->ifa_name, sizeof(ifrp->ifr_name));

		if (ifa->ifa_addr->sa_family == AF_LINK) {
			namep = ifa->ifa_name;
			if (getinfo(ifrp, 0) < 0)
				continue;
			ifdata = ifa->ifa_data;
			status(1, (struct sockaddr_dl *)ifa->ifa_addr,
			    ifdata->ifi_link_state);
			count++;
			noinet = 1;
			continue;
		}

		if (!namep || !strcmp(namep, ifa->ifa_name)) {
			const struct afswtch *p;

			if (ifa->ifa_addr->sa_family == AF_INET &&
			    ifaliases == 0 && noinet == 0)
				continue;
			if ((p = afp) != NULL) {
				if (ifa->ifa_addr->sa_family == p->af_af)
					p->af_status(1);
			} else {
				for (p = afs; p->af_name; p++) {
					if (ifa->ifa_addr->sa_family ==
					    p->af_af)
						p->af_status(0);
				}
			}
			count++;
			if (ifa->ifa_addr->sa_family == AF_INET)
				noinet = 0;
			continue;
		}
	}
	freeifaddrs(ifap);
	free(oname);
	if (count == 0) {
		fprintf(stderr, "%s: no such interface\n", name);
		exit(1);
	}
}

#define MASK 2
#define ADDR 1
#define SIN6(x) ((struct sockaddr_in6 *) &(x))
struct sockaddr_in6 *sin6tab[] = {
SIN6(in6_ridreq.ifr_addr), SIN6(in6_addreq.ifra_addr),
SIN6(in6_addreq.ifra_prefixmask), SIN6(in6_addreq.ifra_dstaddr)};

void
in6_getaddr(const char *s, int which)
{
	struct sockaddr_in6 *sin6 = sin6tab[which];
	struct addrinfo hints, *res;
	char buf[HOST_NAME_MAX+1 + sizeof("/128")], *pfxlen;
	int error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM;	/*dummy*/

	if (which == ADDR && strchr(s, '/') != NULL) {
		if (strlcpy(buf, s, sizeof(buf)) >= sizeof(buf))
			errx(1, "%s: bad value", s);
		pfxlen = strchr(buf, '/');
		*pfxlen++ = '\0';
		s = buf;
		in6_getprefix(pfxlen, MASK);
		explicit_prefix = 1;
	}

	error = getaddrinfo(s, "0", &hints, &res);
	if (error)
		errx(1, "%s: %s", s, gai_strerror(error));
	memcpy(sin6, res->ai_addr, res->ai_addrlen);
#ifdef __KAME__
	if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) &&
	    *(u_int16_t *)&sin6->sin6_addr.s6_addr[2] == 0 &&
	    sin6->sin6_scope_id) {
		*(u_int16_t *)&sin6->sin6_addr.s6_addr[2] =
		    htons(sin6->sin6_scope_id & 0xffff);
		sin6->sin6_scope_id = 0;
	}
#endif /* __KAME__ */
	freeaddrinfo(res);
}

void
in6_getprefix(const char *plen, int which)
{
	struct sockaddr_in6 *sin6 = sin6tab[which];
	const char *errmsg = NULL;
	u_char *cp;
	int len;

	len = strtonum(plen, 0, 128, &errmsg);
	if (errmsg)
		errx(1, "prefix %s: %s", plen, errmsg);

	sin6->sin6_len = sizeof(*sin6);
	if (which != MASK)
		sin6->sin6_family = AF_INET6;
	if ((len == 0) || (len == 128)) {
		memset(&sin6->sin6_addr, 0xff, sizeof(struct in6_addr));
		return;
	}
	memset((void *)&sin6->sin6_addr, 0x00, sizeof(sin6->sin6_addr));
	for (cp = (u_char *)&sin6->sin6_addr; len > 7; len -= 8)
		*cp++ = 0xff;
	if (len)
		*cp = 0xff << (8 - len);
}



