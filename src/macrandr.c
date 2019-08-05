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
#include <signal.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_media.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/sockio.h>
#include <assert.h>

#include <netinet/ip_carp.h>
#include <util.h>
#include <ifaddrs.h>

#include "macrandr.h"

static void get_version(void);
static void usage(void);
static void roundifaces(void);
static void setiflladdr(void);
static void get_version (void);
static void getsock (int naf);
static int init_macarnd(void);
static void signal_handler(int sig);

struct ifreq ifr;

int	setaddr;
int	s;
int	af = AF_INET;


static int debug = 0;
static char	name[IFNAMSIZ];

int
main (int argc, char *argv[])
{
  int opt;

  if(argc == 1){
    usage();
  }

	if (pledge("error stdio unix dpath cpath rpath \
              drm inet route tty unveil", NULL) == -1)
    err(1, "pledge");


  if (unveil("/home", "") == -1)
			err(1, "unveil");

  assert(TIME_ROUND > TIME_GUARD); //avoid saturation

  if (geteuid())
	  errx(1, "need root privileges");

  getsock(af);

  while ((opt = getopt(argc, argv, "dvcD")) != -1)
  {
         switch (opt) {
         case 'c':
            roundifaces();
           break;
         case 'v':
            get_version();
           break;
         case 'D':
            if(daemon(1,1))
             errx(1, "failed to daemon.");
            init_macarnd();
           break;
         case 'd':
           fprintf(stdout,"Debug mode.\n");
           debug = 1;
           roundifaces();
           break;
         default:
           usage();
         }
  }
  return 0;
}

static int done = 0;
int init_macarnd(){
  signal(SIGSTOP,signal_handler);
  signal(SIGTERM,signal_handler);
  signal(SIGKILL,signal_handler);

  while(!done)
    {
      if(debug)
        fprintf(stdout,"[macrandr][daemon] Change addresses. \n");
        sleep (TIME_ROUND);
        roundifaces();
    }
  return 0;
}

void signal_handler(sig) /* signal handler function */
	int sig;
	{
		switch(sig){
			case SIGHUP:
				/* rehash the server */
				break;
			case SIGTERM:
      case SIGSTOP:
				/* finalize the server */
				done = 1;
				break;
    case SIGKILL:
        done = 1;
        exit(255);
      break;
		}
	}

static void
usage()
{
	fprintf(stdout,"usage: macrandr [-dvc] [-d Debug mode.] [-v Get version.]\n"
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

void
roundifaces()
{
    struct ifaddrs *ifap,*ifa;
  	struct if_data *ifdata;

    if (getifaddrs(&ifap) != 0)
		  err(1, "getifaddrs");

	  for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
      strcpy(name,ifa->ifa_name);

      if(strcmp(name,"lo0") == 0 || strcmp(name,"enc0") == 0 ||
         strcmp(name,"pflog0") == 0  )
        continue;

      setiflladdr();
    }
}

void
setiflladdr()
{
	struct ether_addr *eap, eabuf;

  arc4random_buf(&eabuf, sizeof (eabuf));
	/* Non-multicast and claim it is a hardware address */
	eabuf.ether_addr_octet[0] &= 0xfc;
	eap = &eabuf;
	strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));

  if(debug)
    fprintf(stdout,"Chosen iface: %s.\n" ,ifr.ifr_name);

	ifr.ifr_addr.sa_len = ETHER_ADDR_LEN;
	ifr.ifr_addr.sa_family = AF_LINK;
	bcopy(eap, ifr.ifr_addr.sa_data, ETHER_ADDR_LEN);

  if(debug)
      fprintf(stdout,"Changed address for iface: %s.\n" ,ifr.ifr_name);

  s = socket(af, SOCK_DGRAM, 0);

  if(debug)
      fprintf(stdout,"Opened socket for iface: %s.\n" ,ifr.ifr_name);

	if (ioctl(s, SIOCSIFLLADDR, (caddr_t)&ifr) == -1){
      if(debug)
          fprintf(stdout,"ioctl done for iface: %s.\n" ,ifr.ifr_name);
    err(1,"ioctl ERROR");
  }
  close(s);

  if(debug)
    fprintf(stdout,"Closed socket for iface: %s.\n" ,ifr.ifr_name);
}
