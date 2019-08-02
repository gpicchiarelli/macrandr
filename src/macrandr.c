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

#include "macrandr.h"

static void get_version();
static void usage();

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
           printf("Debug.\n");
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


