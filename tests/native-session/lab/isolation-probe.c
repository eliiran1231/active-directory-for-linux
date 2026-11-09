#include <stdio.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <string.h>
#include <sys/stat.h>
int main(void) {
 struct ifaddrs *all=0; int seen=0;
 if(geteuid()!=65534 || getifaddrs(&all)) return 1;
 for(struct ifaddrs *p=all;p;p=p->ifa_next) { if(strcmp(p->ifa_name,"lo")) return 2; seen=1; }
 freeifaddrs(all); if(!seen) return 3;
 FILE *f=fopen("/run/adfl/probe","w"); if(!f)return 4; fclose(f); unlink("/run/adfl/probe");
 f=fopen("/outside-probe","w"); if(f) return 5;
 puts("PASS: unprivileged uid; only loopback interface; temporary writable state; root not writable to test uid"); return 0;
}
