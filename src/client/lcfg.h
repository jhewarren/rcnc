// load_cfg.h

#include <stdio.h>
 #include <netinet/in.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
 #include <string.h>
 #include <sys/socket.h>
 #include <sys/types.h>
 #include <unistd.h>

 #define MAXLINE 80
 #define CONFIG "./config"
 #define IP_PROTOCOL 0
 #define IP_ADDRESS "10.100.5.21" // localhost
 #define PORT_NO 15050
 #define NET_BUF_SIZE 32
 #define cipherKey 'S'
 #define sendrecvflag 0
 // config uses key<space>value format, ignoring ^# and ^/n
 // send pointer to base address of kv pairs

int load_cfg();
 int fnsniff();
 int fncrypt();
 int fnegage();
 int fndrmnt();
 int fnclose();
 void kbwait();
 int get_args(int, char**);
 int getrcmd(char*);
 void clearBuf(char* );
 unsigned char swapIN(unsigned char);

struct profiledefn{
	char filt[64];
	char sip[12];
	char dip[12];
	char tip[12];
	char sport[5];
	char dport[5];
	char tport[5];
	char proto[5];
	char pass[64];
	char prog[64];
 };
 struct profiledefn prf;
 char keys[10][6] = {"sip","dip","tip","proto","sport","dport","tport","filt","pass","prog"};


/*  another time perhaps
typedef struct kvp_t{
	char * key;
	char * value;
	char * next;
};
*/
