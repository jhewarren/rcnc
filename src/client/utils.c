#include "lcfg.h"
char keys[10][6] = {"sip","dip","tip","proto","sport","dport","tport","filt","pass","prog"};

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
