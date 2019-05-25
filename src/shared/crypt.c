/* dcstego 0,1 - Stegonography app
 * Written by John Warren (jhewarren@gmail.com)
 *
 *
 * This program ...
 *      functions...
 *
 * compile: cc -o covert_tcp covert_tcp.c
 *
 */
#include <arpa/inet.h>
#include <linux/ip.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define OPTIONS "?hs:d:"
#define BUFFSIZE    512

// Main functions
void usage(char*);

// util functions
int Crypt(char * , char * );
unsigned char swapIN(unsigned char);
int main(int argc, char** argv){
    char *passwd, *infile, *outfile;
    int encode=0,bits=1, fsz=-1, depth=32,opt=0, flags=0; 
//    logp=fopen(LOGF,"w");
        /* Tell them how to use this thing */
    // initial format ./dcs c/x password <cover> <outfile> <infile>
    // reminder that argc includes program name

    // extract stego n password file
//    system("clear");
    while((opt=getopt(argc,argv,OPTIONS))!=-1){
        switch(opt){
            case 'p':
                flags += 4;
                passwd=optarg;
            break;
            case 's':
                flags += 2;
                infile=optarg;
            break;
            case 'd':
                flags += 1;        
                outfile=optarg;
            break;
            case 'h':
            case '?':
                usage(argv[0]);
                exit(0);
            break;
        }
    }
    
    if ((flags)!=3){
        printf("Ensure there are the minimum number of parameters\n\n");
        usage(argv[0]);
        exit(0);
    }

    Crypt(infile,outfile);

//    close (logp);
}


int Crypt(char *infile, char * outfile){

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

unsigned char swapIN(unsigned char x){
    // my cheap form of encryption
    //    printf("%x %x",x, ~x);
     return ( (~x & 0x0F)<<4 | (~x & 0xF0)>>4 );
}


    /* Tell them how to use this */
void usage(char *progname) {
    printf("%s Usage: \n\n>%s -h|-?\n\t%s -s source-file -d dest-file\n\n",
        progname,progname);
    printf("pass     - password used to encrypt file\n");
    printf("-s source-file - name of input file.\n");
    printf("-d dest-file - name of output file.\n");
    printf("Examples: \n1/\t$ %s h \n",progname);
    printf("\t\ttwill output the help instructions\n");
    printf("2/ \t>$ %s -s encrypted-filename -d destination-filename\n",progname);
    printf("\t\twill decrypt the encrypted data from encrypted-filename into destination-filename\n");
    printf("3/ \t>$ %s -s source-filename -d encrypted-filename\n",progname);
    printf("\t\twill encrypt from source-filename into encrypted-filename\n");

    exit(0);
} /* end usage() */