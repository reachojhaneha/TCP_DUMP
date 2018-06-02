#include <stdio.h>
#include <stdlib.h>
#include <linux/types.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <limits.h>

#define MILLION 1000000
#define bswap32 __builtin_bswap32
#define bswap16 __builtin_bswap16

typedef struct {
    unsigned int    recHdrSec;
    unsigned int    recHdrUSec;
    unsigned int    recHdrNumOct;
    unsigned int    recHdrLen;
} RecHeader;
#define RECHDR_SIZE sizeof(RecHeader)

typedef struct {
    char            headerLength:4, ver:4;
    char            typeOfService;
    unsigned short  totalLength;
    unsigned short  id;
    unsigned short  fragOffset;
    char            timeToLive;
    char            protocol;
    unsigned short  checksum;
    unsigned int    sourceAddress;
    unsigned int    destinationAddress;
} IPHeader;
#define IPHDR_SIZE sizeof(IPHeader)

typedef struct  {
    unsigned short  sourcePort;
    unsigned short  destinationPort;
    unsigned int    sequenceNumber;
    unsigned int    ackNumber;
    unsigned short  reserved:4,dataOffset:4,FIN_FLAG:1,SYN_FLAG:1,RST_FLAG:1,PSH_FLAG:1,ACK_FLAG:1,URG_FLAG:1,ECE_FLAG:1,CWR_FLAG:1;
    unsigned short  windowSize;
    unsigned short  checkSum;
    unsigned short  urgentPointer;
} TCPHeader;
#define TCPHDR_SIZE sizeof(TCPHeader)

typedef struct tcpPkt {
    TCPHeader       *tcpHdr;
    RecHeader       *recHdr;
    unsigned int    expAck;
    double          rtt;
    struct tcpPkt   *next;
} TCPPktList;
#define TCPPKTLIST_SIZE sizeof(TCPPktList)

typedef struct tcp_flow {
    TCPPktList      *head;
    TCPPktList      *tail;
    unsigned short  pktSent;
    unsigned short  pktReceived;
    unsigned short  pktLost;
    unsigned int    sizeSent;
    char            windowScale;
    unsigned short  maxSegSize;
    double          throughput;
    double          avgRTT;
    struct tcp_flow *next;
} FlowList;
#define FLOWLIST_SIZE sizeof(FlowList)

FlowList *flStart;
FlowList *flEnd;

int numOfFlows() {
    int n = 0;
    FlowList *list = flStart;
    do {
        ++n;
        list = list->next;
    } while (list); 

    return n;
}

void initFlow(TCPHeader *tcpHdr, RecHeader *recHdr, char winScale, unsigned short mss) {
    if (flStart != NULL) {
        FlowList *list = (FlowList*) calloc(1,FLOWLIST_SIZE);
        flEnd->next = list;
        flEnd = list;

        list->maxSegSize = mss;
        list->pktReceived = 0;
        list->pktLost = 0;
        list->windowScale = winScale;
        list->pktSent = 1;
        list->sizeSent = recHdr->recHdrNumOct;
        list->next = NULL;

        list->head = (TCPPktList*) calloc(1,TCPPKTLIST_SIZE);
        list->head->recHdr = recHdr;
        list->head->tcpHdr = tcpHdr;
        list->head->rtt = 0;
        list->head->next = NULL;

        list->tail = list->head;
    } else {
        flStart = (FlowList*) calloc(1,FLOWLIST_SIZE);
        flEnd = flStart;

        flStart->maxSegSize = mss;
        flStart->pktReceived = 0;
        flStart->pktLost = 0;
        flStart->windowScale = winScale;
        flStart->pktSent = 1;
        flStart->sizeSent = recHdr->recHdrNumOct;
        flStart->next = NULL;

        flStart->head = (TCPPktList*) calloc(1,TCPPKTLIST_SIZE);
        flStart->head->expAck = tcpHdr->sequenceNumber + bswap32(1);
        flStart->head->recHdr = recHdr;
        flStart->head->tcpHdr = tcpHdr;
        flStart->head->rtt = 0;
        flStart->head->next = NULL;

        flStart->tail = flStart->head;
    }
}

void addFlow(TCPHeader *tcpHdr, RecHeader *recHdr, unsigned int payload_size) {
    TCPPktList *t_list = (TCPPktList*) calloc(1,TCPPKTLIST_SIZE);
    t_list->expAck = UINT_MAX;
    t_list->recHdr = recHdr;
    t_list->tcpHdr = tcpHdr;
    t_list->next = NULL;

    FlowList *list;
    for(list = flStart; ; list = list->next) {
        int tcpSrcPort = tcpHdr->sourcePort;
        int tcpDestPort = tcpHdr->destinationPort;
        int headSrcPort = list->head->tcpHdr->sourcePort;
        int headDestPort = list->head->tcpHdr->destinationPort;
        if ((headSrcPort == tcpDestPort && headDestPort == tcpSrcPort) 
                || (headSrcPort == tcpSrcPort && headDestPort == tcpDestPort)) {
            if (payload_size == 0 && list->pktSent > 1) {
                TCPPktList *t_list_flow;
                int i;
                for(t_list_flow = list->head, i=0; t_list_flow->next && i<2; t_list_flow = t_list_flow->next, i++); // Skip Handshake

                for(; t_list_flow; t_list_flow = t_list_flow->next) {
                    if(t_list_flow->rtt == 0) {
                        if (tcpHdr->ackNumber == t_list_flow->expAck) {
                            unsigned int recHdrUSec = recHdr->recHdrSec * MILLION + recHdr->recHdrUSec;
                            unsigned int flowRecHdrUSec = t_list_flow->recHdr->recHdrSec * MILLION + t_list_flow->recHdr->recHdrUSec;
                            t_list_flow->rtt = (double) (recHdrUSec - flowRecHdrUSec) / MILLION;
                            list->pktReceived++;
                            break;
                        }
                        if (bswap32(t_list_flow->expAck) < bswap32(tcpHdr->ackNumber)) {
                            list->pktReceived++;
                            t_list_flow->rtt = -1;
                        }
                    }
                }
                list->tail->next = t_list;
                list->tail = t_list;
                return;
            } else {
                TCPPktList *t_list_flow;
                t_list->rtt = 0;
                t_list->expAck = bswap32(payload_size + (bswap32(tcpHdr->sequenceNumber) + tcpHdr->FIN_FLAG));
                for(t_list_flow = list->head; t_list_flow; t_list_flow = t_list_flow->next) {
                    if (list->pktSent > 2) 
                        if(tcpHdr->sequenceNumber == t_list_flow->tcpHdr->sequenceNumber) { //Packet lost
                            t_list_flow->rtt = -1;
                            list->pktLost++;
                            t_list->expAck = UINT_MAX;
                            list->sizeSent -= t_list_flow->recHdr->recHdrLen;
                            break;
                        }
                }
                list->tail->next = t_list;
                list->sizeSent += t_list->recHdr->recHdrLen;
                list->pktSent++;
                list->tail = t_list;
                return;
            }
        }
    }
    printf("No flow found\n");
}

void print2A(int num) {
    int flowCount = 1;
    FlowList *list;
    printf("Flow      ");
    printf("Ports     ");
    printf("Seq_Num     ");
    printf("Ack_Num     ");
    printf("Dest_Seq_Num   ");
    printf("Dest_Ack_Num  ");
    printf("Recv_Window   ");
    printf("Length\n");

    for(list = flStart; list; ) {
        char *port = (char*) calloc(1,12);
        unsigned short srcPort = (unsigned short)bswap16(list->head->tcpHdr->sourcePort);
        unsigned short destPort = (unsigned short) bswap16(list->head->tcpHdr->destinationPort);
        sprintf(port,"%u->%u", srcPort, destPort);

        TCPPktList *t_list;
        for(t_list = list->head; t_list->tcpHdr->SYN_FLAG && t_list->tcpHdr->ACK_FLAG; t_list = t_list->next); //Skip handshake
        t_list = t_list->next->next;

        int transaction;
        for(transaction = 0; transaction < num; transaction++) { 
            t_list = t_list->next;
            printf("%3d",  flowCount);
            printf("%14s", port);
            printf("%12u", bswap32(t_list->tcpHdr->sequenceNumber));
            printf("%12u", bswap32(t_list->tcpHdr->ackNumber));
            printf("%14u", bswap32(t_list->tcpHdr->ackNumber));
            printf("%15u", bswap32(t_list->expAck));
            printf("%10u", bswap16(t_list->tcpHdr->windowSize) * (1 << list->windowScale));
            printf("%12u\n", t_list->recHdr->recHdrNumOct);
        }
        flowCount++;
        list = list->next;
    }
}

void print2B() {
    int flowCount = 1;
    FlowList *list = flStart;
    printf("Flow      Ports       Sent(B)  Time(s)    Throughput(Mbps)\n");
    while (list) {;
        unsigned long start_time = (long) list->head->recHdr->recHdrSec * MILLION + list->head->recHdr->recHdrUSec;
        unsigned long end_time = (long) list->tail->recHdr->recHdrSec * MILLION + list->tail->recHdr->recHdrUSec;
        double total_time_taken = (double) (end_time - start_time) / MILLION;
        char *port = (char*) calloc(1,12);
        unsigned short srcPort = (unsigned short)bswap16(list->head->tcpHdr->sourcePort);
        unsigned short destPort = (unsigned short) bswap16(list->head->tcpHdr->destinationPort);
        sprintf(port,"%u->%u", srcPort, destPort);
        list->throughput = 8.0 / MILLION * (double) list->sizeSent / total_time_taken;
        printf("%3d", flowCount++);
        printf("%14s", port);
        printf("%12u", list->sizeSent);
        printf("%10.6lf", total_time_taken);
        printf("%15.6lf\n", list->throughput);
        list = list->next;
    }
}

void print2C() {
    int flowCount = 1;
    FlowList *list = flStart;
    printf("Flow      Ports    Packets Sent  Packets Lost  Loss Rate\n");
    while (list) {
        char *port = (char*) calloc(1,12);
        unsigned short srcPort = (unsigned short)bswap16(list->head->tcpHdr->sourcePort);
        unsigned short destPort = (unsigned short) bswap16(list->head->tcpHdr->destinationPort);
        sprintf(port,"%u->%u", srcPort, destPort);
        printf("%3d", flowCount++);
        printf("%14s", port);
        printf("%11u", list->pktSent);
        printf("%13u", list->pktLost);
        printf("%16.8lf\n", (double)list->pktLost / list->pktSent);
        list = list->next;
    }
}

void print2D() {
    int flowCount = 1;
    double throughput;
    double theoretical_throughput;
    FlowList *list = flStart;
    printf("Flow      Ports    Average RTT  Theoretical Throughput  Empirical Throughput\n");
    while (list) {
        int s_port = list->head->tcpHdr->sourcePort;
        TCPPktList *t_list = list->head;

        double avgRTT = 0;
        int list_count = 0;
        while (t_list) {
            if (t_list->tcpHdr->sourcePort == s_port) {
                if (t_list->rtt > 0) {
                    avgRTT += t_list->rtt;
                    list_count++;
                }
            }
            t_list = t_list->next;
        }
        char *port = (char*) calloc(1,12);
        list->avgRTT = avgRTT / list_count;
        throughput = list->throughput;
        theoretical_throughput = (sqrt(3/2)*list->maxSegSize)/(list->avgRTT * sqrt((double)list->pktLost / list->pktSent)) * 8 / MILLION;
        unsigned short srcPort = (unsigned short)bswap16(list->head->tcpHdr->sourcePort);
        unsigned short destPort = (unsigned short) bswap16(list->head->tcpHdr->destinationPort);
        sprintf(port,"%u->%u", srcPort, destPort);
        printf("%3d", flowCount++);
        printf("%14s", port);
        printf("%12.6lf", avgRTT / list_count);
        printf("%20lf", theoretical_throughput);
        printf("%21lf\n", throughput);
        list = list->next;
    }
}

int main(int argc, char **argv) {
    FILE *fp = fopen("assignment2.pcap", "r");

    void *tcpHdrOptional = NULL;
    RecHeader *rec_h = (RecHeader*) calloc(1,RECHDR_SIZE);
    TCPHeader *tcpHdr;
    int payloadSize;
    void *ipHdrOptional = NULL;
    IPHeader ip_h;
    int tcpHdrOptionalLength;
    int ipHdrOptionalLength;

    void *temp = calloc(1,24);

    fread(temp, 24, 1, fp); //read and ignore global header
    int items = fread(rec_h, RECHDR_SIZE, 1, fp);

    while (items > 0) {
        tcpHdr = (TCPHeader*) calloc(1,TCPHDR_SIZE);

        if (temp != NULL)
            free(temp);
        temp = (void*) calloc(1,14);
        fread(temp, 14, 1, fp); //read and ignore ethernet header

        fread(&ip_h, IPHDR_SIZE, 1, fp);
        ipHdrOptionalLength = 4 * (ip_h.headerLength - 5);
        if (ipHdrOptional)
            free(ipHdrOptional);
        ipHdrOptional = (void*) calloc(1,ipHdrOptionalLength);

        fread(ipHdrOptional, ipHdrOptionalLength, 1, fp);

        fread(tcpHdr, TCPHDR_SIZE, 1, fp);
        tcpHdrOptionalLength = 4 * (tcpHdr->dataOffset - 5);
        if (tcpHdrOptional)
            free(tcpHdrOptional);
        tcpHdrOptional = (void *) calloc(1,tcpHdrOptionalLength);

        fread(tcpHdrOptional, tcpHdrOptionalLength, 1, fp);

        if (temp != NULL)
            free(temp);
        payloadSize = rec_h->recHdrLen - 54 /*size of the headers*/ - ipHdrOptionalLength - tcpHdrOptionalLength;
        temp = (void*) calloc(1,payloadSize);
        fread(temp, payloadSize, 1, fp);

        if (!tcpHdr->SYN_FLAG || tcpHdr->ACK_FLAG) {
            addFlow(tcpHdr, rec_h, payloadSize);
        } else {
            char win = 0;
            unsigned short mss = 0;
            if (NULL != tcpHdrOptional) {
                char *hdrOptional = (char*) tcpHdrOptional;
                int ctr;
                short len;
                char kind;
                for(ctr=0; ctr < tcpHdrOptionalLength; ) {
                    kind = hdrOptional[ctr];
                    ctr++;
                    if(kind == 2) {
                        mss = hdrOptional[++ctr];
                        mss = (mss<<8) + hdrOptional[++ctr];
                        ctr ++;
                    } else if(kind == 5 || kind == 8) {
                        len = (short) hdrOptional[ctr];
                        ctr += len - 1;
                    } else if(kind == 3) {
                        win = hdrOptional[++ctr];
                        ctr++;
                    } else if(kind == 0) {
                        ctr = tcpHdrOptionalLength;
                    } else if(kind == 4) {
                        ctr++;
                    }
                }
            }
            initFlow(tcpHdr, rec_h, win, mss);
        }

        rec_h = (RecHeader*) calloc(1,RECHDR_SIZE);
        items = fread(rec_h, RECHDR_SIZE, 1, fp);
    }
    printf("Part A\n1. Total Number of TCP Flows initiated by the Sender - %d\n", numOfFlows());
    printf("\n2 (a) First 2 transactions per Flow\n");
    print2A(2);
    printf("\n2 (b) Throughput\n");
    print2B();
    printf("\n2 (c) Loss Rate\n");
    print2C();
    printf("\n2 (d) Average RTT\n");
    print2D();
    fclose(fp);
    return 0;
}
