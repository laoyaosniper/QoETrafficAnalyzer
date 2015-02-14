/*
 * tcpflow.h
 *
 * Created by: Qi Alfred Chen, 1/07/2014
 *
 */
#ifndef TCP_FLOW_H_INCLUDED
#define TCP_FLOW_H_INCLUDED


#include "basic.h"
#include "TraceAnalyze.h"
#include <arpa/inet.h>

#define TCPCONSTATE_CLOSED 0
#define TCPCONSTATE_SYN_SEND 1
#define TCPCONSTATE_SYN_RECEIVED 2
#define TCPCONSTATE_ESTABLISHED 3
#define TCPCONSTATE_FIN 4

#define SIMUL_SYNACK_NOT_RECEIVED 0
#define SIMUL_SYNACK_RECEIVED 1

#define PKTSENDER_CLT 0
#define PKTSENDER_SVR 1

#define FLOWINITBYCLT 0
#define FLOWINITBYSVR 1

class TCPFlowStat {
private:
    deque< pair<int,double> > unackedSegs;
    double clientInitTime;
    double serverInitTime;
    void calcUplinkThrpt(double ts);
    void calcDownlinkThrpt(double ts);
    void updateRTT(double ts);
    int cltWndShift;
    int svrWndShift;
public:
    string cltip;
    string svrip;
    u_short cltport;
    u_short svrport;

    u_int tcpconnstate;
    double syntime, synacktime, acktime;
    double syntosynacktime, synacktoacktime;


    u_int cltseq,cltackseq,svrseq,svrackseq;
    u_int cltinitseq,svrinitseq;

    int simulsyn, simulsynackstate;
    int flowinitby;

    //metrics
    int pktcnt;
    int clientcnt;
    int servercnt;
    int rttcnt;
    double tcpconnsetuptime;
    int cltretxbytes,svrretxbytes,cltretxnum,svrretxnum;
    double avepacketinterarrivaltime;
    double lastpacketarrivaltime;
    double avgUplinkIAT;
    double avgDownlinkIAT;
    double lastUplinkPktArrivalTime;
    double lastDownlinkPktArrivalTime;

    // More network metrics
    int totalPayloadSize;
    int uplinkPayloadSize;
    int downlinkPayloadSize;
    int avgCltRWin;
    int avgSvrRWin;
    int avgCltCWin;
    int avgSvrCWin;
    double avgRTT;
    double avgUplinkThrpt;
    double avgDownlinkThrpt;
    vector<double> uplinkIATList;
    vector<double> downlinkIATList;
    vector<int> payloadSizeList;
    vector<int> cltRWinList;
    vector<int> svrRWinList;
    vector<int> cltCWinList;
    vector<int> svrCWinList;
    vector<double> latencyList;
    vector<int> cltBIFList;
    vector<int> svrBIFList;
    vector<double> uplinkThrptList;
    vector<double> downlinkThrptList;

    TCPFlowStat();
    void clearData();
    void swapcltsvr();
    void printStat();
    int isClient(u_int ipaddr);
    static int isNewFlow(string ip_src, string ip_dst, struct tcphdr* tcphdr);
    int getPacketDirection(string ip_src, string ip_dst, u_short srcport, u_short dstport);
    void addPacket(string ip_src, string ip_dst, int ippayloadlen, struct tcphdr* tcphdr, double ts);
    int isMyPacket(string ip_src, string ip_dst, struct tcphdr* tcphdr);

};

#endif // TCP_FLOW_H_INCLUDED
