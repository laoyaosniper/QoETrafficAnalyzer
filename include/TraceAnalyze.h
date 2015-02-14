/*
 * TraceAnalyze.h
 *
 * Created by: Qi Alfred Chen, 1/07/2013
 *
 */
#ifndef _TRACEANALYZE_H
#define _TRACEANALYZE_H

#include "stl.h"
#include "pcap.h"
#include "basic.h"
#include "io.h"
#include <deque>
#include "tcp_ip.h"
#include "context.h"
#include "DNSops.h"
#include "tcpflowstat.h"
#include "rrcstate.h"

class TraceAnalyze {
public:
//private:
    int pktcnt;
    vector<struct DNSQueryComb> dnsquery;

    double aveInterPacketArriveTime;
    double lastPacketArriveTime;

    int gt5pktcnt;
    RRCStateMachine rrcstate;
    //deque<struct TCPFlowStat> tcpflows;
    deque<struct TCPFlowStat> tcpflows;
    vector<struct DNSQueryComb> ansdnsquery;
    vector<string> gt5state;
    TraceAnalyze();
    void clearData();
    void printTitle(ofstream &output);
    int printLine(ofstream &output,int i);
    void getStrAddr(long ip, char* res);
    void bswapIP(ip* ip);
    void bswapIPv6(struct ip6_hdr* ip6);
    void bswapTCP(tcphdr* tcphdr);
    void bswapUDP(udphdr* udphdr);
    void bswapDNS(struct DNS_HEADER* dnshdr);
    void handleTCPFlow(string ip_src, string ip_dst, int ippayloadlen, struct tcphdr* tcphdr, double ts);
    void feedTracePacket(Context ctx, const struct pcap_pkthdr *header, const u_char *pkt_data);
/*
    double printAvgIAT() const;
    int printAvgPktSize() const;
    int printUplinkPktSize() const;
    int printDownlinkPktSize() const;
    int printAvgClientReceiverWindowSize() const;
    int printAvgServerReceiverWindowSize() const;
    double printAvgRTT() const;
    double printUplinkThroughput() const;
    double printDownlinkThroughput() const;
*/
    //double printAvgIAT(string ip = "") const;
    double printUplinkIAT(string ip = "") const;
    double printDownlinkIAT(string ip = "") const;
    int printAvgPktSize(string ip = "") const;
    int printUplinkPktSize(string ip = "") const;
    int printDownlinkPktSize(string ip = "") const;
    int printAvgClientReceiverWindowSize(string ip = "") const;
    int printAvgServerReceiverWindowSize(string ip = "") const;
    double printAvgRTT(string ip = "") const;
    double printUplinkThroughput(string ip = "") const;
    double printDownlinkThroughput(string ip = "") const;

};

#endif /* _TRACEANALYZE_H */
