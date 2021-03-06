#ifndef _PACO_PACKET_ANALYZER_H
#define _PACO_PACKET_ANALYZER_H

#include "stl.h"
#include "pcap.h"
#include "basic.h"
#include "io.h"
#include "tcp_ip.h"
#include "context.h"
#include "TraceAnalyze.h"
#include "util.h"

class PacketAnalyzer {
private:
	vector<string> mTraceList;
	string outputFileFolder;
	Context mTraceCtx;
    string mTraceListFileName;
	string getFolder(string s);
	void configTraceList();
public:
	TraceAnalyze mTraceAnalyze;
    vector<TraceAnalyze> mPcapTraces;
	PacketAnalyzer();

    void init();
    string getNetworkType(string datafolder);
    string trimNameFormat(string fdr);
    void setOutputFileFolder(string fdr);
    string getLastFolder(string s);
	void checkSystem();
	void clearConfig();
	void setTraceListFileName(string fn);
	void addTrace(string tracename);
	Context getContext();
	string getTraceListFileName();
	void outputTraceAnalyze(string datafolder, int firsttime);
	void run();
	void dh(u_char *c, const struct pcap_pkthdr *header, const u_char *pkt_data);
    void printCandleStickData(const map<string, string>& targetIpSet, string metric);
    void printSkypeInfo();

};


#endif /* _PACO_PACKET_ANALYZER_H */
