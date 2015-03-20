#include "tcpflowstat.h"

TCPFlowStat::TCPFlowStat(){
    clearData();
};

void TCPFlowStat::clearData(){
    cltWndShift = 0;
    svrWndShift = 0;
    tcpconnstate=0;
    pktcnt=0;
    clientcnt=0;
    servercnt=0;
    rttcnt=0;
    totalPayloadSize = 0;
    avgRTT=0.0;
    clientInitTime = 0.0;
    serverInitTime = 0.0;
    avgUplinkThrpt = 0.0;
    avgDownlinkThrpt = 0.0;
    simulsyn=0;
    simulsynackstate=SIMUL_SYNACK_NOT_RECEIVED;

    tcpconnsetuptime=0;
    cltretxbytes=0; svrretxbytes=0;
    cltretxnum=0; svrretxnum=0;
    avepacketinterarrivaltime=0.0;
    lastpacketarrivaltime=-1.0;
    lastUplinkPktArrivalTime=-1.0;
    lastDownlinkPktArrivalTime=-1.0;

    startCltAckTs = -1.0;
    startCltAckSeq = -1;
    endCltAckTs = -1.0;
    endCltAckSeq = -1;

    startSvrAckTs = -1.0;
    startSvrAckSeq = -1;
    endSvrAckTs = -1.0;
    endSvrAckSeq = -1;

    httpRequestSeq = 0;
    httpResponseSeq = 0;
    //payloadSizeList.clear();
}


int TCPFlowStat::getPacketDirection(string ip_src, string ip_dst, u_short srcport, u_short dstport){
    if (cltip.compare(ip_src)==0 && svrip.compare(ip_dst)==0 && cltport==srcport && svrport==dstport) return PKTSENDER_CLT;
    if (cltip.compare(ip_dst)==0 && svrip.compare(ip_src)==0 && cltport==dstport && svrport==srcport) return PKTSENDER_SVR;
    return -1;

}

int TCPFlowStat::isNewFlow(string ip_src, string ip_dst, struct tcphdr* tcphdr){
    if (tcphdr->syn==1 && tcphdr->ack!=1) return 1;
    return 0;
}

int TCPFlowStat::isMyPacket(string ip_src, string ip_dst, struct tcphdr* tcphdr) {
    if (!(cltip.compare(ip_src)==0 && svrip.compare(ip_dst)==0 \
          && cltport==tcphdr->source && svrport==tcphdr->dest) \
        &&
        !(cltip.compare(ip_dst)==0 && svrip.compare(ip_src)==0 \
          && cltport==tcphdr->dest && svrport==tcphdr->source)) return 0;
    int pktdir=getPacketDirection(ip_src, ip_dst, tcphdr->source, tcphdr->dest);

  /*  if (tcphdr->syn==1 && )
      return 0;

    if (tcphdr->syn==1 && tcphdr->ack==1 \
        && !(tcpconnstate==TCPCONSTATE_SYN_SEND && pktsdr==PKTSENDER_)){
            return 0;
    }*/
  /*  if (tcphdr->syn==1 && tcphdr->ack!=1 \
        && !(tcpconnstate==TCPCONSTATE_SYN_SEND && pktdir==PKTSENDER_SVR)) {
            return 0;
    }
*/

  /*
    if (tcpconnstate==TCPCONSTATE_FIN){
            return 0;
    }
    */

    return 1;
}

void TCPFlowStat::swapcltsvr(){
    //only swap those updated before TCPCONSTATE_ESTABLISHED
    string stri=cltip; cltip=svrip; svrip=stri;
    u_short ts=cltport; cltport=svrport; svrport=ts;

    u_int ti=ti=cltseq; cltseq=svrseq; svrseq=ti;
    ti=cltackseq; cltackseq=svrackseq; svrackseq=ti;
    ti=cltinitseq; cltinitseq=svrinitseq; svrinitseq=ti;
};

void TCPFlowStat::printStat(){
    //for debug
    if (0 && cltip.compare("192.168.1.139")==0 && svrip.compare("31.13.74.144")==0)
    printf("\ncltip:%s svrip:%s cltport:%d svrport:%d cltseq:%u cltackseq:%u svrseq:%u svrackseq:%u\n",\
                       cltip.c_str(),svrip.c_str(), cltport,svrport,cltseq,cltackseq,svrseq,svrackseq);
}

void TCPFlowStat::addPacket(string ip_src, string ip_dst, int ippayloadlen, struct tcphdr* tcphdr, double ts){
    if (!isNewFlow(ip_src, ip_dst, tcphdr) && isMyPacket(ip_src, ip_dst, tcphdr)!=1) return;
    int pktdir=getPacketDirection(ip_src, ip_dst, tcphdr->source, tcphdr->dest);
    int tcpdatalen=ippayloadlen-tcphdr->doff*4;

    pktcnt++;
    //packet inter-arrival time
    if (lastpacketarrivaltime > 0){
        double iat=ts-lastpacketarrivaltime;
        avepacketinterarrivaltime=(avepacketinterarrivaltime*(pktcnt-2)+iat)/(pktcnt-1);
    }
    lastpacketarrivaltime=ts;

    // save payload size
    payloadSizeList.push_back(tcpdatalen);
    totalPayloadSize += tcpdatalen;
    if (pktdir == PKTSENDER_SVR) {
        servercnt++;
        if (lastDownlinkPktArrivalTime > 0) {
            double iat = ts - lastDownlinkPktArrivalTime;
            downlinkIATList.push_back(iat);
        }
        lastDownlinkPktArrivalTime = ts;
        // window scaling is considered
        int wnd = (int)tcphdr->window << svrWndShift;
        svrRWinList.push_back(wnd);
        if (tcpdatalen > 0) svrPayloadSizeList.push_back(tcpdatalen);
    }
    else {
        clientcnt++;
        if (lastUplinkPktArrivalTime > 0) {
            double iat = ts - lastUplinkPktArrivalTime;
            uplinkIATList.push_back(iat);
        }
        lastUplinkPktArrivalTime = ts;
        // window scaling is considered
        int wnd = (int)tcphdr->window << cltWndShift;
        cltRWinList.push_back(wnd);
        if (tcpdatalen > 0) cltPayloadSizeList.push_back(tcpdatalen);
    }

    if (tcphdr->doff > 5) {
        const char* hdr = (const char*)tcphdr + 5*4;
        const char* hdrBound = (const char*)tcphdr + tcphdr->doff*4;
        while (hdr < hdrBound) {
            int type = (int)*hdr;
            //cout << "Type: " << type << endl;
            if (type == 3) { // window scale
                hdr += 2;
                if (pktdir == PKTSENDER_SVR) {
                    svrWndShift = (int)*hdr;
                }
                else {
                    cltWndShift = (int)*hdr;
                }
                break;
            }
            else if (type == 1 || type == 0) {
                hdr++;
            }
            else {
                hdr++;
                int length = *hdr;
                //cout << "Length: " << length << endl;
                hdr += length - 1; //length
            }
        }
    }

    switch (tcpconnstate){
        case TCPCONSTATE_CLOSED:
            if (tcphdr->syn==1 && tcphdr->ack!=1){
                syntime=ts;
                cltip=ip_src;
                svrip=ip_dst;
                cltport=tcphdr->source;
                svrport=tcphdr->dest;
                cltseq=tcphdr->seq;
                svrackseq=tcphdr->seq+1; cltinitseq=tcphdr->seq+1;
                clientInitTime = ts;

                flowinitby=FLOWINITBYCLT;
                printStat();

                tcpconnstate=TCPCONSTATE_SYN_SEND;
            }
            else {
                printf("Unknown TCP packet.\n");
            };
            break;
        case TCPCONSTATE_SYN_SEND:
            if (tcphdr->syn==1 && tcphdr->ack==1 && tcphdr->ack_seq==svrackseq){
                synacktime=ts;
                syntosynacktime=synacktime-syntime;
                svrseq=tcphdr->seq;
                cltackseq=tcphdr->seq+1; svrinitseq=tcphdr->seq+1;
                serverInitTime = ts;
                // for uplink throughput
                calcUplinkThrpt(ts);

                cltseq=tcphdr->ack_seq;

                tcpconnstate=TCPCONSTATE_SYN_RECEIVED;
                printStat();
            }
            else if (tcphdr->syn==1 && tcphdr->ack!=1 && pktdir==PKTSENDER_SVR){
                //simultanous syn sent from both side
                simulsyn=1;
                svrseq=tcphdr->seq;
                cltackseq=tcphdr->seq+1; svrinitseq=tcphdr->seq+1;
                serverInitTime = ts;
                // for uplink throughput
                calcUplinkThrpt(ts);

                tcpconnstate=TCPCONSTATE_SYN_RECEIVED;
                printStat();
            }
            else{
                printf("Unknown TCP packet.\n");
            };

            break;
        case TCPCONSTATE_SYN_RECEIVED:
            if (tcphdr->syn!=1 &&tcphdr->ack==1 && tcphdr->seq==cltseq && tcphdr->ack_seq==cltackseq){
                acktime=ts;
                synacktoacktime=acktime-synacktime;
                if (synacktoacktime>syntosynacktime){
                //the server side is the local device
                    swapcltsvr();
                    flowinitby=FLOWINITBYSVR;
                }
                tcpconnsetuptime=acktime-syntime;


                pktdir=getPacketDirection(ip_src, ip_dst, tcphdr->source, tcphdr->dest);

                if (pktdir==PKTSENDER_CLT){
                    cltseq=tcphdr->seq+tcpdatalen;
                    cltackseq=tcphdr->ack_seq;
                    // for downlink throughput
                    calcDownlinkThrpt(ts);

                    svrseq=tcphdr->ack_seq;
                    unackedSegs.push_back(make_pair(cltseq, ts));
                }
                if (pktdir==PKTSENDER_SVR){
                    svrseq=tcphdr->seq+tcpdatalen;
                    svrackseq=tcphdr->ack_seq;
                    cltseq=tcphdr->ack_seq;
                }
                printStat();

                tcpconnstate=TCPCONSTATE_ESTABLISHED;
            }
            else
            if (tcphdr->syn==1 && tcphdr->ack==1 && simulsyn==1){
            //simultanous syn sent from both side
                if (pktdir==PKTSENDER_CLT && tcphdr->seq==cltseq && tcphdr->ack_seq==cltackseq){
                    if (simulsynackstate==SIMUL_SYNACK_NOT_RECEIVED)
                      simulsynackstate==SIMUL_SYNACK_NOT_RECEIVED;
                    if (simulsynackstate==SIMUL_SYNACK_RECEIVED)
                      tcpconnstate=TCPCONSTATE_ESTABLISHED;

                }
                if (pktdir==PKTSENDER_SVR && tcphdr->seq==svrseq && tcphdr->ack_seq==svrackseq){

                    if (simulsynackstate==SIMUL_SYNACK_NOT_RECEIVED)
                      simulsynackstate==SIMUL_SYNACK_NOT_RECEIVED;
                    if (simulsynackstate==SIMUL_SYNACK_RECEIVED)
                      tcpconnstate=TCPCONSTATE_ESTABLISHED;
                }

                if (tcpconnstate==TCPCONSTATE_ESTABLISHED){
                    tcpconnsetuptime=ts-syntime;
                    cltseq=svrackseq;
                    svrseq=cltackseq;
                }

            }
            else {
                printf("Unknown TCP packet.\n");
            };
            break;
        case TCPCONSTATE_ESTABLISHED:
            if (tcphdr->syn!=1 && tcphdr->rst!=1) {

                if (pktdir==PKTSENDER_CLT){
                    //calc metrics first
                    if (tcphdr->seq > cltseq){
                        printf("client seq is greater than expected, may be pcap's fault.\n");
                    }
                    if (tcphdr->seq < cltseq){
                    //has re-transmission
                        int retxseq = tcphdr->seq + tcpdatalen;
                        updateUnackedSeg(retxseq, ts);
                    /*
                        int retxb=cltseq-tcphdr->seq;
                        if (tcpdatalen<retxb)
                          retxb=tcpdatalen;

                        cltretxbytes+=retxb;
                        cltretxnum+=1;
                  //      printf("client retx %d bytes.\n", retxb);
                    */
                    };
                    //if (tcphdr->seq < cltseq) {
                    if (tcphdr->seq < cltseq && tcpdatalen > 0){
                    //has re-transmission
                        int retxb=cltseq-tcphdr->seq;
                        if (tcpdatalen<retxb)
                          retxb=tcpdatalen;

                        cltretxbytes+=retxb;
                        cltretxnum+=1;
                  //      printf("client retx %d bytes.\n", retxb);
                    };

                    //the last thing: update seq
                    if (tcphdr->seq+tcpdatalen > cltseq) {
                        cltseq=tcphdr->seq+tcpdatalen;
                        //updateUnackedSeg(cltseq, ts);
                        unackedSegs.push_back(make_pair(cltseq,ts));
                        if (svrport == 80 || svrport == 8080) {
                            char* pHTTPRequest =  (char*)tcphdr + tcphdr->doff*4;
                            if (pHTTPRequest[0] == 'G' && pHTTPRequest[1] == 'E' && pHTTPRequest[2] == 'T') {
                                httpRequestSeq++;
                                unackedHTTPSegs.push_back(make_pair(httpRequestSeq, ts));
                            }
                        }
                        int bif = cltseq - svrackseq;
                        cltBIFList.push_back(bif);
                    }

                    if (tcphdr->ack_seq >= cltackseq) {
                        cltackseq=tcphdr->ack_seq;
                        // downlink throughput
                        calcDownlinkThrpt(ts);
                    };
                    printStat();
                };

                if (pktdir==PKTSENDER_SVR){

                    if (tcphdr->seq > svrseq){
                 //       printf("svr seq is greater than expected, some server data are delayed or lost.\n");
                    }
/*
                    if (tcphdr->seq < svrseq) {
                        int retxb=svrseq-tcphdr->seq;
                        if (tcpdatalen<retxb)
                          retxb=tcpdatalen;

                        svrretxbytes+=retxb;
                        svrretxnum+=1;
                   //     printf("server retx %d bytes.\n", retxb);
                    };
*/
                    if (tcphdr->seq < svrseq && tcpdatalen > 0) {
                        int retxb=svrseq-tcphdr->seq;
                        if (tcpdatalen<retxb)
                          retxb=tcpdatalen;

                        svrretxbytes+=retxb;
                        svrretxnum+=1;
                   //     printf("server retx %d bytes.\n", retxb);
                    };


                    //the last thing: update seq

                    if (tcphdr->seq+tcpdatalen > svrseq) {
                        svrseq=tcphdr->seq+tcpdatalen;
                        if (svrport == 80 || svrport == 8080) {
                            char* pHTTPRequest =  (char*)tcphdr + tcphdr->doff*4;
                            if (pHTTPRequest[0] == 'H' && pHTTPRequest[1] == 'T' && pHTTPRequest[2] == 'T' && pHTTPRequest[3] == 'P') {
                                httpResponseSeq++;
                                updateHTTPLatency(ts);
                            }
                        }
                        int bif = svrseq - cltackseq;
                        svrBIFList.push_back(bif);
                    }


                    if (tcphdr->ack_seq >= svrackseq) {
                        svrackseq=tcphdr->ack_seq;
                        calcUplinkThrpt(ts);
                        // rtt
                        updateRTT(ts);
                    };
                    printStat();

                }

                if (tcphdr->fin==1 || tcphdr->rst==1){
                    tcpconnstate=TCPCONSTATE_FIN;
                }
            }
            break;
        case TCPCONSTATE_FIN:
                break;
                if (pktdir==PKTSENDER_CLT){
                    //calc metrics first
                    if (tcphdr->seq < cltseq){
                    //has re-transmission
                        int retxseq = tcphdr->seq + tcpdatalen;
                        updateUnackedSeg(cltseq, ts);
                    /*
                        int retxb=cltseq-tcphdr->seq;
                        if (tcpdatalen<retxb)
                          retxb=tcpdatalen;

                        cltretxbytes+=retxb;
                        cltretxnum+=1;
                  //      printf("client retx %d bytes.\n", retxb);
                    */
                    };

                    //the last thing: update seq
                    if (tcphdr->seq+tcpdatalen > cltseq) {
                        cltseq=tcphdr->seq+tcpdatalen;
                        //unackedSegs.push_back(make_pair(cltseq,ts));
                        updateUnackedSeg(cltseq, ts);
                        int bif = cltseq - svrackseq;
                        cltBIFList.push_back(bif);
                    }

                    if (tcphdr->ack_seq >= cltackseq) {
                        cltackseq=tcphdr->ack_seq;
                        // downlink throughput
                        //calcDownlinkThrpt(ts);
                    };
                    printStat();
                };

                if (pktdir==PKTSENDER_SVR){
                    /*
                    if (tcphdr->seq < svrseq) {
                        int retxb=svrseq-tcphdr->seq;
                        if (tcpdatalen<retxb)
                          retxb=tcpdatalen;

                        svrretxbytes+=retxb;
                        svrretxnum+=1;
                   //     printf("server retx %d bytes.\n", retxb);
                    };
                    */

                    //the last thing: update seq

                    if (tcphdr->seq+tcpdatalen > svrseq) {
                        svrseq=tcphdr->seq+tcpdatalen;
                        int bif = svrseq - cltackseq;
                        svrBIFList.push_back(bif);
                    }


                    if (tcphdr->ack_seq >= svrackseq) {
                        svrackseq=tcphdr->ack_seq;
                        //calcUplinkThrpt(ts);
                        // rtt
                        updateRTT(ts);
                    };
                    printStat();

                }
            break;
        default:
            printf("Unknown TCP connection state.\n");
            break;
    };

}

void TCPFlowStat::calcUplinkThrpt(double ts) {
    // uplink throughput, bps
    avgUplinkThrpt = 8 * (svrackseq - cltinitseq) / (ts - clientInitTime);
    // more fine-grinded measurement
    if (startSvrAckSeq == -1) {
        startSvrAckSeq = svrackseq;
        startSvrAckTs = ts;
        endSvrAckSeq = svrackseq;
        endSvrAckTs = ts;
        uplinkThrptList.push_back(0.0);
    }
    //else if (svrackseq > startSvrAckSeq) {
    else if (svrackseq > endSvrAckSeq) {
        if (ts - startSvrAckTs > THRPT_SAMPLE_INTERVAL) {
            uplinkThrptList.push_back(0.0);
            startSvrAckSeq = endSvrAckSeq;
            endSvrAckSeq = svrackseq;
            startSvrAckTs = ts;
        }
        else {
            endSvrAckSeq = svrackseq;
            endSvrAckTs = ts;
        }
        double& thrpt = uplinkThrptList.back();
        thrpt = 8 * (endSvrAckSeq - startSvrAckSeq) / THRPT_SAMPLE_INTERVAL;
        /*
        if (svrip == "2607:7700:0:7::42eb:9371") {
            cout << startSvrAckSeq << " " << endSvrAckSeq << " " << thrpt << endl;
            for (vector<double>::iterator it = uplinkThrptList.begin(); it != uplinkThrptList.end(); it++) {
                cout << *it << " ";
            }
            cout << endl;
        }
        */
    }

}
void TCPFlowStat::calcDownlinkThrpt(double ts) {
    // average downlink throughput, bps
    avgDownlinkThrpt = 8 * (cltackseq - svrinitseq) / (ts - serverInitTime);
    // more fine-grinded measurement
    if (startCltAckSeq == -1) {
        startCltAckSeq = cltackseq;
        startCltAckTs = ts;
        endCltAckSeq = cltackseq;
        endCltAckTs = ts;
        downlinkThrptList.push_back(0.0);
    }
    //else if (cltackseq > startCltAckSeq) {
    else if (cltackseq > endCltAckSeq) {
        if (ts - startCltAckTs > THRPT_SAMPLE_INTERVAL) {
            downlinkThrptList.push_back(0.0);
            startCltAckSeq = endCltAckSeq;
            endCltAckSeq = cltackseq;
            startCltAckTs = ts;
        }
        else {
            endCltAckSeq = cltackseq;
            endCltAckTs = ts;
        }
        double& thrpt = downlinkThrptList.back();
        thrpt = 8 * (endCltAckSeq - startCltAckSeq) / THRPT_SAMPLE_INTERVAL;
        /*
        if (thrpt < 0.00001 && thrpt > -0.00001) {
            cout << startCltAckSeq << " " << endCltAckSeq << " " << startCltAckTs << endl;
        }
        */
    }
}

/*
void TCPFlowStat::updateRTT(double ts) {
    while(!unackedSegs.empty()) {
        pair<int,double>& pr = unackedSegs.front();
        if(pr.first == svrackseq) {
            // found RTT sample
            rttcnt++;
            double rtt = ts - pr.second;
            avgRTT = (avgRTT*(rttcnt-1) + rtt)/rttcnt;
            latencyList.push_back(rtt);
            unackedSegs.pop_front();
            break;
        }
        else if (pr.first < svrackseq) {
            unackedSegs.pop_front();
        }
        else {
            break;
        }
    }
}
*/
void TCPFlowStat::updateRTT(double ts) {
    while(!unackedSegs.empty()) {
        pair<int,double>& pr = unackedSegs.front();
        if(pr.first == svrackseq) {
            // found RTT sample
            rttcnt++;
            double rtt = ts - pr.second;
            /*
            if (rtt > 0.1) {
                cout << fixed << cltport << " " << pktcnt << " " << svrackseq-cltinitseq+1 << " " << ts << " " << pr.second << " " << ts - pr.second << endl;
            }
            */
            avgRTT = (avgRTT*(rttcnt-1) + rtt)/rttcnt;
            latencyList.push_back(rtt);
            unackedSegs.pop_front();
            break;
        }
        else if (pr.first < svrackseq) {
            unackedSegs.pop_front();
        }
        else {
            break;
        }
    }
}

void TCPFlowStat::updateUnackedSeg(int seq, double ts) {
    bool isFound = false;
    for (deque< pair<int, double> >::iterator it = unackedSegs.begin();
        it != unackedSegs.end();
        it++) {
        if (it->first == seq) {
            it->second = ts;
            isFound = true;
            break;
        }
    }
    /*
    if (isFound == false) {
        unackedSegs.push_back(make_pair(seq,ts));
    }
    */
}

void TCPFlowStat::updateHTTPLatency(double ts) {
    while(!unackedHTTPSegs.empty()) {
        pair<int,double>& pr = unackedHTTPSegs.front();
        if(pr.first == httpResponseSeq) {
            // found HTTP RTT sample
            double rtt = ts - pr.second;
            /*
            if (svrip == "2607:7700:0:7::3f83:933b") {
                cout << cltport << " " << rtt << endl;
            }
            */
            /*
            if (rtt > 0.1) {
                cout << fixed << cltport << " " << pktcnt << " " << svrackseq-cltinitseq+1 << " " << ts << " " << pr.second << " " << ts - pr.second << endl;
            }
            */
            HTTPLatencyList.push_back(rtt);
            unackedHTTPSegs.pop_front();
            break;
        }
        else if (pr.first < httpResponseSeq) {
            unackedHTTPSegs.pop_front();
        }
        else {
            break;
        }
    }
}
