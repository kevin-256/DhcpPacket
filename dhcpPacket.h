#pragma once
#include "dhcpOption.h"

class DhcpPacket
{
protected:
    unsigned char op;
    unsigned char htype;
    unsigned char hlen;
    unsigned char hops;
    unsigned int transactionId;
    unsigned short int secs;
    unsigned short int flags;
    string clientIpAddr;
    string offeredIpAddr;
    string serverIpAddr;
    string gatewayIpAddr;
    string clientMacAddr;
    //client mac address must be padded to 16 bytes
    //192 octets of 0s; BOOTP legacy.
    static unsigned int magicCookie;
    vector<DhcpOption*> dhcpOptions;
public:
    DhcpPacket(unsigned char op, unsigned int transactionId, string clientIpAddr, string offeredIpAddr, string serverIpAddr, string gatewayIpAddr, string clientMacAddr, vector<DhcpOption*> dhcpOptions);
    static DhcpPacket* fromBytes(unsigned char* bytes);
    static unsigned char* toBytes(DhcpPacket dhcpPacket, unsigned char* output);
    static unsigned char* toBytes(DhcpPacket dhcpPacket);
    static unsigned char getMessageType(DhcpPacket dhcpPacket);
    unsigned char* toBytes();
    unsigned int getLength();
};