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
    vector<DhcpOption*>dhcpOptions;
    DhcpPacket();
    void initPacket(unsigned char op, unsigned int transactionId, string clientIpAddr, string offeredIpAddr, string serverIpAddr, string gatewayIpAddr, string clientMacAddr, vector<DhcpOption*>dhcpOptions);
public:
    DhcpPacket(unsigned char op, unsigned int transactionId, string clientIpAddr, string offeredIpAddr, string serverIpAddr, string gatewayIpAddr, string clientMacAddr, vector<DhcpOption*>dhcpOptions);
    ~DhcpPacket();
    static DhcpPacket* fromBytes(unsigned char* bytes);
    static unsigned char* toBytes(DhcpPacket& dhcpPacket, unsigned char* output);
    static unsigned char* toBytes(DhcpPacket& dhcpPacket);
    static unsigned char getMessageType(DhcpPacket dhcpPacket);
    unsigned char* toBytes();
    unsigned int getLength();
};

//1     DHCPDISCOVER
class DhcpPacketDiscover : public DhcpPacket {
public:
    DhcpPacketDiscover(unsigned int transactionId, string clientIpAddr, string offeredIpAddr, string serverIpAddr, string gatewayIpAddr, string clientMacAddr, vector<DhcpOption*>dhcpOptions) {
        switch (DhcpOption::getMessageType(dhcpOptions))//add message type or change it if is wrong
        {
        case 0:
            dhcpOptions.push_back(new MessageType(1));
            break;
        case 1:
            break;
        default:
            for (int i = 0; i < dhcpOptions.size(); i++)
            {
                if (dhcpOptions[i]->getCode() == 53) {
                    ((MessageType*)dhcpOptions[i])->setData(0x01);
                }
            }
        }
        initPacket(1, transactionId, clientIpAddr, offeredIpAddr, serverIpAddr, gatewayIpAddr, clientMacAddr, dhcpOptions);
    }
};
//2	    DHCPOFFER
class DhcpPacketOffer : public DhcpPacket {

public:
    DhcpPacketOffer(unsigned int transactionId, string clientIpAddr, string offeredIpAddr, string serverIpAddr, string gatewayIpAddr, string clientMacAddr, vector<DhcpOption*>dhcpOptions) {
        switch (DhcpOption::getMessageType(dhcpOptions))//add message type or change it if is wrong
        {
        case 0:
            dhcpOptions.push_back(new MessageType(1));
            break;
        case 2:
            break;
        default:
            for (int i = 0; i < dhcpOptions.size(); i++)
            {
                if (dhcpOptions[i]->getCode() == 53) {
                    ((MessageType*)dhcpOptions[i])->setData(0x02);
                }
            }
        }
        initPacket(2, transactionId, clientIpAddr, offeredIpAddr, serverIpAddr, gatewayIpAddr, clientMacAddr, dhcpOptions);
    }
};
//3	    DHCPREQUEST
class DhcpPacketRequest : public DhcpPacket {

public:
    DhcpPacketRequest(unsigned int transactionId, string clientIpAddr, string offeredIpAddr, string serverIpAddr, string gatewayIpAddr, string clientMacAddr, vector<DhcpOption*>dhcpOptions) {
        switch (DhcpOption::getMessageType(dhcpOptions))//add message type or change it if is wrong
        {
        case 0:
            dhcpOptions.push_back(new MessageType(1));
            break;
        case 3:
            break;
        default:
            for (int i = 0; i < dhcpOptions.size(); i++)
            {
                if (dhcpOptions[i]->getCode() == 53) {
                    ((MessageType*)dhcpOptions[i])->setData(0x03);
                }
            }
        }
        initPacket(1, transactionId, clientIpAddr, offeredIpAddr, serverIpAddr, gatewayIpAddr, clientMacAddr, dhcpOptions);
    }
};
//4	    DHCPDECLINE
class DhcpPacketDecline : public DhcpPacket {

public:
    DhcpPacketDecline(unsigned int transactionId, string clientIpAddr, string offeredIpAddr, string serverIpAddr, string gatewayIpAddr, string clientMacAddr, vector<DhcpOption*>dhcpOptions) {
        switch (DhcpOption::getMessageType(dhcpOptions))//add message type or change it if is wrong
        {
        case 0:
            dhcpOptions.push_back(new MessageType(1));
            break;
        case 4:
            break;
        default:
            for (int i = 0; i < dhcpOptions.size(); i++)
            {
                if (dhcpOptions[i]->getCode() == 53) {
                    ((MessageType*)dhcpOptions[i])->setData(0x04);
                }
            }
        }
        initPacket(1, transactionId, clientIpAddr, offeredIpAddr, serverIpAddr, gatewayIpAddr, clientMacAddr, dhcpOptions);
    }
};
//5	    DHCPACK
class DhcpPacketAck : public DhcpPacket {

public:
    DhcpPacketAck(unsigned char op, unsigned int transactionId, string clientIpAddr, string offeredIpAddr, string serverIpAddr, string gatewayIpAddr, string clientMacAddr, vector<DhcpOption*>dhcpOptions) {
        switch (DhcpOption::getMessageType(dhcpOptions))//add message type or change it if is wrong
        {
        case 0:
            dhcpOptions.push_back(new MessageType(1));
            break;
        case 5:
            break;
        default:
            for (int i = 0; i < dhcpOptions.size(); i++)
            {
                if (dhcpOptions[i]->getCode() == 53) {
                    ((MessageType*)dhcpOptions[i])->setData(0x05);
                }
            }
        }
        initPacket(op, transactionId, clientIpAddr, offeredIpAddr, serverIpAddr, gatewayIpAddr, clientMacAddr, dhcpOptions);
    }
};
//6	    DHCPNAK
class DhcpPacketNak : public DhcpPacket {

public:
    DhcpPacketNak(unsigned int transactionId, string clientIpAddr, string offeredIpAddr, string serverIpAddr, string gatewayIpAddr, string clientMacAddr, vector<DhcpOption*>dhcpOptions) {
        switch (DhcpOption::getMessageType(dhcpOptions))//add message type or change it if is wrong
        {
        case 0:
            dhcpOptions.push_back(new MessageType(1));
            break;
        case 6:
            break;
        default:
            for (int i = 0; i < dhcpOptions.size(); i++)
            {
                if (dhcpOptions[i]->getCode() == 53) {
                    ((MessageType*)dhcpOptions[i])->setData(0x06);
                }
            }
        }
        initPacket(2, transactionId, clientIpAddr, offeredIpAddr, serverIpAddr, gatewayIpAddr, clientMacAddr, dhcpOptions);
    }
};
//7	    DHCPRELEASE
class DhcpPacketRelease : public DhcpPacket {

public:
    DhcpPacketRelease(unsigned int transactionId, string clientIpAddr, string offeredIpAddr, string serverIpAddr, string gatewayIpAddr, string clientMacAddr, vector<DhcpOption*>dhcpOptions) {
        switch (DhcpOption::getMessageType(dhcpOptions))//add message type or change it if is wrong
        {
        case 0:
            dhcpOptions.push_back(new MessageType(1));
            break;
        case 7:
            break;
        default:
            for (int i = 0; i < dhcpOptions.size(); i++)
            {
                if (dhcpOptions[i]->getCode() == 53) {
                    ((MessageType*)dhcpOptions[i])->setData(0x07);
                }
            }
        }
        initPacket(1, transactionId, clientIpAddr, offeredIpAddr, serverIpAddr, gatewayIpAddr, clientMacAddr, dhcpOptions);
    }
};
//8	    DHCPINFORM
//9	    DHCPFORCERENEW
//10	DHCPLEASEQUERY
//11	DHCPLEASEUNASSIGNED
//12	DHCPLEASEUNKNOWN
//13	DHCPLEASEACTIVE
//14	DHCPBULKLEASEQUERY
//15	DHCPLEASEQUERYDONE
//16	DHCPACTIVELEASEQUERY
//17	DHCPLEASEQUERYSTATUS
//18	DHCPTLS