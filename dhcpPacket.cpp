#include "dhcpPacket.h"
unsigned int DhcpPacket::magicCookie = 0x63825363;
DhcpPacket::DhcpPacket(unsigned char op, unsigned int transactionId, string clientIpAddr, string offeredIpAddr, string serverIpAddr, string gatewayIpAddr, string clientMacAddr, vector<DhcpOption*> dhcpOptions) {
	this->op = op;
	this->htype = 0x01;
	this->hlen = 0x06;
	this->hops = 0x00;
	this->transactionId = transactionId;
	this->secs = 0x0000;
	this->flags = 0x0000;
	this->clientIpAddr = clientIpAddr;
	this->offeredIpAddr = offeredIpAddr;
	this->serverIpAddr = serverIpAddr;
	this->gatewayIpAddr = gatewayIpAddr;
	this->clientMacAddr = clientIpAddr;
	this->dhcpOptions = dhcpOptions;
}

DhcpPacket DhcpPacket::fromBytes(unsigned char* bytes) {
    unsigned char op = bytes[0];
    unsigned char htype = bytes[1];
    unsigned char hlen = bytes[2];
    unsigned char hops = bytes[3];
    unsigned int transactionId = bytes[4] << 24 + bytes[5] << 16 + bytes[6] << 8 + bytes[7];
    unsigned short int secs = bytes[8] << 8 + bytes[9];
    unsigned short int flags = bytes[10] << 8 + bytes[11];
    string clientIpAddr = utility::ipFromBytes(bytes + 12);
    string offeredIpAddr = utility::ipFromBytes(bytes + 16);
    string serverIpAddr = utility::ipFromBytes(bytes + 20);
    string gatewayIpAddr = utility::ipFromBytes(bytes + 24);
    string clientMacAddr = utility::macFromBytes(bytes+28);
    //client mac address must be padded to 16 bytes
    //192 bytes of 0s; BOOTP legacy.
    //  4 bytes of     magicCookie
    vector<DhcpOption*> dhcpOptions = vector<DhcpOption*>();
    int current = 240;
    while(true){
        if (((DhcpOption*)(bytes + current))->getCode() == End::getCode()) {
            dhcpOptions.push_back(&End::End());
            break;
        }
        dhcpOptions.push_back(&DhcpOption::fromBytes(bytes + current));
        current += 2 + dhcpOptions.back()->getLength();
    }
    return DhcpPacket(op, transactionId, clientIpAddr, offeredIpAddr, serverIpAddr, gatewayIpAddr, clientMacAddr, dhcpOptions);
}
unsigned char* DhcpPacket::toBytes(DhcpPacket dhcpPacket) {
    unsigned char* output = new unsigned char[1];
}
unsigned char DhcpPacket::getMessageType(DhcpPacket dhcpPacket) {
    return DhcpOption::getMessageType(dhcpPacket.dhcpOptions);
}