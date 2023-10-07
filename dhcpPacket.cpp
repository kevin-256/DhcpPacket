#include "dhcpPacket.h"
unsigned int DhcpPacket::magicCookie = 0x63825363;
DhcpPacket::DhcpPacket() {
    initPacket(0, 0, "0.0.0.0", "0.0.0.0", "0.0.0.0", "0.0.0.0", "00:00:00:00:00:00", vector<DhcpOption*>());
}
void DhcpPacket::initPacket(unsigned char op, unsigned int transactionId, string clientIpAddr, string offeredIpAddr, string serverIpAddr, string gatewayIpAddr, string clientMacAddr, vector<DhcpOption*>dhcpOptions) {
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
    this->clientMacAddr = clientMacAddr;
    if (DhcpOption::getMessageType(dhcpOptions) == 0) {
        throw std::invalid_argument("packet must have a type");
    }
    else if (!DhcpOption::hasEnd(dhcpOptions)) {
        dhcpOptions.push_back(new End());
    }
    this->dhcpOptions = dhcpOptions;
}
DhcpPacket::DhcpPacket(unsigned char op, unsigned int transactionId, string clientIpAddr, string offeredIpAddr, string serverIpAddr, string gatewayIpAddr, string clientMacAddr, vector<DhcpOption*>dhcpOptions) {
    initPacket(op, transactionId, clientIpAddr, offeredIpAddr, serverIpAddr, gatewayIpAddr, clientMacAddr, dhcpOptions);
}
DhcpPacket::~DhcpPacket() {
    while (!dhcpOptions.empty()) {
        dhcpOptions.back()->~DhcpOption();
        //delete dhcpOptions.back();
        dhcpOptions.pop_back();
    }
}

DhcpPacket* DhcpPacket::fromBytes(unsigned char* bytes) {
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
    string clientMacAddr = utility::macFromBytes(bytes+28);//client mac address is padded to 16 bytes
    //192 bytes of 0s; BOOTP legacy.
    //  4 bytes of     magicCookie
    vector<DhcpOption*> dhcpOptions = vector<DhcpOption*>();
    int current = 240;
    while(true){
        if (((DhcpOption*)(bytes + current))->getCode() == 255) {
            dhcpOptions.push_back(new End());
            break;
        }
        dhcpOptions.push_back(DhcpOption::fromBytes(bytes + current));
        current += 2 + dhcpOptions.back()->getLength();
    }
    return new DhcpPacket(op, transactionId, clientIpAddr, offeredIpAddr, serverIpAddr, gatewayIpAddr, clientMacAddr, dhcpOptions);
}
unsigned char* DhcpPacket::toBytes(DhcpPacket& dhcpPacket, unsigned char* output) {
    if (output == nullptr) return nullptr;
    unsigned char* current = output;
    *current = dhcpPacket.op;
    current += 1;
    *current = dhcpPacket.htype;
    current += 1;
    *current = dhcpPacket.hlen;
    current += 1;
    *current = dhcpPacket.hops;
    current += 1;
    current[0] = (dhcpPacket.transactionId & 0xff000000) >> 24;
    current[1] = (dhcpPacket.transactionId & 0x00ff0000) >> 16;
    current[2] = (dhcpPacket.transactionId & 0x0000ff00) >> 8;
    current[3] = (dhcpPacket.transactionId & 0x000000ff);
    current += 4;
    current[0]  = (dhcpPacket.secs & 0x0000ff00) >> 8;
    current[1]  = (dhcpPacket.secs & 0x000000ff);
    current += 2;
    current[0] = (dhcpPacket.flags  & 0x0000ff00) >> 8;
    current[1] = (dhcpPacket.flags & 0x000000ff);
    current += 2;
    utility::ipToBytes(dhcpPacket.clientIpAddr, current);
    current += 4;
    utility::ipToBytes(dhcpPacket.offeredIpAddr, current);
    current += 4;
    utility::ipToBytes(dhcpPacket.serverIpAddr, current);
    current += 4;
    utility::ipToBytes(dhcpPacket.gatewayIpAddr, current);
    current += 4;
    utility::macToBytes(dhcpPacket.clientMacAddr, current);
    current += 6;
    //useless padding of mac address + useless bootp legacy
    for (int i = 0; i < 10+192; i++)
    {
        current[i] = 0x00;
    }
    current += 10+192;
    current[0] = (dhcpPacket.magicCookie & 0xff000000) >> 24;
    current[1] = (dhcpPacket.magicCookie & 0x00ff0000) >> 16;
    current[2] = (dhcpPacket.magicCookie & 0x0000ff00) >> 8;
    current[3] = (dhcpPacket.magicCookie & 0x000000ff);
    current += 4;
    DhcpOption::listToBytes(dhcpPacket.dhcpOptions, current);
    return output;
 }
unsigned char* DhcpPacket::toBytes(DhcpPacket& dhcpPacket) {
    return toBytes(dhcpPacket, new unsigned char[dhcpPacket.getLength()]);
}
unsigned char DhcpPacket::getMessageType(DhcpPacket dhcpPacket) {
    return DhcpOption::getMessageType(dhcpPacket.dhcpOptions);
}
unsigned int DhcpPacket::getLength() {
    return 240 + DhcpOption::getListLengthInBytes(this->dhcpOptions);
}
unsigned char* DhcpPacket::toBytes() {
    return toBytes(*this, new unsigned char[this->getLength()]);
}