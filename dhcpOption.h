#pragma once
#include <vector>
#include <stdexcept>
#include "utility.h"
#include <iostream>

using namespace std;

class DhcpOption
{
protected:
    const regex ipAddrRegex = regex("^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$");
    const regex macAddrRegex = regex("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})|([0-9a-fA-F]{4}\\.[0-9a-fA-F]{4}\\.[0-9a-fA-F]{4})$");
    static unsigned char code;
    unsigned char* data;
    unsigned int dataLength;
    static bool isCodeValid(unsigned short int code);
public:
    DhcpOption();
    ~DhcpOption();
    unsigned int getLength();
    static unsigned char getCode();
    static unsigned char getMessageType(vector<DhcpOption*> dhcpOptions);
    static string getRequestedIpAddr(vector<DhcpOption*> dhcpOptions);
    static unsigned int getListLength(vector<DhcpOption*> dhcpOptions);
    static bool hasEnd(vector<DhcpOption*> dhcpOptions);
    static unsigned char* listToBytes(vector<DhcpOption*> dhcpOptions);
    static DhcpOption fromBytes(unsigned char* bytes);
    virtual unsigned char* asBytes();
};
class CustomDhcpOption : public DhcpOption {
public:
    unsigned int code;
    CustomDhcpOption(unsigned int code, unsigned char* data, unsigned int dataLength) {
        this->code = code;
        setData(data, dataLength);
    }
    void setData(unsigned char* data, unsigned int dataLength) {
        this->data = data;
        this->dataLength = dataLength;
    }
    unsigned char* getData() {
        return this->data;
    }
};

//Options from 1 to 255
//1
class SubnetMask : public DhcpOption {
public:
    SubnetMask(string subnetMask) {
        this->code = 1;
        this->dataLength = utility::ipLengthInBytes;
        setData(subnetMask);
    }
    void setData(string subnetMask) {
        if (!regex_match(subnetMask, ipAddrRegex)) {
            throw std::invalid_argument("Subnetmask must be a string like 255.255.255.0");
        }
        if (this->data == nullptr) {
            this->data = new unsigned char[this->dataLength];
        }
        else {
            delete this->data;
            this->data = new unsigned char[this->dataLength];
        }
        this->data = utility::ipToBytes(subnetMask);
    }
    string getData() {
        return utility::ipFromBytes(this->data);
    }
};

//3
class Router : public DhcpOption {
public:
    Router(vector<string> routers) {
        this->code = 3;
        setData(routers);
    }
    void setData(vector<string> routers) {
        this->dataLength = routers.size() * utility::ipLengthInBytes;
        for (int i = 0; i < routers.size(); i++)
        {
            if (!regex_match(routers[i], ipAddrRegex)) {throw std::invalid_argument("Ip address must a string like 192.168.1.1");}
        }
        if (this->data == nullptr) {
            this->data = new unsigned char[this->dataLength];
        }
        else {
            delete this->data;
            this->data = new unsigned char[this->dataLength];
        }
        int j = 0;
        for (int i = 0; i < routers.size(); i++)
        {
             utility::ipToBytes(routers[i], &data[i * utility::ipLengthInBytes]);
        }
        
    }
    vector<string> getData() {
        vector<string> output = vector<string>(this->dataLength/utility::ipLengthInBytes);
        for (int i = 0; i < this->dataLength/utility::ipLengthInBytes; i++)
        {
            output[i] = utility::ipFromBytes(&this->data[i * utility::ipLengthInBytes]);
        }
        return output;
    }
};

//6
class DomainNameServer : public DhcpOption {
public:
    DomainNameServer(vector<string> domainNameServers) {
        this->code = 6;
        setData(domainNameServers);
    }
    void setData(vector<string> domainNameServers) {
        this->dataLength = domainNameServers.size() * utility::ipLengthInBytes;
        for (int i = 0; i < domainNameServers.size(); i++)
        {
            if (!regex_match(domainNameServers[i], ipAddrRegex)) { throw std::invalid_argument("Ip address must a string like 192.168.1.1"); }
        }
        if (this->data == nullptr) {
            this->data = new unsigned char[this->dataLength];
        }
        else {
            delete this->data;
            this->data = new unsigned char[this->dataLength];
        }
        int j = 0;
        for (int i = 0; i < domainNameServers.size(); i++)
        {
            utility::ipToBytes(domainNameServers[i], &data[i * utility::ipLengthInBytes]);
        }

    }
    vector<string> getData() {
        vector<string> output = vector<string>(this->dataLength / utility::ipLengthInBytes);
        for (int i = 0; i < this->dataLength / utility::ipLengthInBytes; i++)
        {
            output[i] = utility::ipFromBytes(&this->data[i * utility::ipLengthInBytes]);
        }
        return output;
    }
};

//12
class ClientHostName : public DhcpOption {
public:
    ClientHostName(string clientHostName) {
        this->code = 12;
        setData(clientHostName);
    }
    void setData(string clientHostName) {
        this->dataLength = clientHostName.size();
        if (this->dataLength == 0 || this->dataLength > 255) {
            throw std::invalid_argument("Host Name must be a string from 1 to 255 characters");
        }
        if (this->data == nullptr) {
            this->data = new unsigned char[this->dataLength];
        }
        else {
            delete this->data;
            this->data = new unsigned char[this->dataLength];
        }
        for (int i = 0; i < this->dataLength; i++)
        {
            this->data[i] = clientHostName[i];
        }

    }
    string getData() {
        string output = string(this->dataLength, ' ');
        for (int i = 0; i < this->dataLength; i++)
        {
            output[i] = this->data[i];
        }
        return output;
    }
};

//50
class RequestedIpAddr : public DhcpOption {
public:
    RequestedIpAddr(string requestedIpAddr) {
        this->code = 50;
        this->dataLength = utility::ipLengthInBytes;
        setData(requestedIpAddr);
    }
    void setData(string requestedIpAddr) {
        if (!regex_match(requestedIpAddr, ipAddrRegex)) {
            throw std::invalid_argument("Subnetmask must be a string like 192.168.1.1");
        }
        if (this->data == nullptr) {
            this->data = new unsigned char[this->dataLength];
        }
        else {
            delete this->data;
            this->data = new unsigned char[this->dataLength];
        }
        this->data = utility::ipToBytes(requestedIpAddr);
    }
    string getData() {
        return utility::ipFromBytes(this->data);
    }
};

//51
class LeaseTime : public DhcpOption {
public:
    LeaseTime(unsigned int leaseTime) {
        this->code = 51;
        this->dataLength = sizeof(unsigned int);
        setData(leaseTime);
    }
    void setData(unsigned int leaseTime) {
        if (this->data == nullptr) {
            this->data = new unsigned char[this->dataLength];
        }
        else {
            delete this->data;
            this->data = new unsigned char[this->dataLength];
        }
        this->data[0] = (leaseTime & 0xff000000) >> 24;
        this->data[1] = (leaseTime & 0x00ff0000) >> 16;
        this->data[2] = (leaseTime & 0x0000ff00) >> 8;
        this->data[3] = (leaseTime & 0x000000ff);
    }
    unsigned int getData() {
        return this->data[0] << 24 + this->data[1] << 16 + this->data[2] << 8 + this->data[3];
    }
};

//53
class MessageType : public DhcpOption {
public:
    //1 DHCPDISCOVER()
    //2 DHCPOFFER()
    //3 DHCPREQUEST()
    //4 DHCPDECLINE()
    //5 DHCPACK()
    //6 DHCPNAK()
    //7 DHCPRELEASE()
    MessageType(unsigned char messageType) {
        this->code = 53;
        this->dataLength = sizeof(unsigned char);
        setData(messageType);
    }
    void setData(unsigned char messageType) {
        if (this->data == nullptr) {
            this->data = new unsigned char[this->dataLength];
        }
        else {
            delete this->data;
            this->data = new unsigned char[this->dataLength];
        }
        *this->data = messageType;
    }
    unsigned char getData() {
        return *this->data;
    }
};

//55

//58

//59

//255
class End : public DhcpOption {
public:
    End() {
        this->code = 255;
        this->dataLength = 0;
        setData();
    }
    void setData() {
    }
    bool getData() {
        return 0;
    }
    unsigned char* asBytes() {
        unsigned char* output = new unsigned char[2 + this->dataLength];
        output[0] = this->code;
        output[1] = this->dataLength;
        return output;
    }
};