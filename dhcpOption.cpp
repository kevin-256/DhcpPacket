#include "dhcpOption.h"
unsigned char DhcpOption::code = 0;
DhcpOption::DhcpOption(){
    this->data = nullptr;
}
DhcpOption::~DhcpOption() {
    delete[] this->data;
}

bool DhcpOption::isCodeValid(unsigned short int code) {
    if (code < 1 || code>254) {
        return true;
    }
    return false;
}

unsigned int DhcpOption::getLength() {
    return dataLength;
}

unsigned char DhcpOption::getCode() {
    return code;
}

unsigned char DhcpOption::getMessageType(vector<DhcpOption*> dhcpOptions) {
    for (int i = 0; i < dhcpOptions.size(); i++)
    {
        if (dhcpOptions[i]->getCode() == MessageType::getCode()) {
            return ((MessageType*)dhcpOptions[i])->getData();
        }
    }
    return 0;
}

string DhcpOption::getRequestedIpAddr(vector<DhcpOption*> dhcpOptions) {
    for (int i = 0; i < dhcpOptions.size(); i++)
    {
        if (dhcpOptions[i]->getCode() == RequestedIpAddr::getCode()) {
            return ((RequestedIpAddr*)dhcpOptions[i])->getData();
        }
    }
    return "";
}

unsigned int getListLength(vector<DhcpOption*> dhcpOptions) {
    unsigned int output = 0;
    for (int i = 0; i < dhcpOptions.size(); i++)
    {
        output += dhcpOptions[i]->getLength() + 2;
    }
    return output;
}

bool DhcpOption::hasEnd(vector<DhcpOption*> dhcpOptions) {
    for (int i = 0; i < dhcpOptions.size(); i++)
    {
        if (dhcpOptions[i]->getCode() == End::getCode()) {
            return true;
        }
    }
    return false;
}

unsigned char* DhcpOption::listToBytes(vector<DhcpOption*> dhcpOptions) {
    unsigned int totalLength = 1;
    for (int i = 0; i < dhcpOptions.size() - 1; i++)
    {
        totalLength += dhcpOptions[i]->getLength() + 2;
    }
    unsigned char* output = new unsigned char(totalLength);
    unsigned int j = 0;
    for (int i = 0; i < dhcpOptions.size(); i++)
    {
        unsigned char* optionAsBytes = dhcpOptions[i]->asBytes();
        for (int l = 0; l < dhcpOptions[i]->getLength(); l++, j++)
        {
            output[j] = optionAsBytes[l];
        }
    }
    return output;
}

DhcpOption DhcpOption::fromBytes(unsigned char* bytes) {
    switch (bytes[0])
    {
        case 1:
            return SubnetMask(utility::ipFromBytes(bytes + 2));
        case 3:
        {
            vector<string> routers = vector<string>(bytes[1] / utility::ipLengthInBytes);
            for (int i = 0; i < bytes[1] / utility::ipLengthInBytes; i++)
            {
                routers.push_back(utility::ipFromBytes((bytes + 2) + (i * utility::ipLengthInBytes)));
            }
            return Router(routers);
        }
        case 6:
        {
            vector<string> domainNameServers = vector<string>(bytes[1] / utility::ipLengthInBytes);
            for (int i = 0; i < bytes[1] / utility::ipLengthInBytes; i++)
            {
                domainNameServers.push_back(utility::ipFromBytes((bytes + 2) + (i * utility::ipLengthInBytes)));
            }
            return DomainNameServer(domainNameServers);
        }
        case 12:
        {
            string clientHostName = string(bytes[1], ' ');
            for (int i = 0; i < bytes[1]; i++)
            {
                clientHostName[i] = bytes[2 + i];
            }
            return ClientHostName(clientHostName);
        }
        case 50:
            return RequestedIpAddr(utility::ipFromBytes(bytes + 2));
        case 51:
            return LeaseTime((unsigned int)(bytes[2] << 24 + bytes[3] << 16 + bytes[4] << 8 + bytes[5]));
        case 53:
            return MessageType(bytes[2]);
        case 255:
            return End();
        default:
        {
            unsigned int code = bytes[0];
            unsigned int dataLength = bytes[1];
            unsigned char* data = new unsigned char[dataLength];
            for (size_t i = 0; i < dataLength; i++)
            {
                data[i] = bytes[2 + i];
            }
            return CustomDhcpOption(code, data, dataLength);
        }

    }
};

unsigned char* DhcpOption::asBytes() {
    unsigned char* output = new unsigned char(2 + this->dataLength);
    output[0] = code;
    output[1] = dataLength;
    for (int i = 2; i < dataLength + 2; i++)
    {
        output[i] = data[i];
    }
    return output;
}