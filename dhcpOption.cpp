#include "dhcpOption.h"
//const unsigned char DhcpOption::code = 0;
DhcpOption::DhcpOption(){
    this->data = nullptr;
}
DhcpOption::~DhcpOption() {
    if (this->data != nullptr) {
        delete [] this->data;
    }
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
        if (dhcpOptions[i]->getCode() == 53) {
            return ((MessageType*)dhcpOptions[i])->getData();
        }
    }
    return 0;
}

string DhcpOption::getRequestedIpAddr(vector<DhcpOption*> dhcpOptions) {
    for (int i = 0; i < dhcpOptions.size(); i++)
    {
        if (dhcpOptions[i]->getCode() == 50) {
            return ((RequestedIpAddr*)dhcpOptions[i])->getData();
        }
    }
    return "";
}

unsigned int DhcpOption::getListLengthInBytes(vector<DhcpOption*> dhcpOptions) {
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
        if (dhcpOptions[i]->getCode() == 255) {
            return true;
        }
    }
    return false;
}

unsigned char* DhcpOption::listToBytes(vector<DhcpOption*> dhcpOptions, unsigned char* output) {
    if (output == nullptr) return nullptr;
    unsigned int position = 0;
    for (int i = 0; i < dhcpOptions.size(); i++)
    {
        dhcpOptions[i]->asBytes(output+ position);
        position+=dhcpOptions[i]->getLength()+2;
    }
    return output;
}
unsigned char* DhcpOption::listToBytes(vector<DhcpOption*> dhcpOptions) {
    return listToBytes(dhcpOptions, new unsigned char[getListLengthInBytes(dhcpOptions)]);
}

DhcpOption* DhcpOption::fromBytes(unsigned char* bytes) {
    switch (bytes[0])
    {
        case 1:
            return (DhcpOption*)new SubnetMask(utility::ipFromBytes(bytes + 2));
        case 3:
        {
            vector<string> routers = vector<string>(bytes[1] / utility::ipLengthInBytes);
            for (int i = 0; i < bytes[1] / utility::ipLengthInBytes; i++)
            {
                routers.push_back(utility::ipFromBytes((bytes + 2) + (i * utility::ipLengthInBytes)));
            }
            return (DhcpOption*)new Router(routers);
        }
        case 6:
        {
            vector<string> domainNameServers = vector<string>(bytes[1] / utility::ipLengthInBytes);
            for (int i = 0; i < bytes[1] / utility::ipLengthInBytes; i++)
            {
                domainNameServers.push_back(utility::ipFromBytes((bytes + 2) + (i * utility::ipLengthInBytes)));
            }
            return (DhcpOption*)new DomainNameServer(domainNameServers);
        }
        case 12:
        {
            string clientHostName = string(bytes[1], ' ');
            for (int i = 0; i < bytes[1]; i++)
            {
                clientHostName[i] = bytes[2 + i];
            }
            return (DhcpOption*)new ClientHostName(clientHostName);
        }
        case 50:
            return (DhcpOption*)new RequestedIpAddr(utility::ipFromBytes(bytes + 2));
        case 51:
            return (DhcpOption*)new LeaseTime((unsigned int)(bytes[2] << 24 + bytes[3] << 16 + bytes[4] << 8 + bytes[5]));
        case 53:
            return (DhcpOption*)new MessageType(bytes[2]);
        case 255:
            return (DhcpOption*)new End();
        default:
        {
            unsigned int code = bytes[0];
            unsigned int dataLength = bytes[1];
            unsigned char* data = new unsigned char[dataLength];
            for (size_t i = 0; i < dataLength; i++)
            {
                data[i] = bytes[2 + i];
            }
            return (DhcpOption*)new CustomDhcpOption(code, data, dataLength);
        }

    }
};
unsigned char* DhcpOption::asBytes(unsigned char* output) {
    output[0] = this->code;
    output[1] = (unsigned char)dataLength;
    for (int i = 0; i < dataLength; i++)
    {
        output[i+2] = data[i];
    }
    return output;
}

unsigned char* DhcpOption::asBytes() {
    return asBytes(new unsigned char[2 + this->dataLength]);
}