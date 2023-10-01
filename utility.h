#pragma once
#include <string>
#include <regex>

using namespace std;

class utility
{
public:
    //all length are in bytes
    static const unsigned short ipLengthInBytes = 4, macLengthInBytes = 6;
    static constexpr char const hexmap[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
    static string ipFromBytes(unsigned char* bytes) {
        string output = "";
        for (int i = 0; i < ipLengthInBytes; i++)
        {
            output += to_string((unsigned char)bytes[i]) + '.';
        }
        return output.substr(0, output.size() - 1);
    };
    static unsigned char* ipToBytes(string ipAddr, unsigned char* output) {
        if (!regex_match(ipAddr, regex("^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$"))) {
            throw std::invalid_argument("Ip must be a string like 192.168.1.1");
        }
        int i = 0;
        int j = 0;
        string currentNumber = "";
        if (output == nullptr) return nullptr;
        while (ipAddr[i] != '\0') {
            if (ipAddr[i] == '.') {
                output[j] = (unsigned char)stoi(currentNumber);
                j++;
                currentNumber = "";
            }
            else {
                currentNumber += ipAddr[i];
            }
            i++;
        }
        output[j] = (unsigned char)stoi(currentNumber);
        return output;
    };
    static unsigned char* ipToBytes(string ipAddr) {
        return ipToBytes(ipAddr, new unsigned char[ipLengthInBytes]);
    };
    static string macFromBytes(unsigned char* bytes) {
        string output = "";
        for (int i = 0; i < macLengthInBytes; i++)
        {
            output += string(1, hexmap[(short)bytes[i] >> 4]) + string(1, hexmap[(short)bytes[i] & 0x0f]) + ':';
        }
        return output.substr(0, output.size() - 1);
    };
    static unsigned char* macToBytes(string macAddr, unsigned char* output) {
        if (!regex_match(macAddr, regex("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})|([0-9a-fA-F]{4}\\.[0-9a-fA-F]{4}\\.[0-9a-fA-F]{4})$"))) {
            throw std::invalid_argument("Mac Address must be a string like 00:00:00:00:00");
        }
        if (output == nullptr) return nullptr;
        for (int i = 0; i < macLengthInBytes; i++)
        {
            output[i] = (stoi(string(1, tolower(macAddr[i * 3])), nullptr, 16) << 4) + stoi(string(1, tolower(macAddr[(i * 3) + 1])), nullptr, 16);
        }
        return output;
    };
    static unsigned char* macToBytes(string macAddr) {
        return macToBytes(macAddr, new unsigned char[macLengthInBytes]);
    };
};

