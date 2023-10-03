#include <iostream>
#include "dhcpPacket.h"
using namespace std;

int main()
{
	vector<DhcpOption*> v = vector<DhcpOption*>();
	vector<string> routers = vector<string>();
	routers.push_back("192.168.1.254");
	v.push_back(new MessageType(1));
	v.push_back(new SubnetMask("255.255.255.0"));
	v.push_back(new Router(routers));
	v.push_back(new End());
	DhcpPacket p = DhcpPacket(1, 0x3903F326,"0.0.0.0","192.168.1.100","192.168.1.1","0.0.0.0","00:05:3C:04:8D:59",v);
	int length = p.getLength();
	unsigned char* output = p.toBytes();
	for (int i = 0; i < length; i++)
	{
		cout << output[i];
	}
	delete output;
	return 0;
}
