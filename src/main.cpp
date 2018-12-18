// File:  main.cpp
// Date:  9/5/2017
// Auth:  K. Loux
// Desc:  Utility to add IP addresses to Ethernet interfaces.  Allows DHCP and static IPs simultaneously.

// Windows headers
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <IPHlpApi.h>

// Standard C++ headers
#include <iostream>
#include <memory>

int main(int argc, char* argv[])
{
	if (argc != 3)
	{
		std::cout << "Usage:  " << argv[0] << " <IP address> <subnet>" << std::endl;
		return 1;
	}

	UINT iaIPAddress;
	if (inet_pton(AF_INET, argv[1], &iaIPAddress) != 1)
	{
		std::cerr << "Failed to interpret IP address\n";
		return 1;
	}

	UINT iaIPMask;
	if (inet_pton(AF_INET, argv[2], &iaIPMask) != 1)
	{
		std::cerr << "Failed to interpret subnet\n";
		return 1;
	}

	// Before calling AddIPAddress we use GetIpAddrTable to get
	// an adapter to which we can add the IP.
	std::unique_ptr<MIB_IPADDRTABLE> pIPAddrTable(std::make_unique<MIB_IPADDRTABLE>());
	DWORD dwSize(0);
	if (!pIPAddrTable)
	{
		std::cerr << "Failed to allocate IP address table\n";
		return 1;
	}
	else
	{
		// Make an initial call to GetIpAddrTable to get the
		// necessary size into the dwSize variable
		if (GetIpAddrTable(pIPAddrTable.get(), &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER)
		{
			pIPAddrTable = std::unique_ptr<MIB_IPADDRTABLE>(reinterpret_cast<MIB_IPADDRTABLE*>(new char[dwSize]));
			if (!pIPAddrTable)
			{
				std::cerr << "Failed to allocate IP address table (sized)\n";
				return 1;
			}
		}
	}

	// Make a second call to GetIpAddrTable to get the
	// actual data we want
	DWORD dwRetVal(GetIpAddrTable(pIPAddrTable.get(), &dwSize, 0));
	if (dwRetVal != NO_ERROR)
	{
		std::cerr << "GetIPAddrTable failed:  " << dwRetVal << '\n';
		return 1;
	}

	// Save the interface index to use for adding an IP address
	DWORD ifIndex(pIPAddrTable->table[0].dwIndex);
	char strBuf[INET_ADDRSTRLEN];

	std::cout << "\nInterface Index:\t" << ifIndex << '\n';
	std::cout << "IP Address:       \t" << inet_ntop(AF_INET, &pIPAddrTable->table[0].dwAddr, strBuf, sizeof(strBuf)) << " (" << pIPAddrTable->table[0].dwAddr << ")\n";
	std::cout << "Subnet Mask:      \t" << inet_ntop(AF_INET, &pIPAddrTable->table[0].dwMask, strBuf, sizeof(strBuf)) << " (" << pIPAddrTable->table[0].dwMask << ")\n";
	std::cout << "BroadCast Address:\t" << inet_ntop(AF_INET, &pIPAddrTable->table[0].dwBCastAddr, strBuf, sizeof(strBuf)) << " (" << pIPAddrTable->table[0].dwBCastAddr << ")\n";
	std::cout << "Reassembly size:  \t" << pIPAddrTable->table[0].dwReasmSize << '\n' << std::endl;

	ULONG NTEContext = 0;
	ULONG NTEInstance = 0;

	if ((dwRetVal = AddIPAddress(iaIPAddress, iaIPMask, ifIndex, &NTEContext, &NTEInstance)) == NO_ERROR)
	{
		std::cout << "IPv4 address " << argv[1] << " was added successfully\n";
	}
	else
	{
		std::cerr << "AddIPAddress failed with error " << dwRetVal << '\n';

		LPVOID lpMsgBuf;
		if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, dwRetVal, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf, 0, NULL))
		{
			std::cerr << "Error " << static_cast<char*>(lpMsgBuf) << '\n';
			LocalFree(lpMsgBuf);
			return 1;
		}
	}
    
	/*if ((dwRetVal = DeleteIPAddress(NTEContext)) == NO_ERROR)
		std::cout << "IPv4 address " << argv[1] << " was successfully deleted" << std::endl;
	else
	{
		std::cerr << "DeleteIPAddress failed with error:  " << dwRetVal << '\n';
		return 1;
	}*/

	return 0;
}
