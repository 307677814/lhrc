#pragma once

#include <map>
#include <mutex>
#include <sys/types.h>
#include <sys/socket.h>
#include "stdafx.h"

class agent
{
public:
	agent();
	~agent();

	bool inti();

	bool  dowork(tcpHandle* tcphandle,const std::string& firstSPack/*���͸��ƶ˵��װ�*/,
		const std::string& firstAPack/*���͸����ط���˵��װ�*/,const char* sip, int sport,const char* aip,int aport);
private:

	bool sendSocket(SOCKET s, const char* data, int len);

	bool copySocket(SOCKET s1,SOCKET s2);

	bool closeSocket(SOCKET s);
	bool sendHandlePack(SOCKET s, tcpHandle* tcphandle);
	SOCKET getsockete(const char* ip, int port);

};
