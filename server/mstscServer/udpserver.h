#pragma once

#include "tcpServer.h"

struct clientInfo
{
	CONNID	cid;
	char	rc4Psw[128];
};

class udpServer :
	CUdpServerListener, 
	serverBase
{
public:
	udpServer();
	~udpServer();
	bool init(tcpServer* tcpserver);
private:
	bool checkSilence();

	
	EnHandleResult	OnHandShake(IUdpServer* pSender, CONNID dwConnID);
	EnHandleResult	OnReceive(IUdpServer* pSender, CONNID dwConnID, const BYTE * data, int iLength);
	EnHandleResult	OnClose(IUdpServer* pSender, CONNID dwConnID, EnSocketOperation enOperation, int iErrorCode);

	EnHandleResult	onRsaData(IUdpServer* pSender, CONNID dwConnID, const BYTE* data, int iLength);
	EnHandleResult	onRC4Data(IUdpServer* pSender, CONNID dwConnID, const BYTE* data, int iLength);
	EnHandleResult	onRecv(IUdpServer* pSender, CONNID dwConnID, const std::string& data, ContextPtr& context);
	EnHandleResult	onMakeSafeLink(IUdpServer* pSender, CONNID dwConnID, const std::string& data,DWORD retid);
	EnHandleResult	onSloginV3(IUdpServer* pSender, CONNID dwConnID, const std::string& data, DWORD retid, ContextPtr& context);
	EnHandleResult	onCloginV3(IUdpServer* pSender, CONNID dwConnID, const std::string& data, DWORD retid, ContextPtr& context);
	EnHandleResult	onTurnSend(IUdpServer* pSender, CONNID dwConnID, const BYTE* data, int iLength);
	EnHandleResult	sendRecvData(IUdpServer* pSender, CONNID dwConnID, const char* data,int len, DWORD retid, std::string& psw);

	

	tcpServer*		m_tcpServer;
	CUdpServerPtr	m_server;

};

