#pragma once

#include <map>
#include <mutex>
#include <vector>
#include <atomic>
#include <functional>
#include "cContext.h"
#include "tcpServer.h"
#include "../../HPSocket/HPSocket.h"

class websocketServer :
	CHttpServerListener,
	serverBase
{
public:
	websocketServer();
	~websocketServer();
	bool init(tcpServer* server);
private:
	EnHttpParseResult	OnBody(IHttpServer* pSender, CONNID dwConnID, const BYTE* pData, int iLength);
	EnHandleResult		OnClose(ITcpServer* pSender, CONNID dwConnID, EnSocketOperation enOperation, int iErrorCode);
	EnHttpParseResult	OnHeadersComplete(IHttpServer* pSender, CONNID dwConnID);
	EnHttpParseResult	OnMessageComplete(IHttpServer* pSender, CONNID dwConnID);
	EnHttpParseResult	OnParseError(IHttpServer* pSender, CONNID dwConnID, int iErrorCode, LPCSTR lpszErrorDesc);
	EnHttpParseResult	OnUpgrade(IHttpServer* pSender, CONNID dwConnID, EnHttpUpgradeType enUpgradeType);
	EnHandleResult		OnReceive(ITcpServer* pSender, CONNID dwConnID, int iLength);
	EnHandleResult		OnReceive(ITcpServer* pSender, CONNID dwConnID, const BYTE* data, int iLength);

	EnHandleResult		OnWSMessageHeader(IHttpServer* pSender, CONNID dwConnID, BOOL bFinal, BYTE iReserved, BYTE iOperationCode, const BYTE lpszMask[4], ULONGLONG ullBodyLen);
	EnHandleResult		OnWSMessageBody(IHttpServer* pSender, CONNID dwConnID, const BYTE* pData, int iLength);
	EnHandleResult		OnWSMessageComplete(IHttpServer* pSender, CONNID dwConnID);


	EnHttpParseResult onConnect(ContextPtr&  context, IHttpServer * pSender, CONNID dwConnID, const BYTE* data, int iLength);
	EnHttpParseResult sLogin(ContextPtr& context, const std::string& data, IHttpServer* pSender, CONNID dwConnID);
	EnHttpParseResult cLogin(ContextPtr& context, const std::string & data, IHttpServer * pSender, CONNID dwConnID);
	EnHandleResult sClose(ContextPtr& context, IHttpServer * pSender, CONNID dwConnID);
	EnHandleResult cClose(ContextPtr& context, IHttpServer * pSender, CONNID dwConnID);

	EnHandleResult sendP2PData(ContextPtr& context, IHttpServer * pSender, int p2p);
	EnHandleResult sendData(IHttpServer * pSender, CONNID dwConnID, BYTE * data, int iLength);
	EnHandleResult repeatSend(ContextPtr& context, IHttpServer* pSender, CONNID dwConnID, const BYTE* data, int iLength);


	std::mutex			m_loginLock;
	tcpServer*			m_tcpServer;
	CHttpServerPtr		m_server;
};

