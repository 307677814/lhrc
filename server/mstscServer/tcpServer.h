#pragma once
#include <map>
#include <mutex>
#include <vector>
#include <atomic>
#include <functional>
#include "cContext.h"
#include "../../HPSocket/HPSocket.h"

class serverBase
{
public:

	virtual ~serverBase();
protected:
	CONNID	getMappingID(const std::string& name);
	bool	setMappingID(const std::string& name, CONNID cid);
	bool	delMappingID(const std::string& name);

	bool	getContext(const CONNID dwConnID, ContextPtr& ret);
	bool	setContext(const CONNID dwConnID, const ContextPtr ret);
	bool	delContext(const CONNID dwConnID);

	int		getContextmapIndex(const CONNID dwConnID);

	std::mutex		m_mappingLock;
	std::mutex		m_contextMapLock[CONTEXT_LOCK_NUM];
	std::mutex		m_cContextLock[CONTEXT_LOCK_NUM];
	std::map<std::string, CONNID> m_connMap;
	std::map<CONNID, ContextPtr>  m_context[CONTEXT_LOCK_NUM];
};


class tcpServer :
	CTcpServerListener
{


public:
	tcpServer();
	~tcpServer();
	bool init();
	//type 0=udp 1=websocket
	LOGIN_STATUS createClient(CONNID sid, const std::string& cName, int p2p,int type, const std::string& cip, int cport);//0=正常 1=用户不存在 2=发送失败
private:
	EnHandleResult cLogin(ITcpServer* pSender,const std::string & data, CONNID dwConnID);
	EnHandleResult cClose(ITcpServer* pSender,const std::string & data, CONNID dwConnID);


	CONNID  getConn(const std::string& key);
	bool	getConnPsw(CONNID id, std::string& psw);
	bool	setConn(ITcpServer* pSender,const std::string& key, CONNID id,const std::string& psw);
	bool	delConn(const std::string& key);
	bool	delConn(CONNID id);

	EnHandleResult createClientRet(CONNID dwConnID, const std::string& data);

	EnHandleResult OnPrepareListen(ITcpServer* pSender, SOCKET soListen);
	EnHandleResult OnAccept(ITcpServer* pSender, CONNID dwConnID, UINT_PTR soClient);
	EnHandleResult OnHandShake(ITcpServer* pSender, CONNID dwConnID);
	EnHandleResult OnReceive(ITcpServer* pSender, CONNID dwConnID, int iLength);
	EnHandleResult OnReceive(ITcpServer* pSender, CONNID dwConnID, const BYTE* data, int iLength);
	EnHandleResult OnClose(ITcpServer* pSender, CONNID dwConnID, EnSocketOperation enOperation, int iErrorCode);

	CTcpPackServerPtr					m_server;
	std::mutex							m_connMapLock;
	std::map<std::string, CONNID>		m_connMap;
	std::map<CONNID, std::string>		m_connPsw;
};
