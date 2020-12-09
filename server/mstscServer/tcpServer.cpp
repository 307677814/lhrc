#include "pch.h"
#include "tcpServer.h"
#include "rsaMgr.h"
#include "base/crpyto/rc4.h"

tcpServer::tcpServer()
	:m_server(this)
{
}

tcpServer::~tcpServer()
{
}

bool tcpServer::init()
{
	std::string p_ip = "0.0.0.0";
	m_server->SetKeepAliveTime(20 * 1000);
	m_server->SetMarkSilence(true);
	return m_server->Start((WCHAR*)p_ip.c_str(), 5821);
}

LOGIN_STATUS tcpServer::createClient(CONNID sid, const std::string& cName, int p2p, int type,const std::string& cip,int cport)
{
	CONNID p_uid = getConn(cName);
	if (p_uid == 0)
	{
		return L_NO_USER;
	}
	std::string p_psw;
	getConnPsw(p_uid, p_psw);
	if (p_psw.empty())
	{
		return L_NO_USER;
	}
	auto ntot = [](UINT n)
	{
		std::string re;
		char str[13];
		sprintf_s(str, sizeof(str), "%u", n);
		re = str;
		return re;
	};
	std::string p_str;
	p_str = "fun=create_client&uname=" + cName + "&sid=" + ntot(sid) + "&type=" + ntot(type);
	if (p2p)
	{
		p_str += "&p2p=1";
	}
	rc4::encrypt(&p_str[0], p_str.length(), p_psw.c_str(), p_psw.length());
	if (m_server->Send(p_uid, (BYTE*)&p_str[0], p_str.length()))
	{
		return L_LOGIN;
	}
	return L_NO_USER;
}


EnHandleResult tcpServer::cLogin(ITcpServer* pSender, const std::string& data, CONNID dwConnID)
{
	std::string p_uname = webbase::post(data, "uname", false);
	if (p_uname.length() > 32 || p_uname.length() < 4)
	{
		return HR_ERROR;
	}
	std::string p_psw = webbase::post(data, "psw", false);
	if (setConn(pSender, p_uname, dwConnID, p_psw))
	{
		return HR_OK;
	}
	return HR_ERROR;
}

EnHandleResult tcpServer::cClose(ITcpServer* pSender,const std::string & data, CONNID dwConnID)
{
	return EnHandleResult();
}

bool tcpServer::getConnPsw(CONNID id,std::string& psw)
{
	std::lock_guard<std::mutex>p_lock(m_connMapLock);
	auto p_it = m_connPsw.find(id);
	if (p_it == m_connPsw.end())
	{
		return false;
	}
	psw= p_it->second;
	return true;
}

CONNID tcpServer::getConn(const std::string & key)
{
	std::lock_guard<std::mutex>p_lock(m_connMapLock);
	auto p_it = m_connMap.find(key);
	if (p_it == m_connMap.end())
	{
		return 0;
	}
	return p_it->second;
}

bool tcpServer::setConn(ITcpServer* pSender,const std::string & key, CONNID id, const std::string& psw)
{
	if (psw.length() < 4 || psw.length() > 31)
	{
		return false;
	}
	std::lock_guard<std::mutex>p_lock(m_connMapLock);
	m_connMap[key] = id;
	m_connPsw[id] = psw;
	return true;
}

bool tcpServer::delConn(const std::string& key)
{
	std::lock_guard<std::mutex>p_lock(m_connMapLock);
	auto p_it = m_connMap.find(key);
	if (p_it == m_connMap.end())
	{
		return true;
	}
	m_connPsw.erase(p_it->second);
	m_connMap.erase(p_it);
	return true;
}

bool tcpServer::delConn(CONNID id)
{
	std::lock_guard<std::mutex>p_lock(m_connMapLock);
	m_connPsw.erase(id);
	for (auto it : m_connMap)
	{
		if (it.second == id)
		{
			m_connMap.erase(it.first);
			return true;
		}
	}
	return false;
}

EnHandleResult tcpServer::createClientRet(CONNID dwConnID, const std::string & data)
{
	CONNID p_sid = webbase::post_i(data, "sid");
	if (p_sid == 0)
	{
		return HR_ERROR;
	}
	// m_createCallBack(p_sid, dwConnID);
	return HR_OK;
}

EnHandleResult tcpServer::OnPrepareListen(ITcpServer * pSender, SOCKET soListen)
{
	return HR_OK;
}

EnHandleResult tcpServer::OnAccept(ITcpServer * pSender, CONNID dwConnID, UINT_PTR soClient)
{
	pSender->SetConnectionExtra(dwConnID, nullptr);
	return HR_OK;
}

EnHandleResult tcpServer::OnHandShake(ITcpServer * pSender, CONNID dwConnID)
{
	return HR_OK;
}

EnHandleResult tcpServer::OnReceive(ITcpServer * pSender, CONNID dwConnID, int iLength)
{

	return HR_OK;
}

EnHandleResult tcpServer::OnReceive(ITcpServer * pSender, CONNID dwConnID, const BYTE * data, int iLength)
{
	if (iLength < 4)
	{
		return HR_ERROR;
	}

	std::string p_str;
	if (data[0] == 0)
	{
		g_rsaMgr.decode((char*)data + 1, iLength - 1, p_str);
	}
	else
	{	
		std::string p_psw;
		if (getConnPsw(dwConnID,p_psw))
		{
			return HR_ERROR;
		}
		p_str.append((char*)data + 1, iLength - 1);
		rc4::encrypt(&p_str[0], p_str.length(), p_psw.c_str(), p_psw.length());
	}

	std::string p_fun = webbase::post(p_str, "fun");
	if (p_fun == "create_client")
	{
		return createClientRet(dwConnID, p_str);
	}
	else if (p_fun == "clogin")
	{
		return  cLogin(pSender,p_str, dwConnID);
	}
	return HR_OK;
}

EnHandleResult tcpServer::OnClose(ITcpServer * pSender, CONNID dwConnID, EnSocketOperation enOperation, int iErrorCode)
{
	void* p_str=nullptr;
	pSender->GetConnectionExtra(dwConnID, &p_str);
	if (p_str)
	{
		delete (char*)p_str;
	}
	delConn(dwConnID);
	return HR_OK;
}



serverBase::~serverBase()
{
}

CONNID serverBase::getMappingID(const std::string & name)
{
	std::lock_guard<std::mutex> lock(m_mappingLock);
	auto p_client = m_connMap.find(name);
	if (p_client == m_connMap.end())
	{
		return 0;
	}
	return p_client->second;
}
bool serverBase::setMappingID(const std::string & name, CONNID cid)
{
	std::lock_guard<std::mutex> lock(m_mappingLock);
	auto p_client = m_connMap.find(name);
	if (p_client != m_connMap.end())
	{
		return false;
	}
	m_connMap[name] = cid;
	return true;
}
bool serverBase::delMappingID(const std::string & name)
{
	std::lock_guard<std::mutex> lock(m_mappingLock);
	auto p_client = m_connMap.find(name);
	if (p_client != m_connMap.end())
	{
		m_connMap.erase(p_client);
	}
	return true;
}
bool serverBase::getContext(const CONNID dwConnID, ContextPtr & ret)
{
	int p_lockIndex = getContextmapIndex(dwConnID);
	std::lock_guard<std::mutex> lock(m_contextMapLock[p_lockIndex]);
	auto p_ret = m_context[p_lockIndex].find(dwConnID);
	if (p_ret == m_context[p_lockIndex].end())
	{
		return false;
	}
	ret = p_ret->second;
	return true;
}
bool serverBase::setContext(const CONNID dwConnID, const ContextPtr ret)
{
	int p_lockIndex = getContextmapIndex(dwConnID);
	std::lock_guard<std::mutex> lock(m_contextMapLock[p_lockIndex]);
	m_context[p_lockIndex][dwConnID] = ret;
	return true;
}
bool serverBase::delContext(const CONNID dwConnID)
{
	int p_lockIndex = getContextmapIndex(dwConnID);
	std::lock_guard<std::mutex> lock(m_contextMapLock[p_lockIndex]);
	m_context[p_lockIndex].erase(dwConnID);
	return true;
}

int serverBase::getContextmapIndex(const CONNID dwConnID)
{
	return dwConnID % CONTEXT_LOCK_NUM;
}
