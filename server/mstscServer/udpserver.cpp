#include "pch.h"
#include "udpserver.h"
#include "base/crpyto/rc4.h"
#include "rsaMgr.h"


udpServer::udpServer()
	:m_server(this)
{

}

udpServer::~udpServer()
{
}

bool udpServer::init(tcpServer * tcpserver)
{
	m_tcpServer = tcpserver;
	std::string p_ip = "0.0.0.0";
	m_server->SetSendPolicy(SP_DIRECT);
	m_server->SetMaxDatagramSize(1520);
	m_server->SetDetectAttempts(0);
	m_server->SetDetectInterval(0);
	m_server->SetMarkSilence(TRUE);
	std::thread(&udpServer::checkSilence, this).detach();
	return (m_server->Start((WCHAR*)p_ip.c_str(), 5821))==TRUE;
}

bool udpServer::checkSilence()
{
	while (true)
	{
		Sleep(30000);
		m_server->DisconnectSilenceConnections(30000, TRUE);
	}
	return false;
}

EnHandleResult udpServer::OnReceive(IUdpServer * pSender, CONNID dwConnID, const BYTE * data, int iLength)
{
	if (iLength < 5)
	{
		return HR_ERROR;
	}
	switch (data[0])
	{
	case server_head::server_repeat: return onTurnSend(pSender, dwConnID, data, iLength);
	case server_head::server_rsa: return onRsaData(pSender, dwConnID, data, iLength);
	case server_head::server_rc4: return onRC4Data(pSender, dwConnID, data, iLength);
	}
	return HR_ERROR;
}

EnHandleResult udpServer::OnHandShake(IUdpServer * pSender, CONNID dwConnID)
{
	return HR_OK;
}

EnHandleResult udpServer::OnClose(IUdpServer * pSender, CONNID dwConnID, EnSocketOperation enOperation, int iErrorCode)
{
	ContextPtr p_conText;
	if (!getContext(dwConnID, p_conText))
	{
		return HR_OK;
	}
	delContext(dwConnID);
	if (p_conText->cid != 0)
	{
		m_server->Disconnect(p_conText->cid);
	}
	return HR_OK;
}

EnHandleResult udpServer::onRsaData(IUdpServer* pSender, CONNID dwConnID, const BYTE* data, int iLength)
{
	if (iLength <= 5)
	{
		return HR_ERROR;
	}
	ContextPtr  p_conText = NULL;
	if (getContext(dwConnID, p_conText))
	{
		return sendRecvData(pSender, dwConnID, "ok", 2, p_conText->safeLinkRetid, p_conText->rc4psw);
	}
	std::string p_str;
	if (!g_rsaMgr.decode((char*)data + 1, iLength - 1, p_str))
	{
		return HR_ERROR;
	}
	if (p_str.length() <= 5)
	{
		return HR_ERROR;
	}
	if (p_str[0] == SEND_WAIT)
	{
		ContextPtr  p_conText = NULL;
		return onRecv(pSender,dwConnID, p_str, p_conText);
	}
	return HR_ERROR;
}

EnHandleResult udpServer::onRC4Data(IUdpServer* pSender, CONNID dwConnID, const BYTE* data, int iLength)
{
	if (iLength <= 5)
	{
		return HR_ERROR;
	}
	ContextPtr  p_conText = NULL;
	if (!getContext(dwConnID, p_conText))
	{
		return HR_OK;
	}
	std::string p_str((char*)data + 1, iLength - 1);
	rc4::encrypt(&p_str[0], p_str.length(), p_conText->rc4psw.c_str(), p_conText->rc4psw.length());
	if (p_str[0] == SEND_WAIT)
	{
		return onRecv(pSender, dwConnID, p_str, p_conText);
	}
	return HR_ERROR;
}

EnHandleResult udpServer::onRecv(IUdpServer* pSender, CONNID dwConnID, const std::string& data, ContextPtr& context)
{
	DWORD p_retid;
	memcpy(&p_retid, &data[1], 4);
	std::string p_func = webbase::post(data, "func", false);
	if (p_func == "makeSafeLink")
	{
		return onMakeSafeLink(pSender, dwConnID, data, p_retid);
	}
	else if(p_func=="sloginv3")
	{
		return onSloginV3(pSender, dwConnID, data, p_retid, context);
	}
	else if (p_func == "cloginv3")
	{
		return onCloginV3(pSender, dwConnID, data, p_retid, context);
	}
	return EnHandleResult();
}

EnHandleResult udpServer::onMakeSafeLink(IUdpServer* pSender, CONNID dwConnID, const std::string& data,DWORD retid)
{
	ContextPtr  p_conText = NULL;
	if (!getContext(dwConnID, p_conText))
	{
		int p_index = getContextmapIndex(dwConnID);
		p_conText = std::make_shared<clientContext>(&(m_cContextLock[p_index]));
		setContext(dwConnID, p_conText);
	}
	p_conText->rc4psw = webbase::post(data, "psw", false);
	if (p_conText->rc4psw.length() < 4 || p_conText->rc4psw.length() > 256)
	{
		return HR_ERROR;
	}
	p_conText->safeLinkRetid = retid;
	return sendRecvData(pSender, dwConnID, "ok", 2, retid, p_conText->rc4psw);
}

EnHandleResult udpServer::onSloginV3(IUdpServer* pSender, CONNID dwConnID, const std::string& data, DWORD retid, ContextPtr& context)
{
	std::string p_ret;
	if (context->islogin)
	{
		if (context->cid)
		{
			char p_ip[32] = {};
			int p_ipLen = 32;
			USHORT p_port = 0;
			pSender->GetRemoteAddress(context->cid, (wchar_t*)p_ip, p_ipLen, p_port);
			p_ret = "status=1&cid=" + ntl::ntoT((UINT)context->cid.load())+ "&cip=";
			p_ret += p_ip;
			p_ret += "&cport=" + ntl::ntoT(p_port);
			p_ret += context->rsacode;
			return sendRecvData(pSender, dwConnID, p_ret.c_str(), p_ret.length(), retid, context->rc4psw);
		}
		return HR_OK;
	}
	std::string p_uname = webbase::post(data, "uname");
	if (p_uname == "")
	{
		return HR_ERROR;
	}
	context->selfID = dwConnID;
	context->clientType = SCLIENT;
	context->uname = p_uname;
	char p_ip[32] = {};
	int p_ipLen = 32;
	USHORT p_port = 0;
	pSender->GetRemoteAddress(dwConnID, (wchar_t*)p_ip, p_ipLen, p_port);
	int p_e = m_tcpServer->createClient(dwConnID, p_uname, webbase::post_i(data, "p2p"), 0,p_ip,p_port);
	if (p_e != L_LOGIN)
	{
		p_ret = "status=" + ntl::ntoT(p_e);
		return sendRecvData(pSender, dwConnID, p_ret.c_str(), p_ret.length(), retid, context->rc4psw);
	}
	context->islogin = true;
	return HR_OK;
}

EnHandleResult udpServer::onCloginV3(IUdpServer* pSender, CONNID dwConnID, const std::string& data, DWORD retid, ContextPtr& context)
{
	std::string p_ret;

	if (context->islogin)
	{
		char p_ip[32] = {};
		int p_ipLen = 32;
		USHORT p_port = 0;
		pSender->GetRemoteAddress(context->cid, (wchar_t*)p_ip, p_ipLen, p_port);
		p_ret = "status=1&cip=";
		p_ret += p_ip;
		p_ret += "&cport=" + ntl::ntoT(p_port);
		return sendRecvData(pSender, dwConnID, p_ret.c_str(), p_ret.length(), retid, context->rc4psw);
	}
	CONNID p_sid = webbase::post_i(data, "sid");
	if (p_sid == 0)
	{
		return HR_ERROR;
	}

	std::string p_uname = webbase::post(data, "uname");
	if (p_uname == "")
	{
		return HR_ERROR;
	}
	ContextPtr  p_conText = NULL;
	if (!getContext(p_sid, p_conText))
	{
		p_ret = "status=5";
		return sendRecvData(pSender, dwConnID, p_ret.c_str(), p_ret.length(), retid, context->rc4psw);
		return HR_ERROR;//下線了,或提交數據有誤
	}
	if (!cContext::checkUserinfo(p_conText, p_uname, ""))
	{
		p_ret = "status=5";
		return sendRecvData(pSender, dwConnID, p_ret.c_str(), p_ret.length(), retid, context->rc4psw);
		return HR_ERROR;//改密了,重連了
	}
	context->selfID = dwConnID;
	context->clientType = CCLIENT;
	context->cid = p_sid;
	setContext(dwConnID, context);
	size_t p_index = data.find("&seed=");
	if (p_index == std::string::npos)
	{
		p_ret = "status=7";
	}
	else
	{
		char p_ip[32] = {};
		int p_ipLen = 32;
		USHORT p_port = 0;
		pSender->GetRemoteAddress(p_sid, (wchar_t*)p_ip, p_ipLen, p_port);
		p_ret = "status=1&cip=";
		p_ret += p_ip;
		p_ret += "&cport=" + ntl::ntoT(p_port);
		p_conText->rsacode = data.substr(p_index);
	}
	p_conText->cid = dwConnID;
	if (sendRecvData(pSender, dwConnID, p_ret.c_str(), p_ret.length(), retid, context->rc4psw)== HR_OK)
	{
		context->islogin = true;
		return HR_OK;
	}
	return HR_ERROR;
}

EnHandleResult udpServer::onTurnSend(IUdpServer* pSender, CONNID dwConnID, const BYTE* data, int iLength)
{
	DWORD* p_cid = (DWORD*)(data + 1);
	pSender->Send(*p_cid, data, iLength);
	return HR_OK;
}




EnHandleResult udpServer::sendRecvData(IUdpServer* pSender, CONNID dwConnID, const char* data, int len, DWORD retid,std::string& psw)
{
	std::string p_data;
	p_data.resize(len + 5);
	p_data[0] = server_ret;
	memcpy(&p_data[5], data, len);
	memcpy(&p_data[1], &retid, 4);
	rc4::encrypt(&p_data[1],p_data.length(),psw.c_str(),psw.length());
	if (pSender->Send(dwConnID, (BYTE*)&p_data[0], len + 5))
	{
		return HR_OK;
	}
	return HR_ERROR;
}


