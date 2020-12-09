#include "pch.h"
#include "websocketServer.h"
#include "crypto.h"
bool MakeSecWebSocketAccept(LPCSTR lpszKey, std::string& strAccept)
{
	std::string strKey = lpszKey;
	strKey += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

	_SHA1_CTX ctx;
	BYTE buf[20];
	::sha1_init(&ctx);
	::sha1_update(&ctx, (BYTE*)&strKey[0], strKey.length());
	::sha1_final(&ctx, buf);
	strAccept.clear();
	strAccept.resize(SHA1_BLOCK_SIZE * 4 / 3 + 4);
	int len = (int)::base64_encode(buf, (BYTE*)&strAccept[0], SHA1_BLOCK_SIZE, FALSE);
	strAccept.resize(len);
	return true;
}

websocketServer::websocketServer()
	:m_server(this)
{
}


websocketServer::~websocketServer()
{
}

bool websocketServer::init(tcpServer * server)
{
	std::string p_ip = "0.0.0.0";
	m_server->SetSocketBufferSize(1024*512);
	m_server->Start((WCHAR*)p_ip.c_str(), 5822);
	m_tcpServer = server;
	return true;
}

EnHttpParseResult websocketServer::OnBody(IHttpServer * pSender, CONNID dwConnID, const BYTE * pData, int iLength)
{
	return HPR_OK;
}

EnHandleResult websocketServer::OnClose(ITcpServer * pSender, CONNID dwConnID, EnSocketOperation enOperation, int iErrorCode)
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

EnHttpParseResult websocketServer::OnHeadersComplete(IHttpServer * pSender, CONNID dwConnID)
{
	return HPR_OK;
}

EnHttpParseResult websocketServer::OnMessageComplete(IHttpServer * pSender, CONNID dwConnID)
{
	if (pSender->IsUpgrade(dwConnID))
	{
		return HPR_OK;
	}
	return HPR_OK;
}

EnHttpParseResult websocketServer::OnParseError(IHttpServer * pSender, CONNID dwConnID, int iErrorCode, LPCSTR lpszErrorDesc)
{
	return HPR_OK;
}

EnHttpParseResult websocketServer::OnUpgrade(IHttpServer * pSender, CONNID dwConnID, EnHttpUpgradeType enUpgradeType)
{
	if (enUpgradeType == HUT_HTTP_TUNNEL)
	{
		pSender->SendResponse(dwConnID, HSC_OK, "Connection Established");
	}
	else if (enUpgradeType == HUT_WEB_SOCKET)
	{
		int iHeaderCount = 4;
		THeader header[] = { { "Connection", "Upgrade" },
		{ "Upgrade", "WebSocket" },
		{ nullptr, nullptr },
		{ nullptr, nullptr },
		{ nullptr, nullptr } };

		LPCSTR lpszAccept = nullptr;

		if (!pSender->GetHeader(dwConnID, "Sec-WebSocket-Key", &lpszAccept))
			return HPR_ERROR;

		std::string strAccept;
		::MakeSecWebSocketAccept(lpszAccept, strAccept);

		header[2].name = "Sec-WebSocket-Accept";
		header[2].value = strAccept.c_str();

		header[3].name = "lhwebsocket";
		header[3].value = "HIPSSL";
		LPCSTR lpszProtocol = nullptr;
		if (pSender->GetHeader(dwConnID, "Sec-WebSocket-Protocol", &lpszProtocol))
		{
			int i = 0;
			std::string strProtocol(lpszProtocol);
			i = strProtocol.find(", ");
			if (i > 0)
			{
				strProtocol = strProtocol.substr(0, i);
				header[4].name = "Sec-WebSocket-Protocol";
				header[4].value = strProtocol.c_str();
				++iHeaderCount;
			}
		}
		if (!pSender->SendResponse(dwConnID, HSC_SWITCHING_PROTOCOLS, nullptr, header, iHeaderCount))
		{
			return HPR_ERROR;
			//OnUpgrade(dwConnID, pSender->IsSecure());
		}
	}
	char* p_str = (char*)pSender->GetUrlField(dwConnID, HUF_QUERY);
	if (p_str == NULL)
	{
		return HPR_ERROR;
	}

	int p_index = getContextmapIndex(dwConnID);
	auto p_context = std::make_shared<clientContext>(&(m_cContextLock[p_index]));
	p_context->uri = p_str;
	p_context->clientType = UNDEFINED;
	setContext(dwConnID, p_context);
	return HPR_OK;
}

EnHandleResult websocketServer::OnReceive(ITcpServer * pSender, CONNID dwConnID, int iLength)
{
	return EnHandleResult();
}

EnHandleResult websocketServer::OnReceive(ITcpServer * pSender, CONNID dwConnID, const BYTE * data, int iLength)
{
	return EnHandleResult();
}

EnHandleResult websocketServer::OnWSMessageHeader(IHttpServer * pSender, CONNID dwConnID, BOOL bFinal, BYTE iReserved, BYTE iOperationCode, const BYTE lpszMask[4], ULONGLONG ullBodyLen)
{
	return HR_OK;
}

EnHandleResult websocketServer::OnWSMessageBody(IHttpServer * pSender, CONNID dwConnID, const BYTE * pData, int iLength)
{

	ContextPtr  p_conText = NULL;
	getContext(dwConnID, p_conText);
	if ( p_conText->clientType == UNDEFINED)
	{
		return onConnect(p_conText, pSender, dwConnID, (BYTE*)&(p_conText->uri)[0], p_conText->uri.length()) == HPR_OK ? HR_OK : HR_ERROR;
	}
	return repeatSend(p_conText, pSender, dwConnID, pData, iLength);
}

EnHandleResult websocketServer::OnWSMessageComplete(IHttpServer * pSender, CONNID dwConnID)
{
	return HR_OK;
}

EnHttpParseResult websocketServer::onConnect(ContextPtr & context, IHttpServer * pSender, CONNID dwConnID, const BYTE * data, int iLength)
{
	std::string p_data((char*)data, iLength);
	std::string p_fun = webbase::post(p_data, "fun");
	if (p_fun == "slogin")
	{
		return sLogin(context, p_data, pSender, dwConnID);
	}
	else if (p_fun == "clogin")
	{
		return cLogin(context, p_data, pSender, dwConnID);
	}
	return HPR_ERROR;
}

EnHttpParseResult websocketServer::sLogin(ContextPtr & context, const std::string & data, IHttpServer * pSender, CONNID dwConnID)
{

	std::string p_uname = webbase::post(data, "uname");
	std::string p_psw = "";
	if (p_uname == "")
	{
		return HPR_ERROR;
	}
	if (!context)
	{
		int p_index = getContextmapIndex(dwConnID);
		context = std::make_shared<clientContext>(&(m_cContextLock[p_index]));
		setContext(dwConnID, context);
	}
	context->uname = p_uname;
	int p_e = m_tcpServer->createClient(dwConnID, p_uname,  webbase::post_i(data, "p2p"),1,"",0);
	if (p_e != 0)
	{
		std::string p_str = "fun=p2p_login_end&error=" + ntl::ntoT(p_e);
		m_server->SendWSMessage(dwConnID, TRUE, 0, 0x2, nullptr, (BYTE*)&p_str[0], p_str.length());
		return HPR_OK;
	}
	std::string p_str = "fun=p2p_login_end&error=0";
	return m_server->SendWSMessage(dwConnID, TRUE, 0, 0x2, nullptr, (BYTE*)&p_str[0], p_str.length()) ? HPR_OK : HPR_ERROR;
}

EnHttpParseResult websocketServer::cLogin(ContextPtr & context, const std::string & data, IHttpServer * pSender, CONNID dwConnID)
{
	CONNID p_sid = webbase::post_i(data, "sid");
	if (p_sid == 0)
	{
		return HPR_ERROR;
	}
	std::string p_uname = webbase::post(data, "uname");
	if (p_uname == "")
	{
		return HPR_ERROR;
	}
	ContextPtr  p_conText = NULL;
	if (!getContext(p_sid, p_conText))
	{
		std::string p_str = "fun=p2p_login_end&error=3";
		m_server->SendWSMessage(dwConnID, TRUE, 0, 0x2, nullptr, (BYTE*)&p_str[0], p_str.length());
		return HPR_ERROR;//下線了,或提交數據有誤
	}
	if (!cContext::checkUserinfo(p_conText, p_uname, ""))
	{
		return HPR_ERROR;//改密了,重連了
	}
	int p_ret = webbase::post_i(data, "ret");//沒初始成功;
	if (p_ret != 1)
	{
		m_server->Disconnect(p_sid);
		return HPR_ERROR;
	}
	if (!context)
	{
		int p_index = getContextmapIndex(dwConnID);
		context = std::make_shared<clientContext>(&(m_cContextLock[p_index]));
	}
	context->selfID = dwConnID;
	context->clientType = CCLIENT;
	context->cid = p_sid;
	setContext(dwConnID, context);
	p_conText->cid = dwConnID;
	sendP2PData(p_conText, pSender, webbase::post_i(data, "p2p"));
	return  HPR_OK;
}

EnHandleResult websocketServer::sClose(ContextPtr & context, IHttpServer * pSender, CONNID dwConnID)
{
	ContextPtr p_ccontext;
	if (!getContext(context->cid, p_ccontext))
	{
		return HR_OK;
	}
	m_server->Disconnect(context->cid);
	int p_clientNum = cContext::delSid(p_ccontext, dwConnID);
	char p_temp[64] = {};
	sprintf_s(p_temp, sizeof(p_temp), "fun=work&clientNum=%u", p_clientNum);
	//sendData(pSender, context->cid, (BYTE*)p_temp, strlen(p_temp));
	return HR_OK;
}

EnHandleResult websocketServer::cClose(ContextPtr & context, IHttpServer * pSender, CONNID dwConnID)
{
	pSender->Disconnect(context->cid);

	return HR_OK;
}

EnHandleResult websocketServer::sendP2PData(ContextPtr & context, IHttpServer * pSender, int p2p)
{
	char p_temp[128] = {};
	char p_ip[32] = {};
	int p_ipLen = 32;
	USHORT p_port = 0;
	int p_retMakr = rand();
	if (p2p)
	{
		if (!pSender->GetRemoteAddress(context->selfID, (wchar_t*)p_ip, p_ipLen, p_port))
		{
			return HR_ERROR;
		}
	}
	sprintf_s(p_temp, sizeof(p_temp), "fun=p2p_login_ret&remote_ip=%s&remote_port=%u&c&ret_mark=%d&p2p=%d", p_ip, (UINT)p_port, p_retMakr, p2p);
	pSender->SendWSMessage(context->cid, TRUE, 0, 0x2, nullptr, (BYTE*)p_temp, strlen(p_temp));
	p_ipLen = 32;
	if (!pSender->GetRemoteAddress(context->cid, (wchar_t*)p_ip, p_ipLen, p_port))
	{
		return HR_ERROR;
	}
	ZeroMemory(p_temp, sizeof(p_temp));
	sprintf_s(p_temp, sizeof(p_temp), "fun=p2p_login_ret&remote_ip=%s&remote_port=%u&s&ret_mark=%d&p2p=%d", p_ip, (UINT)p_port, p_retMakr, p2p);
	return  pSender->SendWSMessage(context->selfID, TRUE, 0, 0x2, nullptr, (BYTE*)p_temp, strlen(p_temp)) ? HR_OK : HR_ERROR;
}

EnHandleResult websocketServer::sendData(IHttpServer * pSender, CONNID dwConnID, BYTE * data, int iLength)
{
	return EnHandleResult();
}

EnHandleResult websocketServer::repeatSend(ContextPtr & context, IHttpServer * pSender, CONNID dwConnID, const BYTE * data, int iLength)
{
	if (context->cid == 0)
	{
		printf("cid null[%d]\r\n", context->selfID.load());
		return HR_ERROR;//下线了
	}
	/*
	iReserved		-- RSV1/RSV2/RSV3 各 1 位
	*			iOperationCode	-- 操作码：0x0 - 0xF
	*			lpszMask		-- 掩码（nullptr 或 4 字节掩码，如果为 nullptr 则没有掩码）
	*			pData			-- 消息体数据缓冲区
	*			iLength			-- 消息体数据长度
	*			ullBodyLen		-- 消息总长度
	*/

	if (context->sendLen == 0)
	{
		BOOL lpbFinal = FALSE;
		BYTE iReserved = 0;
		BYTE iOperationCode = 0;
		const BYTE* lpszMask = NULL;
		ULONGLONG pbodyLen = 0;
		ULONGLONG lpullBodyRemain = 0;
		m_server->GetWSMessageState(dwConnID, &lpbFinal, &iReserved, &iOperationCode, &lpszMask, &pbodyLen, &lpullBodyRemain);
		context->sendLen = pbodyLen - iLength;
		return m_server->SendWSMessage(context->cid, lpbFinal, 0, iOperationCode, nullptr, (BYTE*)data, iLength, pbodyLen) ? HR_OK : HR_ERROR;
	}

	context->sendLen -= iLength;
	if (m_server->Send(context->cid, (BYTE*)data, iLength))
	{
		return HR_OK;
	}
	return HR_ERROR;
}