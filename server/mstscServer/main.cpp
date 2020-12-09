#include "pch.h"
#include "tcpServer.h"
#include "udpserver.h"
#include "websocketServer.h"
#include "rsaMgr.h"







int main()
{
	tcpServer g_tcpServer;
	udpServer g_udpServer;
	websocketServer g_webServer;
	//��Դ���벻���� ��ǰ�汾��˽Կ
	g_rsaMgr.init();
	g_tcpServer.init();
	g_udpServer.init(&g_tcpServer);
	g_webServer.init(&g_tcpServer);
	while (true)
	{
		//printf("cnum:%d\r", g_server.getClientNum());
		Sleep(5000);
	}
	return 1;
}

