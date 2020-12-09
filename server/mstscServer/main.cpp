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
	//开源代码不公布 当前版本的私钥
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

