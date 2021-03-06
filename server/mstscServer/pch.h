// 入门提示: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件

#ifndef PCH_H
#define PCH_H

// TODO: 添加要在此处预编译的标头





#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#elif defined(_MSC_VER)
#pragma warning(disable : 4996)
#endif


typedef enum server_head
{
	server_rsa,
	server_rc4,
	server_repeat,
	server_ret
};



enum LOGIN_STATUS
{
	L_NOMER = 0,
	L_LOGIN = 1,
	L_PSW_ERROE = 2,
	L_TIMEOUT = 3,
	L_SYS_ERROR = 4,
	L_NO_USER,
	L_HEAD_END
};
typedef enum PACK_MARK
{
	//客户端
	SEND_WAIT = 0,		// 同步發送
	SEND_WAIT_RET = 1,	// 回應同步發送
};





#include "../../HPSocket/HPSocket.h"
#include "publib/lib/baselib_ntl/bin/v1.0.0.1001/include/baselib_ntl.h"

#ifdef _DEBUG
#pragma comment(lib,"../../base/crpyto/lib/cryptlib_d.lib")
#pragma comment(lib,"publib/lib/baselib_ntl/bin/v1.0.0.1001/lib/ntl_D.lib")
//#pragma comment(lib,"../../HPSocket/HPSocket_D.lib")
#pragma comment(lib,"publib/lib/hpsocket/include/static/HPSocket_D.lib")
//#pragma comment(lib,"publib/lib///NETLOG/v1.0.0.1001/bin///NETLOG_d.lib")
#else
#pragma comment(lib,"../../base/crpyto/lib/cryptlib.lib")
#pragma comment(lib,"publib/lib/hpsocket/include/static/HPSocket.lib")
#pragma comment(lib,"publib/lib/baselib_ntl/bin/v1.0.0.1001/lib/ntl.lib")
//#pragma comment(lib,"../../HPSocket/HPSocket.lib")
#endif

#endif //PCH_H