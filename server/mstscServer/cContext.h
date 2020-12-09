#pragma once
#include <atomic>
#include <windows.h>
#include <memory>
#include <map>
#include <mutex>
#include "pch.h"

#define CONTEXT_BUFF_LENGTH   1024*410
#define CONTEXT_LOCK_NUM	  8
enum CTYPE
{
	UNDEFINED = 0,
	SCLIENT = 1, //主控端
	CCLIENT = 2, //被控端
};

struct clientContext
{
	std::atomic<CONNID>		cid;			//對端id
	std::atomic<CONNID>		selfID;			//当前对像id
	DWORD					safeLinkRetid;
	CTYPE		clientType;
	std::atomic<bool>		islogin;
	std::string uname;
	std::string rc4psw;
	std::string uri;
	std::string rsacode;
	int			sendLen;
	std::mutex*	lock;
	clientContext(std::mutex* lock_)
	{
		this->lock = lock_;
		sendLen = 0;
		selfID = 0;
		cid = 0;
		clientType = UNDEFINED;
		islogin = false;
	};
	~clientContext()
	{

	}

};
typedef std::shared_ptr<clientContext> ContextPtr;
namespace cContext
{
	void setUserInfo(ContextPtr& c, const std::string& user, const std::string& psw);
	bool checkUserinfo(ContextPtr& c, const std::string& user, const std::string& psw);
	void setSid(ContextPtr& c, CONNID sid);
	bool getSids(ContextPtr& c, CONNID* sid, int& sidNum);
	int  delSid(ContextPtr& c, CONNID sid);
};

