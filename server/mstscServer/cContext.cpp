#include "pch.h"
#include "cContext.h"

void cContext::setUserInfo(ContextPtr & c, const std::string & user, const std::string & psw)
{
	c->lock->lock();
	c->uname = user;
	c->lock->unlock();
}

bool cContext::checkUserinfo(ContextPtr & c, const std::string & user, const std::string & psw)
{
	std::lock_guard<std::mutex> lock(*(c->lock));
	return (c->uname == user);
}

void cContext::setSid(ContextPtr & c, CONNID sid)
{

}

bool cContext::getSids(ContextPtr & c, CONNID * sid, int & sidNum)
{
	sidNum = 0;
	return false;
}

int cContext::delSid(ContextPtr & c, CONNID sid)
{
	return 0;
}

