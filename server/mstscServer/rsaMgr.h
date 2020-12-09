#pragma once
#include <string>
#include "base/crpyto/rsa.h"
#include "base/crpyto/randpool.h"



#define rsakeylen 2048
typedef unsigned char byte;

class rsaMgr
{
public:
	rsaMgr();
	~rsaMgr();
	bool init();
	bool decode(const char* data, int datalen, std::string& ret);

private:
	uint64_t	m_fixedLen;
	std::string m_rsaPrivetKey;
	std::string m_rsaSeed;
	CryptoPP::RSAES_OAEP_SHA_Decryptor m_dec;
	CryptoPP::RandomPool m_randomPool;

};

extern rsaMgr g_rsaMgr;


