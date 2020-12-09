#include "pch.h"
#include "rsaMgr.h"

rsaMgr::rsaMgr()
{
}

rsaMgr::~rsaMgr()
{
}

bool rsaMgr::init()
{
	ntl::readFile((ntl::getRunPath() + "\\privetkey.txt").c_str(), m_rsaPrivetKey);
	ntl::readFile((ntl::getRunPath() + "\\seed.txt").c_str(), m_rsaSeed);
	int p_len = 0;
	m_rsaPrivetKey = webbase::BaseDecode(m_rsaPrivetKey.c_str(), m_rsaPrivetKey.length(), p_len);

	CryptoPP::ArraySource keyArr((byte*)&m_rsaPrivetKey[0], m_rsaPrivetKey.length(), true);
	m_dec.AccessKey().Load(keyArr);
	m_fixedLen = m_dec.FixedCiphertextLength();
	m_randomPool.IncorporateEntropy((byte*)&m_rsaSeed[0], m_rsaSeed.length());
	return true;
}

bool rsaMgr::decode(const char* data, int datalen, std::string& ret)
{
	if (datalen % m_fixedLen != 0)
	{
		return false;
	}
	if (ret.length() < rsakeylen)
	{
		ret.resize(rsakeylen);
	}
	else
	{
		ret.resize(datalen);
	}
	uint64_t putLen = 0;
	size_t p_retLen = ret.length();
	byte* p_retAddr = (byte*)&ret[0];
	byte* p_dataAddr = (byte*)&data[0];
	size_t p_len = 0;
	int p_packNum = 0;
	try
	{
		for (uint64_t i = 0; i < datalen; i += m_fixedLen)
		{
			p_len = m_fixedLen < (datalen - i) ? m_fixedLen : (datalen - i);
			CryptoPP::ArraySink* dstArr = new CryptoPP::ArraySink(p_retAddr + putLen, (size_t)(p_retLen - putLen));
			CryptoPP::ArraySource source(p_dataAddr + i, p_len, true, new CryptoPP::PK_DecryptorFilter(m_randomPool, m_dec, dstArr));
			putLen += dstArr->TotalPutLength();
			//ArraySource Œˆππª· Õ∑≈
		}
	}
	catch (const std::exception&)
	{
		return false;
	}

	ret.resize(putLen);
	return true;
}


rsaMgr g_rsaMgr;