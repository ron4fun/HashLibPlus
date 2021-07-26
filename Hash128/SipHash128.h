///////////////////////////////////////////////////////////////////////
/// SharpHash Library
/// Copyright(c) 2021 Mbadiwe Nnaemeka Ronald
/// Github Repository <https://github.com/ron4fun/HashLibPlus>
///
/// The contents of this file are subject to the
/// Mozilla Public License Version 2.0 (the "License");
/// you may not use this file except in
/// compliance with the License. You may obtain a copy of the License
/// at https://www.mozilla.org/en-US/MPL/2.0/
///
/// Software distributed under the License is distributed on an "AS IS"
/// basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
/// the License for the specific language governing rights and
/// limitations under the License.
///
/// Acknowledgements:
///
/// Thanks to Ugochukwu Mmaduekwe (https://github.com/Xor-el) for his creative
/// development of this library in Pascal/Delphi (https://github.com/Xor-el/HashLib4Pascal).
///
////////////////////////////////////////////////////////////////////////

#pragma once

#include "../Hash64/SipHash64.h"

class SipHash128 : public SipHash
{
protected:
	SipHash128(const Int32 compressionRounds, const Int32 finalizationRounds) 
		: SipHash(16, 8)
	{
		_cr = compressionRounds;
		_fr = finalizationRounds;
	}

	virtual byte GetMagicXor() const { return 0xEE; };

public:
	virtual void Initialize()
	{
		SipHash::Initialize();
		_v1 ^= GetMagicXor();
	}

	virtual IHashResult TransformFinal()
	{
		UInt64 finalBlock = ProcessFinalBlock();
		_v3 ^= finalBlock;
		CompressTimes(_cr);
		_v0 ^= finalBlock;
		_v2 ^= GetMagicXor();
		CompressTimes(_fr);

		HashLibByteArray buffer = HashLibByteArray(GetHashSize());
		Converters::ReadUInt64AsBytesLE(_v0 ^ _v1 ^ _v2 ^ _v3, buffer, 0);
		_v1 ^= 0xDD;
		CompressTimes(_fr);
		Converters::ReadUInt64AsBytesLE(_v0 ^ _v1 ^ _v2 ^ _v3, buffer, 8);
		
		IHashResult result = make_shared<HashResult>(buffer);
		Initialize();
		return result;
	}
};

class SipHash128_2_4 : public SipHash128
{
public:
	SipHash128_2_4() : 
		SipHash128(2, 4)
	{
		_name = __func__;
	}

	virtual IHash Clone() const
	{
		SipHash128_2_4 HashInstance = SipHash128_2_4();
		HashInstance._v0 = _v0;
		HashInstance._v1 = _v1;
		HashInstance._v2 = _v2;
		HashInstance._v3 = _v3;
		HashInstance._key0 = _key0;
		HashInstance._key1 = _key1;
		HashInstance._total_length = _total_length;
		HashInstance._cr = _cr;
		HashInstance._fr = _fr;
		HashInstance._idx = _idx;
		HashInstance._buf = _buf;
		
		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<SipHash128_2_4>(HashInstance);
	}

	virtual IHashWithKey CloneHashWithKey() const
	{
		SipHash128_2_4 HashInstance = SipHash128_2_4();
		HashInstance._v0 = _v0;
		HashInstance._v1 = _v1;
		HashInstance._v2 = _v2;
		HashInstance._v3 = _v3;
		HashInstance._key0 = _key0;
		HashInstance._key1 = _key1;
		HashInstance._total_length = _total_length;
		HashInstance._cr = _cr;
		HashInstance._fr = _fr;
		HashInstance._idx = _idx;
		HashInstance._buf = _buf;

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<SipHash128_2_4>(HashInstance);
	}
};
