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

#include "../Base/HashCryptoNotBuildIn.h"

class MDBase : public BlockHash, public virtual IICryptoNotBuildIn
{
public:
	virtual void Initialize()
	{
		_state[0] = 0x67452301;
		_state[1] = 0xEFCDAB89;
		_state[2] = 0x98BADCFE;
		_state[3] = 0x10325476;

		BlockHash::Initialize();
	} // end function Initialize

protected:

	MDBase(const Int32 a_state_length, const Int32 a_hash_size)
		: BlockHash(a_hash_size, 64)
	{
		_state.resize(a_state_length);
	} // end constructor

	~MDBase()
	{} // end destructor

	virtual HashLibByteArray GetResult()
	{
		HashLibByteArray result = HashLibByteArray(_state.size() * sizeof(UInt32));

		Converters::le32_copy(&_state[0], 0, &result[0], 0, (Int32)_state.size() * sizeof(UInt32));

		return result;
	} // end function GetResult

	virtual void Finish()
	{
		UInt64 bits;
		Int32 padindex;

		bits = _processed_bytes * 8;
		if (_buffer.GetPos() < 56)
			padindex = 56 - _buffer.GetPos();
		else
			padindex = 120 - _buffer.GetPos();

		HashLibByteArray pad = HashLibByteArray((size_t)padindex + 8);

		pad[0] = 0x80;

		bits = Converters::le2me_64(bits);

		Converters::ReadUInt64AsBytesLE(bits, pad, padindex);

		padindex = padindex + 8;

		TransformBytes(pad, 0, padindex);

	} // end function Finish

protected:
	static const UInt32 C1 = 0x50A28BE6;
	static const UInt32 C2 = 0x5A827999;
	static const UInt32 C3 = 0x5C4DD124;
	static const UInt32 C4 = 0x6ED9EBA1;
	static const UInt32 C5 = 0x6D703EF3;
	static const UInt32 C6 = 0x8F1BBCDC;
	static const UInt32 C7 = 0x7A6D76E9;
	static const UInt32 C8 = 0xA953FD4E;

	HashLibUInt32Array _state;

}; // end class MDBase
