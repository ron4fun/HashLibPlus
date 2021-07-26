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

#include "SHA2_512Base.h"

class SHA2_512_256 : public SHA2_512Base
{
public:
	SHA2_512_256()
		: SHA2_512Base(32)
	{
		_name = __func__;
	} // end constructor

	virtual IHash Clone() const
	{
		SHA2_512_256 HashInstance = SHA2_512_256();
		HashInstance._state = _state;
		HashInstance._buffer = _buffer.Clone();
		HashInstance._processed_bytes = _processed_bytes;

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<SHA2_512_256>(HashInstance);
	}

	virtual void Initialize()
	{
		_state[0] = 0x22312194FC2BF72C;
		_state[1] = 0x9F555FA3C84C64C2;
		_state[2] = 0x2393B86B6F53B151;
		_state[3] = 0x963877195940EABD;
		_state[4] = 0x96283EE2A88EFFE3;
		_state[5] = 0xBE5E1E2553863992;
		_state[6] = 0x2B0199FC2C85B8AA;
		_state[7] = 0x0EB72DDC81C52CA2;

		SHA2_512Base::Initialize();
	} // end function Initialize

protected:
	virtual HashLibByteArray GetResult()
	{
		HashLibByteArray result = HashLibByteArray(4 * sizeof(UInt64));
		Converters::be64_copy(&_state[0], 0, &result[0], 0, (Int32)result.size());

		return result;
	} // end function GetResult

}; // end class SHA2_512_256
