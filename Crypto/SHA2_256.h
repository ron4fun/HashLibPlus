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

#include "SHA2_256Base.h"

class SHA2_256 : public SHA2_256Base
{
public:
	SHA2_256()
		: SHA2_256Base(32)
	{
		_name = __func__;
	} // end constructor

	virtual IHash Clone() const
	{
		SHA2_256 HashInstance = SHA2_256();
		HashInstance._state = _state;
		HashInstance._buffer = _buffer.Clone();
		HashInstance._processed_bytes = _processed_bytes;

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<SHA2_256>(HashInstance);
	}

	virtual void Initialize()
	{
		_state[0] = 0x6A09E667;
		_state[1] = 0xBB67AE85;
		_state[2] = 0x3C6EF372;
		_state[3] = 0xA54FF53A;
		_state[4] = 0x510E527F;
		_state[5] = 0x9B05688C;
		_state[6] = 0x1F83D9AB;
		_state[7] = 0x5BE0CD19;

		SHA2_256Base::Initialize();
	} // end function Initialize

protected:
	virtual HashLibByteArray GetResult()
	{
		HashLibByteArray result = HashLibByteArray(8 * sizeof(UInt32));
		Converters::be32_copy(&_state[0], 0, &result[0], 0, (Int32)result.size());

		return result;
	} // end function GetResult

}; // end class SHA2_256
