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

class SHA2_224 : public SHA2_256Base
{
public:
	SHA2_224()
		: SHA2_256Base(28)
	{
		_name = __func__;
	} // end constructor

	virtual IHash Clone() const
	{
		SHA2_224 HashInstance = SHA2_224();
		HashInstance._state = _state;
		HashInstance._buffer = _buffer.Clone();
		HashInstance._processed_bytes = _processed_bytes;

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<SHA2_224>(HashInstance);
	}

	virtual void Initialize()
	{
		_state[0] = 0xC1059ED8;
		_state[1] = 0x367CD507;
		_state[2] = 0x3070DD17;
		_state[3] = 0xF70E5939;
		_state[4] = 0xFFC00B31;
		_state[5] = 0x68581511;
		_state[6] = 0x64F98FA7;
		_state[7] = 0xBEFA4FA4;

		SHA2_256Base::Initialize();
	} // end function Initialize

protected:
	virtual HashLibByteArray GetResult()
	{
		HashLibByteArray result = HashLibByteArray(7 * sizeof(UInt32));
		Converters::be32_copy(&_state[0], 0, &result[0], 0, (Int32)result.size());

		return result;
	} // end function GetResult
	
}; // end class SHA2_224
