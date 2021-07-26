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

class SHA2_512 : public SHA2_512Base
{
public:
	SHA2_512()
		: SHA2_512Base(64)
	{
		_name = __func__;
	} // end constructor

	virtual IHash Clone() const
	{
		SHA2_512 HashInstance = SHA2_512();
		HashInstance._state = _state;
		HashInstance._buffer = _buffer.Clone();
		HashInstance._processed_bytes = _processed_bytes;

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<SHA2_512>(HashInstance);
	}

	virtual void Initialize()
	{
		_state[0] = 0x6A09E667F3BCC908;
		_state[1] = 0xBB67AE8584CAA73B;
		_state[2] = 0x3C6EF372FE94F82B;
		_state[3] = 0xA54FF53A5F1D36F1;
		_state[4] = 0x510E527FADE682D1;
		_state[5] = 0x9B05688C2B3E6C1F;
		_state[6] = 0x1F83D9ABFB41BD6B;
		_state[7] = 0x5BE0CD19137E2179;

		SHA2_512Base::Initialize();
	} // end function Initialize

protected:
	virtual HashLibByteArray GetResult()
	{
		HashLibByteArray result = HashLibByteArray(8 * sizeof(UInt64));
		Converters::be64_copy(&_state[0], 0, &result[0], 0, (Int32)result.size());

		return result;
	} // end function GetResult

}; // end class SHA2_512
