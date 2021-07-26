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

#include "SHA0.h"

class SHA1 : public SHA0
{
public:
	SHA1()
		: SHA0()
	{
		_name = __func__;
	} // end constructor

	virtual IHash Clone() const
	{
		SHA1 HashInstance = SHA1();
		HashInstance._state = _state;
		HashInstance._buffer = _buffer.Clone();
		HashInstance._processed_bytes = _processed_bytes;

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<SHA1>(HashInstance);
	}

protected:
	virtual void Expand(UInt32* a_data)
	{
		UInt32 T;

		T = a_data[16 - 3] ^ a_data[16 - 8] ^ a_data[16 - 14] ^ a_data[0];
		a_data[16] = Bits::RotateLeft32(T, 1);
		T = a_data[17 - 3] ^ a_data[17 - 8] ^ a_data[17 - 14] ^ a_data[17 - 16];
		a_data[17] = Bits::RotateLeft32(T, 1);
		T = a_data[18 - 3] ^ a_data[18 - 8] ^ a_data[18 - 14] ^ a_data[18 - 16];
		a_data[18] = Bits::RotateLeft32(T, 1);
		T = a_data[19 - 3] ^ a_data[19 - 8] ^ a_data[19 - 14] ^ a_data[19 - 16];
		a_data[19] = Bits::RotateLeft32(T, 1);
		T = a_data[20 - 3] ^ a_data[20 - 8] ^ a_data[20 - 14] ^ a_data[20 - 16];
		a_data[20] = Bits::RotateLeft32(T, 1);
		T = a_data[21 - 3] ^ a_data[21 - 8] ^ a_data[21 - 14] ^ a_data[21 - 16];
		a_data[21] = Bits::RotateLeft32(T, 1);
		T = a_data[22 - 3] ^ a_data[22 - 8] ^ a_data[22 - 14] ^ a_data[22 - 16];
		a_data[22] = Bits::RotateLeft32(T, 1);
		T = a_data[23 - 3] ^ a_data[23 - 8] ^ a_data[23 - 14] ^ a_data[23 - 16];
		a_data[23] = Bits::RotateLeft32(T, 1);
		T = a_data[24 - 3] ^ a_data[24 - 8] ^ a_data[24 - 14] ^ a_data[24 - 16];
		a_data[24] = Bits::RotateLeft32(T, 1);
		T = a_data[25 - 3] ^ a_data[25 - 8] ^ a_data[25 - 14] ^ a_data[25 - 16];
		a_data[25] = Bits::RotateLeft32(T, 1);
		T = a_data[26 - 3] ^ a_data[26 - 8] ^ a_data[26 - 14] ^ a_data[26 - 16];
		a_data[26] = Bits::RotateLeft32(T, 1);
		T = a_data[27 - 3] ^ a_data[27 - 8] ^ a_data[27 - 14] ^ a_data[27 - 16];
		a_data[27] = Bits::RotateLeft32(T, 1);
		T = a_data[28 - 3] ^ a_data[28 - 8] ^ a_data[28 - 14] ^ a_data[28 - 16];
		a_data[28] = Bits::RotateLeft32(T, 1);
		T = a_data[29 - 3] ^ a_data[29 - 8] ^ a_data[29 - 14] ^ a_data[29 - 16];
		a_data[29] = Bits::RotateLeft32(T, 1);
		T = a_data[30 - 3] ^ a_data[30 - 8] ^ a_data[30 - 14] ^ a_data[30 - 16];
		a_data[30] = Bits::RotateLeft32(T, 1);
		T = a_data[31 - 3] ^ a_data[31 - 8] ^ a_data[31 - 14] ^ a_data[31 - 16];
		a_data[31] = Bits::RotateLeft32(T, 1);
		T = a_data[32 - 3] ^ a_data[32 - 8] ^ a_data[32 - 14] ^ a_data[32 - 16];
		a_data[32] = Bits::RotateLeft32(T, 1);
		T = a_data[33 - 3] ^ a_data[33 - 8] ^ a_data[33 - 14] ^ a_data[33 - 16];
		a_data[33] = Bits::RotateLeft32(T, 1);
		T = a_data[34 - 3] ^ a_data[34 - 8] ^ a_data[34 - 14] ^ a_data[34 - 16];
		a_data[34] = Bits::RotateLeft32(T, 1);
		T = a_data[35 - 3] ^ a_data[35 - 8] ^ a_data[35 - 14] ^ a_data[35 - 16];
		a_data[35] = Bits::RotateLeft32(T, 1);
		T = a_data[36 - 3] ^ a_data[36 - 8] ^ a_data[36 - 14] ^ a_data[36 - 16];
		a_data[36] = Bits::RotateLeft32(T, 1);
		T = a_data[37 - 3] ^ a_data[37 - 8] ^ a_data[37 - 14] ^ a_data[37 - 16];
		a_data[37] = Bits::RotateLeft32(T, 1);
		T = a_data[38 - 3] ^ a_data[38 - 8] ^ a_data[38 - 14] ^ a_data[38 - 16];
		a_data[38] = Bits::RotateLeft32(T, 1);
		T = a_data[39 - 3] ^ a_data[39 - 8] ^ a_data[39 - 14] ^ a_data[39 - 16];
		a_data[39] = Bits::RotateLeft32(T, 1);
		T = a_data[40 - 3] ^ a_data[40 - 8] ^ a_data[40 - 14] ^ a_data[40 - 16];
		a_data[40] = Bits::RotateLeft32(T, 1);
		T = a_data[41 - 3] ^ a_data[41 - 8] ^ a_data[41 - 14] ^ a_data[41 - 16];
		a_data[41] = Bits::RotateLeft32(T, 1);
		T = a_data[42 - 3] ^ a_data[42 - 8] ^ a_data[42 - 14] ^ a_data[42 - 16];
		a_data[42] = Bits::RotateLeft32(T, 1);
		T = a_data[43 - 3] ^ a_data[43 - 8] ^ a_data[43 - 14] ^ a_data[43 - 16];
		a_data[43] = Bits::RotateLeft32(T, 1);
		T = a_data[44 - 3] ^ a_data[44 - 8] ^ a_data[44 - 14] ^ a_data[44 - 16];
		a_data[44] = Bits::RotateLeft32(T, 1);
		T = a_data[45 - 3] ^ a_data[45 - 8] ^ a_data[45 - 14] ^ a_data[45 - 16];
		a_data[45] = Bits::RotateLeft32(T, 1);
		T = a_data[46 - 3] ^ a_data[46 - 8] ^ a_data[46 - 14] ^ a_data[46 - 16];
		a_data[46] = Bits::RotateLeft32(T, 1);
		T = a_data[47 - 3] ^ a_data[47 - 8] ^ a_data[47 - 14] ^ a_data[47 - 16];
		a_data[47] = Bits::RotateLeft32(T, 1);
		T = a_data[48 - 3] ^ a_data[48 - 8] ^ a_data[48 - 14] ^ a_data[48 - 16];
		a_data[48] = Bits::RotateLeft32(T, 1);
		T = a_data[49 - 3] ^ a_data[49 - 8] ^ a_data[49 - 14] ^ a_data[49 - 16];
		a_data[49] = Bits::RotateLeft32(T, 1);
		T = a_data[50 - 3] ^ a_data[50 - 8] ^ a_data[50 - 14] ^ a_data[50 - 16];
		a_data[50] = Bits::RotateLeft32(T, 1);
		T = a_data[51 - 3] ^ a_data[51 - 8] ^ a_data[51 - 14] ^ a_data[51 - 16];
		a_data[51] = Bits::RotateLeft32(T, 1);
		T = a_data[52 - 3] ^ a_data[52 - 8] ^ a_data[52 - 14] ^ a_data[52 - 16];
		a_data[52] = Bits::RotateLeft32(T, 1);
		T = a_data[53 - 3] ^ a_data[53 - 8] ^ a_data[53 - 14] ^ a_data[53 - 16];
		a_data[53] = Bits::RotateLeft32(T, 1);
		T = a_data[54 - 3] ^ a_data[54 - 8] ^ a_data[54 - 14] ^ a_data[54 - 16];
		a_data[54] = Bits::RotateLeft32(T, 1);
		T = a_data[55 - 3] ^ a_data[55 - 8] ^ a_data[55 - 14] ^ a_data[55 - 16];
		a_data[55] = Bits::RotateLeft32(T, 1);
		T = a_data[56 - 3] ^ a_data[56 - 8] ^ a_data[56 - 14] ^ a_data[56 - 16];
		a_data[56] = Bits::RotateLeft32(T, 1);
		T = a_data[57 - 3] ^ a_data[57 - 8] ^ a_data[57 - 14] ^ a_data[57 - 16];
		a_data[57] = Bits::RotateLeft32(T, 1);
		T = a_data[58 - 3] ^ a_data[58 - 8] ^ a_data[58 - 14] ^ a_data[58 - 16];
		a_data[58] = Bits::RotateLeft32(T, 1);
		T = a_data[59 - 3] ^ a_data[59 - 8] ^ a_data[59 - 14] ^ a_data[59 - 16];
		a_data[59] = Bits::RotateLeft32(T, 1);
		T = a_data[60 - 3] ^ a_data[60 - 8] ^ a_data[60 - 14] ^ a_data[60 - 16];
		a_data[60] = Bits::RotateLeft32(T, 1);
		T = a_data[61 - 3] ^ a_data[61 - 8] ^ a_data[61 - 14] ^ a_data[61 - 16];
		a_data[61] = Bits::RotateLeft32(T, 1);
		T = a_data[62 - 3] ^ a_data[62 - 8] ^ a_data[62 - 14] ^ a_data[62 - 16];
		a_data[62] = Bits::RotateLeft32(T, 1);
		T = a_data[63 - 3] ^ a_data[63 - 8] ^ a_data[63 - 14] ^ a_data[63 - 16];
		a_data[63] = Bits::RotateLeft32(T, 1);
		T = a_data[64 - 3] ^ a_data[64 - 8] ^ a_data[64 - 14] ^ a_data[64 - 16];
		a_data[64] = Bits::RotateLeft32(T, 1);
		T = a_data[65 - 3] ^ a_data[65 - 8] ^ a_data[65 - 14] ^ a_data[65 - 16];
		a_data[65] = Bits::RotateLeft32(T, 1);
		T = a_data[66 - 3] ^ a_data[66 - 8] ^ a_data[66 - 14] ^ a_data[66 - 16];
		a_data[66] = Bits::RotateLeft32(T, 1);
		T = a_data[67 - 3] ^ a_data[67 - 8] ^ a_data[67 - 14] ^ a_data[67 - 16];
		a_data[67] = Bits::RotateLeft32(T, 1);
		T = a_data[68 - 3] ^ a_data[68 - 8] ^ a_data[68 - 14] ^ a_data[68 - 16];
		a_data[68] = Bits::RotateLeft32(T, 1);
		T = a_data[69 - 3] ^ a_data[69 - 8] ^ a_data[69 - 14] ^ a_data[69 - 16];
		a_data[69] = Bits::RotateLeft32(T, 1);
		T = a_data[70 - 3] ^ a_data[70 - 8] ^ a_data[70 - 14] ^ a_data[70 - 16];
		a_data[70] = Bits::RotateLeft32(T, 1);
		T = a_data[71 - 3] ^ a_data[71 - 8] ^ a_data[71 - 14] ^ a_data[71 - 16];
		a_data[71] = Bits::RotateLeft32(T, 1);
		T = a_data[72 - 3] ^ a_data[72 - 8] ^ a_data[72 - 14] ^ a_data[72 - 16];
		a_data[72] = Bits::RotateLeft32(T, 1);
		T = a_data[73 - 3] ^ a_data[73 - 8] ^ a_data[73 - 14] ^ a_data[73 - 16];
		a_data[73] = Bits::RotateLeft32(T, 1);
		T = a_data[74 - 3] ^ a_data[74 - 8] ^ a_data[74 - 14] ^ a_data[74 - 16];
		a_data[74] = Bits::RotateLeft32(T, 1);
		T = a_data[75 - 3] ^ a_data[75 - 8] ^ a_data[75 - 14] ^ a_data[75 - 16];
		a_data[75] = Bits::RotateLeft32(T, 1);
		T = a_data[76 - 3] ^ a_data[76 - 8] ^ a_data[76 - 14] ^ a_data[76 - 16];
		a_data[76] = Bits::RotateLeft32(T, 1);
		T = a_data[77 - 3] ^ a_data[77 - 8] ^ a_data[77 - 14] ^ a_data[77 - 16];
		a_data[77] = Bits::RotateLeft32(T, 1);
		T = a_data[78 - 3] ^ a_data[78 - 8] ^ a_data[78 - 14] ^ a_data[78 - 16];
		a_data[78] = Bits::RotateLeft32(T, 1);
		T = a_data[79 - 3] ^ a_data[79 - 8] ^ a_data[79 - 14] ^ a_data[79 - 16];
		a_data[79] = Bits::RotateLeft32(T, 1);

	} // end function Expand
	
}; // end class SHA1
