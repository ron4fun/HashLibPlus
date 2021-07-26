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

class MD2 : public BlockHash, public virtual IICryptoNotBuildIn, public virtual IITransformBlock
{
public:
	MD2()
		: BlockHash(16, 16)
	{
		_name = __func__;

		_state.resize(16);
		_checksum.resize(16);
	} // end constructor

	virtual IHash Clone() const
	{
		MD2 HashInstance = MD2();
		HashInstance._state = _state;
		HashInstance._checksum = _checksum;
		HashInstance._buffer = _buffer.Clone();
		HashInstance._processed_bytes = _processed_bytes;

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<MD2>(HashInstance);
	}

	virtual void Initialize()
	{
		memset(&_state[0], 0, 16 * sizeof(byte));
		memset(&_checksum[0], 0, 16 * sizeof(byte));

		BlockHash::Initialize();
	} // end function Initialize

protected:
	virtual void Finish()
	{
		UInt32 padLen;

		padLen = 16 - _buffer.GetPos();
		HashLibByteArray pad = HashLibByteArray(padLen);

		UInt32 i = 0;
		while (i < padLen)
		{
			pad[i] = padLen;
			i++;
		} // end while

		TransformBytes(pad, 0, padLen);
		TransformBytes(_checksum, 0, 16);

	} // end function Finish

	virtual HashLibByteArray GetResult()
	{
		return _state;
	} // end function GetResult

	virtual void TransformBlock(const byte* a_data,
		const int32_t a_data_length, const int32_t a_index)
	{
		UInt32 t = 0;
		HashLibByteArray temp = HashLibByteArray(48);

		memmove(&temp[0], &_state[0], 16);
		memmove(&temp[16], &a_data[a_index], 16);

		for (Int32 i = 0; i < 16; i++)
		{
			temp[(size_t)i + 32] = (byte)((_state)[i] ^ a_data[i + a_index]);
		} // end for

		for (Int32 i = 0; i < 18; i++)
		{
			for (UInt32 j = 0; j < 48; j++)
			{
				temp[j] = (byte)(temp[j] ^ pi[t]);
				t = temp[j];
			} // end for

			t = (byte)(t + i);
		} // end for

		memmove(&_state[0], &temp[0], 16);

		t = _checksum[15];

		for (Int32 i = 0; i < 16; i++)
		{
			_checksum[i] = _checksum[i] ^ (pi[a_data[i + a_index] ^ t]);
			t = _checksum[i];
		} // end for

		memset(&temp[0], 0, 48);
	} // end function TransformBlock

private:
	HashLibByteArray _state;
	HashLibByteArray _checksum;

	static const byte pi[256];
	
}; // end class MD2

const byte MD2::pi[256] = { 41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
				19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188, 76, 130, 202,
				30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24, 138, 23, 229, 18,	190, 78,
				196, 214, 218, 158, 222, 73, 160, 251, 245, 142, 187, 47, 238, 122, 169, 104, 121,
				145, 21, 178, 7, 63, 148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144,
				50, 39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165, 181, 209, 215,
				94, 146, 42, 172, 86, 170, 198,	79, 184, 56, 210, 150, 164, 125, 182, 118, 252, 107,
				226, 156, 116, 4, 241, 69, 157, 112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45,
				168, 2,	27, 96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15, 85, 71,
				163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197, 234, 38, 44, 83, 13, 110, 133,
				40, 132, 9, 211, 223, 205, 244, 65, 129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250,
				36, 225, 123, 8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233, 203, 213,
				254, 59, 0, 29, 57,	242, 239, 183, 14, 102, 88, 208, 228, 166, 119, 114, 248, 235, 117,
				75, 10,	49, 68, 80, 180, 143, 237, 31, 26, 219, 153, 141, 51, 159, 17, 131, 20 };
