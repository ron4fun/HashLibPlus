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

class SHA2_512Base : public BlockHash, public virtual IICryptoNotBuildIn, public virtual IITransformBlock
{
protected:
	SHA2_512Base(const Int32 a_hash_size)
		: BlockHash(a_hash_size, 128)
	{
		_state.resize(8);		
	} // end constructor

	virtual void Finish()
	{
		UInt64 lowBits, hiBits;
		Int32 padindex;

		lowBits = _processed_bytes << 3;
		hiBits = _processed_bytes >> 61;

		if (_buffer.GetPos() < 112)
			padindex = 111 - _buffer.GetPos();
		else
			padindex = 239 - _buffer.GetPos();

		padindex++;
		HashLibByteArray pad = HashLibByteArray((size_t)padindex + 16);

		pad[0] = 0x80;

		hiBits = Converters::be2me_64(hiBits);

		Converters::ReadUInt64AsBytesLE(hiBits, pad, padindex);

		padindex = padindex + 8;

		lowBits = Converters::be2me_64(lowBits);

		Converters::ReadUInt64AsBytesLE(lowBits, pad, padindex);

		padindex = padindex + 8;

		TransformBytes(pad, 0, padindex);

	} // end function Finish

	virtual void TransformBlock(const byte* a_data,
		const Int32 a_data_length, const Int32 a_index)
	{
		UInt64 T0, T1, a, b, c, d, e, f, g, h;

		HashLibUInt64Array data = HashLibUInt64Array(80);

		Converters::be64_copy(a_data, a_index, &data[0], 0, 128);

		// Step 1

		T0 = data[16 - 15];
		T1 = data[16 - 2];
		data[16] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[16 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[0];
		T0 = data[17 - 15];
		T1 = data[17 - 2];
		data[17] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[17 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[17 - 16];
		T0 = data[18 - 15];
		T1 = data[18 - 2];
		data[18] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[18 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[18 - 16];
		T0 = data[19 - 15];
		T1 = data[19 - 2];
		data[19] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[19 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[19 - 16];
		T0 = data[20 - 15];
		T1 = data[20 - 2];
		data[20] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[20 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[20 - 16];
		T0 = data[21 - 15];
		T1 = data[21 - 2];
		data[21] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[21 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[21 - 16];
		T0 = data[22 - 15];
		T1 = data[22 - 2];
		data[22] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[22 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[22 - 16];
		T0 = data[23 - 15];
		T1 = data[23 - 2];
		data[23] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[23 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[23 - 16];
		T0 = data[24 - 15];
		T1 = data[24 - 2];
		data[24] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[24 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[24 - 16];
		T0 = data[25 - 15];
		T1 = data[25 - 2];
		data[25] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[25 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[25 - 16];
		T0 = data[26 - 15];
		T1 = data[26 - 2];
		data[26] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[26 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[26 - 16];
		T0 = data[27 - 15];
		T1 = data[27 - 2];
		data[27] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[27 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[27 - 16];
		T0 = data[28 - 15];
		T1 = data[28 - 2];
		data[28] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[28 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[28 - 16];
		T0 = data[29 - 15];
		T1 = data[29 - 2];
		data[29] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[29 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[29 - 16];
		T0 = data[30 - 15];
		T1 = data[30 - 2];
		data[30] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[30 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[30 - 16];
		T0 = data[31 - 15];
		T1 = data[31 - 2];
		data[31] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[31 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[31 - 16];
		T0 = data[32 - 15];
		T1 = data[32 - 2];
		data[32] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[32 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[32 - 16];
		T0 = data[33 - 15];
		T1 = data[33 - 2];
		data[33] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[33 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[33 - 16];
		T0 = data[34 - 15];
		T1 = data[34 - 2];
		data[34] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[34 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[34 - 16];
		T0 = data[35 - 15];
		T1 = data[35 - 2];
		data[35] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[35 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[35 - 16];
		T0 = data[36 - 15];
		T1 = data[36 - 2];
		data[36] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[36 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[36 - 16];
		T0 = data[37 - 15];
		T1 = data[37 - 2];
		data[37] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[37 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[37 - 16];
		T0 = data[38 - 15];
		T1 = data[38 - 2];
		data[38] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[38 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[38 - 16];
		T0 = data[39 - 15];
		T1 = data[39 - 2];
		data[39] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[39 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[39 - 16];
		T0 = data[40 - 15];
		T1 = data[40 - 2];
		data[40] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[40 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[40 - 16];
		T0 = data[41 - 15];
		T1 = data[41 - 2];
		data[41] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[41 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[41 - 16];
		T0 = data[42 - 15];
		T1 = data[42 - 2];
		data[42] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[42 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[42 - 16];
		T0 = data[43 - 15];
		T1 = data[43 - 2];
		data[43] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[43 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[43 - 16];
		T0 = data[44 - 15];
		T1 = data[44 - 2];
		data[44] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[44 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[44 - 16];
		T0 = data[45 - 15];
		T1 = data[45 - 2];
		data[45] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[45 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[45 - 16];
		T0 = data[46 - 15];
		T1 = data[46 - 2];
		data[46] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[46 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[46 - 16];
		T0 = data[47 - 15];
		T1 = data[47 - 2];
		data[47] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[47 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[47 - 16];
		T0 = data[48 - 15];
		T1 = data[48 - 2];
		data[48] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[48 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[48 - 16];
		T0 = data[49 - 15];
		T1 = data[49 - 2];
		data[49] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[49 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[49 - 16];
		T0 = data[50 - 15];
		T1 = data[50 - 2];
		data[50] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[50 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[50 - 16];
		T0 = data[51 - 15];
		T1 = data[51 - 2];
		data[51] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[51 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[51 - 16];
		T0 = data[52 - 15];
		T1 = data[52 - 2];
		data[52] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[52 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[52 - 16];
		T0 = data[53 - 15];
		T1 = data[53 - 2];
		data[53] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[53 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[53 - 16];
		T0 = data[54 - 15];
		T1 = data[54 - 2];
		data[54] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[54 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[54 - 16];
		T0 = data[55 - 15];
		T1 = data[55 - 2];
		data[55] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[55 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[55 - 16];
		T0 = data[56 - 15];
		T1 = data[56 - 2];
		data[56] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[56 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[56 - 16];
		T0 = data[57 - 15];
		T1 = data[57 - 2];
		data[57] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[57 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[57 - 16];
		T0 = data[58 - 15];
		T1 = data[58 - 2];
		data[58] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[58 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[58 - 16];
		T0 = data[59 - 15];
		T1 = data[59 - 2];
		data[59] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[59 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[59 - 16];
		T0 = data[60 - 15];
		T1 = data[60 - 2];
		data[60] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[60 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[60 - 16];
		T0 = data[61 - 15];
		T1 = data[61 - 2];
		data[61] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[61 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[61 - 16];
		T0 = data[62 - 15];
		T1 = data[62 - 2];
		data[62] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[62 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[62 - 16];
		T0 = data[63 - 15];
		T1 = data[63 - 2];
		data[63] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[63 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[63 - 16];
		T0 = data[64 - 15];
		T1 = data[64 - 2];
		data[64] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[64 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[64 - 16];
		T0 = data[65 - 15];
		T1 = data[65 - 2];
		data[65] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[65 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[65 - 16];
		T0 = data[66 - 15];
		T1 = data[66 - 2];
		data[66] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[66 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[66 - 16];
		T0 = data[67 - 15];
		T1 = data[67 - 2];
		data[67] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[67 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[67 - 16];
		T0 = data[68 - 15];
		T1 = data[68 - 2];
		data[68] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[68 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[68 - 16];
		T0 = data[69 - 15];
		T1 = data[69 - 2];
		data[69] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[69 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[69 - 16];
		T0 = data[70 - 15];
		T1 = data[70 - 2];
		data[70] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[70 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[70 - 16];
		T0 = data[71 - 15];
		T1 = data[71 - 2];
		data[71] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[71 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[71 - 16];
		T0 = data[72 - 15];
		T1 = data[72 - 2];
		data[72] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[72 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[72 - 16];
		T0 = data[73 - 15];
		T1 = data[73 - 2];
		data[73] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[73 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[73 - 16];
		T0 = data[74 - 15];
		T1 = data[74 - 2];
		data[74] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[74 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[74 - 16];
		T0 = data[75 - 15];
		T1 = data[75 - 2];
		data[75] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[75 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[75 - 16];
		T0 = data[76 - 15];
		T1 = data[76 - 2];
		data[76] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[76 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[76 - 16];
		T0 = data[77 - 15];
		T1 = data[77 - 2];
		data[77] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[77 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[77 - 16];
		T0 = data[78 - 15];
		T1 = data[78 - 2];
		data[78] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[78 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[78 - 16];
		T0 = data[79 - 15];
		T1 = data[79 - 2];
		data[79] = ((Bits::RotateLeft64(T1, 45)) ^ (Bits::RotateLeft64(T1, 3))
			^ (T1 >> 6)) + data[79 - 7] +
			((Bits::RotateLeft64(T0, 63)) ^ (Bits::RotateLeft64(T0, 56))
				^ (T0 >> 7)) + data[79 - 16];

		a = _state[0];
		b = _state[1];
		c = _state[2];
		d = _state[3];
		e = _state[4];
		f = _state[5];
		g = _state[6];
		h = _state[7];

		// Step 2

		// R0
		h = h + (0x428A2F98D728AE22 + data[0] + ((Bits::RotateLeft64(e, 50))
			^ (Bits::RotateLeft64(e, 46)) ^ (Bits::RotateLeft64(e, 23))) +
			((e & f) ^ (~e & g)));

		d = d + h;
		h = h + (((Bits::RotateLeft64(a, 36)) ^ (Bits::RotateLeft64(a, 30))
			^ (Bits::RotateLeft64(a, 25))) + ((a & b) ^ (a & c) ^ (b & c)));

		g = g + (0x7137449123EF65CD + data[1] + ((Bits::RotateLeft64(d, 50))
			^ (Bits::RotateLeft64(d, 46)) ^ (Bits::RotateLeft64(d, 23))) +
			((d & e) ^ (~d & f)));

		c = c + g;
		g = g + (((Bits::RotateLeft64(h, 36)) ^ (Bits::RotateLeft64(h, 30))
			^ (Bits::RotateLeft64(h, 25))) + ((h & a) ^ (h & b) ^ (a & b)));

		f = f + (0xB5C0FBCFEC4D3B2F + data[2] + ((Bits::RotateLeft64(c, 50))
			^ (Bits::RotateLeft64(c, 46)) ^ (Bits::RotateLeft64(c, 23))) +
			((c & d) ^ (~c & e)));

		b = b + f;
		f = f + (((Bits::RotateLeft64(g, 36)) ^ (Bits::RotateLeft64(g, 30))
			^ (Bits::RotateLeft64(g, 25))) + ((g & h) ^ (g & a) ^ (h & a)));

		e = e + (0xE9B5DBA58189DBBC + data[3] + ((Bits::RotateLeft64(b, 50))
			^ (Bits::RotateLeft64(b, 46)) ^ (Bits::RotateLeft64(b, 23))) +
			((b & c) ^ (~b & d)));

		a = a + e;
		e = e + (((Bits::RotateLeft64(f, 36)) ^ (Bits::RotateLeft64(f, 30))
			^ (Bits::RotateLeft64(f, 25))) + ((f & g) ^ (f & h) ^ (g & h)));

		d = d + (0x3956C25BF348B538 + data[4] + ((Bits::RotateLeft64(a, 50))
			^ (Bits::RotateLeft64(a, 46)) ^ (Bits::RotateLeft64(a, 23))) +
			((a & b) ^ (~a & c)));

		h = h + d;
		d = d + (((Bits::RotateLeft64(e, 36)) ^ (Bits::RotateLeft64(e, 30))
			^ (Bits::RotateLeft64(e, 25))) + ((e & f) ^ (e & g) ^ (f & g)));

		c = c + (0x59F111F1B605D019 + data[5] + ((Bits::RotateLeft64(h, 50))
			^ (Bits::RotateLeft64(h, 46)) ^ (Bits::RotateLeft64(h, 23))) +
			((h & a) ^ (~h & b)));

		g = g + c;
		c = c + (((Bits::RotateLeft64(d, 36)) ^ (Bits::RotateLeft64(d, 30))
			^ (Bits::RotateLeft64(d, 25))) + ((d & e) ^ (d & f) ^ (e & f)));

		b = b + (0x923F82A4AF194F9B + data[6] + ((Bits::RotateLeft64(g, 50))
			^ (Bits::RotateLeft64(g, 46)) ^ (Bits::RotateLeft64(g, 23))) +
			((g & h) ^ (~g & a)));

		f = f + b;
		b = b + (((Bits::RotateLeft64(c, 36)) ^ (Bits::RotateLeft64(c, 30))
			^ (Bits::RotateLeft64(c, 25))) + ((c & d) ^ (c & e) ^ (d & e)));

		a = a + (0xAB1C5ED5DA6D8118 + data[7] + ((Bits::RotateLeft64(f, 50))
			^ (Bits::RotateLeft64(f, 46)) ^ (Bits::RotateLeft64(f, 23))) +
			((f & g) ^ (~f & h)));

		e = e + a;
		a = a + (((Bits::RotateLeft64(b, 36)) ^ (Bits::RotateLeft64(b, 30))
			^ (Bits::RotateLeft64(b, 25))) + ((b & c) ^ (b & d) ^ (c & d)));

		// R1
		h = h + (0xD807AA98A3030242 + data[8] + ((Bits::RotateLeft64(e, 50))
			^ (Bits::RotateLeft64(e, 46)) ^ (Bits::RotateLeft64(e, 23))) +
			((e & f) ^ (~e & g)));

		d = d + h;
		h = h + (((Bits::RotateLeft64(a, 36)) ^ (Bits::RotateLeft64(a, 30))
			^ (Bits::RotateLeft64(a, 25))) + ((a & b) ^ (a & c) ^ (b & c)));

		g = g + (0x12835B0145706FBE + data[9] + ((Bits::RotateLeft64(d, 50))
			^ (Bits::RotateLeft64(d, 46)) ^ (Bits::RotateLeft64(d, 23))) +
			((d & e) ^ (~d & f)));

		c = c + g;
		g = g + (((Bits::RotateLeft64(h, 36)) ^ (Bits::RotateLeft64(h, 30))
			^ (Bits::RotateLeft64(h, 25))) + ((h & a) ^ (h & b) ^ (a & b)));

		f = f + (0x243185BE4EE4B28C + data[10] + ((Bits::RotateLeft64(c, 50))
			^ (Bits::RotateLeft64(c, 46)) ^ (Bits::RotateLeft64(c, 23))) +
			((c & d) ^ (~c & e)));

		b = b + f;
		f = f + (((Bits::RotateLeft64(g, 36)) ^ (Bits::RotateLeft64(g, 30))
			^ (Bits::RotateLeft64(g, 25))) + ((g & h) ^ (g & a) ^ (h & a)));

		e = e + (0x550C7DC3D5FFB4E2 + data[11] + ((Bits::RotateLeft64(b, 50))
			^ (Bits::RotateLeft64(b, 46)) ^ (Bits::RotateLeft64(b, 23))) +
			((b & c) ^ (~b & d)));

		a = a + e;
		e = e + (((Bits::RotateLeft64(f, 36)) ^ (Bits::RotateLeft64(f, 30))
			^ (Bits::RotateLeft64(f, 25))) + ((f & g) ^ (f & h) ^ (g & h)));

		d = d + (0x72BE5D74F27B896F + data[12] + ((Bits::RotateLeft64(a, 50))
			^ (Bits::RotateLeft64(a, 46)) ^ (Bits::RotateLeft64(a, 23))) +
			((a & b) ^ (~a & c)));

		h = h + d;
		d = d + (((Bits::RotateLeft64(e, 36)) ^ (Bits::RotateLeft64(e, 30))
			^ (Bits::RotateLeft64(e, 25))) + ((e & f) ^ (e & g) ^ (f & g)));

		c = c + (0x80DEB1FE3B1696B1 + data[13] + ((Bits::RotateLeft64(h, 50))
			^ (Bits::RotateLeft64(h, 46)) ^ (Bits::RotateLeft64(h, 23))) +
			((h & a) ^ (~h & b)));

		g = g + c;
		c = c + (((Bits::RotateLeft64(d, 36)) ^ (Bits::RotateLeft64(d, 30))
			^ (Bits::RotateLeft64(d, 25))) + ((d & e) ^ (d & f) ^ (e & f)));

		b = b + (0x9BDC06A725C71235 + data[14] + ((Bits::RotateLeft64(g, 50))
			^ (Bits::RotateLeft64(g, 46)) ^ (Bits::RotateLeft64(g, 23))) +
			((g & h) ^ (~g & a)));

		f = f + b;
		b = b + (((Bits::RotateLeft64(c, 36)) ^ (Bits::RotateLeft64(c, 30))
			^ (Bits::RotateLeft64(c, 25))) + ((c & d) ^ (c & e) ^ (d & e)));

		a = a + (0xC19BF174CF692694 + data[15] + ((Bits::RotateLeft64(f, 50))
			^ (Bits::RotateLeft64(f, 46)) ^ (Bits::RotateLeft64(f, 23))) +
			((f & g) ^ (~f & h)));

		e = e + a;
		a = a + (((Bits::RotateLeft64(b, 36)) ^ (Bits::RotateLeft64(b, 30))
			^ (Bits::RotateLeft64(b, 25))) + ((b & c) ^ (b & d) ^ (c & d)));

		// R2

		h = h + (0xE49B69C19EF14AD2 + data[16] + ((Bits::RotateLeft64(e, 50))
			^ (Bits::RotateLeft64(e, 46)) ^ (Bits::RotateLeft64(e, 23))) +
			((e & f) ^ (~e & g)));

		d = d + h;
		h = h + (((Bits::RotateLeft64(a, 36)) ^ (Bits::RotateLeft64(a, 30))
			^ (Bits::RotateLeft64(a, 25))) + ((a & b) ^ (a & c) ^ (b & c)));

		g = g + (0xEFBE4786384F25E3 + data[17] + ((Bits::RotateLeft64(d, 50))
			^ (Bits::RotateLeft64(d, 46)) ^ (Bits::RotateLeft64(d, 23))) +
			((d & e) ^ (~d & f)));

		c = c + g;
		g = g + (((Bits::RotateLeft64(h, 36)) ^ (Bits::RotateLeft64(h, 30))
			^ (Bits::RotateLeft64(h, 25))) + ((h & a) ^ (h & b) ^ (a & b)));

		f = f + (0x0FC19DC68B8CD5B5 + data[18] + ((Bits::RotateLeft64(c, 50))
			^ (Bits::RotateLeft64(c, 46)) ^ (Bits::RotateLeft64(c, 23))) +
			((c & d) ^ (~c & e)));

		b = b + f;
		f = f + (((Bits::RotateLeft64(g, 36)) ^ (Bits::RotateLeft64(g, 30))
			^ (Bits::RotateLeft64(g, 25))) + ((g & h) ^ (g & a) ^ (h & a)));

		e = e + (0x240CA1CC77AC9C65 + data[19] + ((Bits::RotateLeft64(b, 50))
			^ (Bits::RotateLeft64(b, 46)) ^ (Bits::RotateLeft64(b, 23))) +
			((b & c) ^ (~b & d)));

		a = a + e;
		e = e + (((Bits::RotateLeft64(f, 36)) ^ (Bits::RotateLeft64(f, 30))
			^ (Bits::RotateLeft64(f, 25))) + ((f & g) ^ (f & h) ^ (g & h)));

		d = d + (0x2DE92C6F592B0275 + data[20] + ((Bits::RotateLeft64(a, 50))
			^ (Bits::RotateLeft64(a, 46)) ^ (Bits::RotateLeft64(a, 23))) +
			((a & b) ^ (~a & c)));

		h = h + d;
		d = d + (((Bits::RotateLeft64(e, 36)) ^ (Bits::RotateLeft64(e, 30))
			^ (Bits::RotateLeft64(e, 25))) + ((e & f) ^ (e & g) ^ (f & g)));

		c = c + (0x4A7484AA6EA6E483 + data[21] + ((Bits::RotateLeft64(h, 50))
			^ (Bits::RotateLeft64(h, 46)) ^ (Bits::RotateLeft64(h, 23))) +
			((h & a) ^ (~h & b)));

		g = g + c;
		c = c + (((Bits::RotateLeft64(d, 36)) ^ (Bits::RotateLeft64(d, 30))
			^ (Bits::RotateLeft64(d, 25))) + ((d & e) ^ (d & f) ^ (e & f)));

		b = b + (0x5CB0A9DCBD41FBD4 + data[22] + ((Bits::RotateLeft64(g, 50))
			^ (Bits::RotateLeft64(g, 46)) ^ (Bits::RotateLeft64(g, 23))) +
			((g & h) ^ (~g & a)));

		f = f + b;
		b = b + (((Bits::RotateLeft64(c, 36)) ^ (Bits::RotateLeft64(c, 30))
			^ (Bits::RotateLeft64(c, 25))) + ((c & d) ^ (c & e) ^ (d & e)));

		a = a + (0x76F988DA831153B5 + data[23] + ((Bits::RotateLeft64(f, 50))
			^ (Bits::RotateLeft64(f, 46)) ^ (Bits::RotateLeft64(f, 23))) +
			((f & g) ^ (~f & h)));

		e = e + a;
		a = a + (((Bits::RotateLeft64(b, 36)) ^ (Bits::RotateLeft64(b, 30))
			^ (Bits::RotateLeft64(b, 25))) + ((b & c) ^ (b & d) ^ (c & d)));

		// R3

		h = h + (0x983E5152EE66DFAB + data[24] + ((Bits::RotateLeft64(e, 50))
			^ (Bits::RotateLeft64(e, 46)) ^ (Bits::RotateLeft64(e, 23))) +
			((e & f) ^ (~e & g)));

		d = d + h;
		h = h + (((Bits::RotateLeft64(a, 36)) ^ (Bits::RotateLeft64(a, 30))
			^ (Bits::RotateLeft64(a, 25))) + ((a & b) ^ (a & c) ^ (b & c)));

		g = g + (0xA831C66D2DB43210 + data[25] + ((Bits::RotateLeft64(d, 50))
			^ (Bits::RotateLeft64(d, 46)) ^ (Bits::RotateLeft64(d, 23))) +
			((d & e) ^ (~d & f)));

		c = c + g;
		g = g + (((Bits::RotateLeft64(h, 36)) ^ (Bits::RotateLeft64(h, 30))
			^ (Bits::RotateLeft64(h, 25))) + ((h & a) ^ (h & b) ^ (a & b)));

		f = f + (0xB00327C898FB213F + data[26] + ((Bits::RotateLeft64(c, 50))
			^ (Bits::RotateLeft64(c, 46)) ^ (Bits::RotateLeft64(c, 23))) +
			((c & d) ^ (~c & e)));

		b = b + f;
		f = f + (((Bits::RotateLeft64(g, 36)) ^ (Bits::RotateLeft64(g, 30))
			^ (Bits::RotateLeft64(g, 25))) + ((g & h) ^ (g & a) ^ (h & a)));

		e = e + (0xBF597FC7BEEF0EE4 + data[27] + ((Bits::RotateLeft64(b, 50))
			^ (Bits::RotateLeft64(b, 46)) ^ (Bits::RotateLeft64(b, 23))) +
			((b & c) ^ (~b & d)));

		a = a + e;
		e = e + (((Bits::RotateLeft64(f, 36)) ^ (Bits::RotateLeft64(f, 30))
			^ (Bits::RotateLeft64(f, 25))) + ((f & g) ^ (f & h) ^ (g & h)));

		d = d + (0xC6E00BF33DA88FC2 + data[28] + ((Bits::RotateLeft64(a, 50))
			^ (Bits::RotateLeft64(a, 46)) ^ (Bits::RotateLeft64(a, 23))) +
			((a & b) ^ (~a & c)));

		h = h + d;
		d = d + (((Bits::RotateLeft64(e, 36)) ^ (Bits::RotateLeft64(e, 30))
			^ (Bits::RotateLeft64(e, 25))) + ((e & f) ^ (e & g) ^ (f & g)));

		c = c + (0xD5A79147930AA725 + data[29] + ((Bits::RotateLeft64(h, 50))
			^ (Bits::RotateLeft64(h, 46)) ^ (Bits::RotateLeft64(h, 23))) +
			((h & a) ^ (~h & b)));

		g = g + c;
		c = c + (((Bits::RotateLeft64(d, 36)) ^ (Bits::RotateLeft64(d, 30))
			^ (Bits::RotateLeft64(d, 25))) + ((d & e) ^ (d & f) ^ (e & f)));

		b = b + (0x06CA6351E003826F + data[30] + ((Bits::RotateLeft64(g, 50))
			^ (Bits::RotateLeft64(g, 46)) ^ (Bits::RotateLeft64(g, 23))) +
			((g & h) ^ (~g & a)));

		f = f + b;
		b = b + (((Bits::RotateLeft64(c, 36)) ^ (Bits::RotateLeft64(c, 30))
			^ (Bits::RotateLeft64(c, 25))) + ((c & d) ^ (c & e) ^ (d & e)));

		a = a + (0x142929670A0E6E70 + data[31] + ((Bits::RotateLeft64(f, 50))
			^ (Bits::RotateLeft64(f, 46)) ^ (Bits::RotateLeft64(f, 23))) +
			((f & g) ^ (~f & h)));

		e = e + a;
		a = a + (((Bits::RotateLeft64(b, 36)) ^ (Bits::RotateLeft64(b, 30))
			^ (Bits::RotateLeft64(b, 25))) + ((b & c) ^ (b & d) ^ (c & d)));

		// R4

		h = h + (0x27B70A8546D22FFC + data[32] + ((Bits::RotateLeft64(e, 50))
			^ (Bits::RotateLeft64(e, 46)) ^ (Bits::RotateLeft64(e, 23))) +
			((e & f) ^ (~e & g)));

		d = d + h;
		h = h + (((Bits::RotateLeft64(a, 36)) ^ (Bits::RotateLeft64(a, 30))
			^ (Bits::RotateLeft64(a, 25))) + ((a & b) ^ (a & c) ^ (b & c)));

		g = g + (0x2E1B21385C26C926 + data[33] + ((Bits::RotateLeft64(d, 50))
			^ (Bits::RotateLeft64(d, 46)) ^ (Bits::RotateLeft64(d, 23))) +
			((d & e) ^ (~d & f)));

		c = c + g;
		g = g + (((Bits::RotateLeft64(h, 36)) ^ (Bits::RotateLeft64(h, 30))
			^ (Bits::RotateLeft64(h, 25))) + ((h & a) ^ (h & b) ^ (a & b)));

		f = f + (0x4D2C6DFC5AC42AED + data[34] + ((Bits::RotateLeft64(c, 50))
			^ (Bits::RotateLeft64(c, 46)) ^ (Bits::RotateLeft64(c, 23))) +
			((c & d) ^ (~c & e)));

		b = b + f;
		f = f + (((Bits::RotateLeft64(g, 36)) ^ (Bits::RotateLeft64(g, 30))
			^ (Bits::RotateLeft64(g, 25))) + ((g & h) ^ (g & a) ^ (h & a)));

		e = e + (0x53380D139D95B3DF + data[35] + ((Bits::RotateLeft64(b, 50))
			^ (Bits::RotateLeft64(b, 46)) ^ (Bits::RotateLeft64(b, 23))) +
			((b & c) ^ (~b & d)));

		a = a + e;
		e = e + (((Bits::RotateLeft64(f, 36)) ^ (Bits::RotateLeft64(f, 30))
			^ (Bits::RotateLeft64(f, 25))) + ((f & g) ^ (f & h) ^ (g & h)));

		d = d + (0x650A73548BAF63DE + data[36] + ((Bits::RotateLeft64(a, 50))
			^ (Bits::RotateLeft64(a, 46)) ^ (Bits::RotateLeft64(a, 23))) +
			((a & b) ^ (~a & c)));

		h = h + d;
		d = d + (((Bits::RotateLeft64(e, 36)) ^ (Bits::RotateLeft64(e, 30))
			^ (Bits::RotateLeft64(e, 25))) + ((e & f) ^ (e & g) ^ (f & g)));

		c = c + (0x766A0ABB3C77B2A8 + data[37] + ((Bits::RotateLeft64(h, 50))
			^ (Bits::RotateLeft64(h, 46)) ^ (Bits::RotateLeft64(h, 23))) +
			((h & a) ^ (~h & b)));

		g = g + c;
		c = c + (((Bits::RotateLeft64(d, 36)) ^ (Bits::RotateLeft64(d, 30))
			^ (Bits::RotateLeft64(d, 25))) + ((d & e) ^ (d & f) ^ (e & f)));

		b = b + (0x81C2C92E47EDAEE6 + data[38] + ((Bits::RotateLeft64(g, 50))
			^ (Bits::RotateLeft64(g, 46)) ^ (Bits::RotateLeft64(g, 23))) +
			((g & h) ^ (~g & a)));

		f = f + b;
		b = b + (((Bits::RotateLeft64(c, 36)) ^ (Bits::RotateLeft64(c, 30))
			^ (Bits::RotateLeft64(c, 25))) + ((c & d) ^ (c & e) ^ (d & e)));

		a = a + (0x92722C851482353B + data[39] + ((Bits::RotateLeft64(f, 50))
			^ (Bits::RotateLeft64(f, 46)) ^ (Bits::RotateLeft64(f, 23))) +
			((f & g) ^ (~f & h)));

		e = e + a;
		a = a + (((Bits::RotateLeft64(b, 36)) ^ (Bits::RotateLeft64(b, 30))
			^ (Bits::RotateLeft64(b, 25))) + ((b & c) ^ (b & d) ^ (c & d)));

		// R5

		h = h + (0xA2BFE8A14CF10364 + data[40] + ((Bits::RotateLeft64(e, 50))
			^ (Bits::RotateLeft64(e, 46)) ^ (Bits::RotateLeft64(e, 23))) +
			((e & f) ^ (~e & g)));

		d = d + h;
		h = h + (((Bits::RotateLeft64(a, 36)) ^ (Bits::RotateLeft64(a, 30))
			^ (Bits::RotateLeft64(a, 25))) + ((a & b) ^ (a & c) ^ (b & c)));

		g = g + (0xA81A664BBC423001 + data[41] + ((Bits::RotateLeft64(d, 50))
			^ (Bits::RotateLeft64(d, 46)) ^ (Bits::RotateLeft64(d, 23))) +
			((d & e) ^ (~d & f)));

		c = c + g;
		g = g + (((Bits::RotateLeft64(h, 36)) ^ (Bits::RotateLeft64(h, 30))
			^ (Bits::RotateLeft64(h, 25))) + ((h & a) ^ (h & b) ^ (a & b)));

		f = f + (0xC24B8B70D0F89791 + data[42] + ((Bits::RotateLeft64(c, 50))
			^ (Bits::RotateLeft64(c, 46)) ^ (Bits::RotateLeft64(c, 23))) +
			((c & d) ^ (~c & e)));

		b = b + f;
		f = f + (((Bits::RotateLeft64(g, 36)) ^ (Bits::RotateLeft64(g, 30))
			^ (Bits::RotateLeft64(g, 25))) + ((g & h) ^ (g & a) ^ (h & a)));

		e = e + (0xC76C51A30654BE30 + data[43] + ((Bits::RotateLeft64(b, 50))
			^ (Bits::RotateLeft64(b, 46)) ^ (Bits::RotateLeft64(b, 23))) +
			((b & c) ^ (~b & d)));

		a = a + e;
		e = e + (((Bits::RotateLeft64(f, 36)) ^ (Bits::RotateLeft64(f, 30))
			^ (Bits::RotateLeft64(f, 25))) + ((f & g) ^ (f & h) ^ (g & h)));

		d = d + (0xD192E819D6EF5218 + data[44] + ((Bits::RotateLeft64(a, 50))
			^ (Bits::RotateLeft64(a, 46)) ^ (Bits::RotateLeft64(a, 23))) +
			((a & b) ^ (~a & c)));

		h = h + d;
		d = d + (((Bits::RotateLeft64(e, 36)) ^ (Bits::RotateLeft64(e, 30))
			^ (Bits::RotateLeft64(e, 25))) + ((e & f) ^ (e & g) ^ (f & g)));

		c = c + (0xD69906245565A910 + data[45] + ((Bits::RotateLeft64(h, 50))
			^ (Bits::RotateLeft64(h, 46)) ^ (Bits::RotateLeft64(h, 23))) +
			((h & a) ^ (~h & b)));

		g = g + c;
		c = c + (((Bits::RotateLeft64(d, 36)) ^ (Bits::RotateLeft64(d, 30))
			^ (Bits::RotateLeft64(d, 25))) + ((d & e) ^ (d & f) ^ (e & f)));

		b = b + (0xF40E35855771202A + data[46] + ((Bits::RotateLeft64(g, 50))
			^ (Bits::RotateLeft64(g, 46)) ^ (Bits::RotateLeft64(g, 23))) +
			((g & h) ^ (~g & a)));

		f = f + b;
		b = b + (((Bits::RotateLeft64(c, 36)) ^ (Bits::RotateLeft64(c, 30))
			^ (Bits::RotateLeft64(c, 25))) + ((c & d) ^ (c & e) ^ (d & e)));

		a = a + (0x106AA07032BBD1B8 + data[47] + ((Bits::RotateLeft64(f, 50))
			^ (Bits::RotateLeft64(f, 46)) ^ (Bits::RotateLeft64(f, 23))) +
			((f & g) ^ (~f & h)));

		e = e + a;
		a = a + (((Bits::RotateLeft64(b, 36)) ^ (Bits::RotateLeft64(b, 30))
			^ (Bits::RotateLeft64(b, 25))) + ((b & c) ^ (b & d) ^ (c & d)));

		// R6

		h = h + (0x19A4C116B8D2D0C8 + data[48] + ((Bits::RotateLeft64(e, 50))
			^ (Bits::RotateLeft64(e, 46)) ^ (Bits::RotateLeft64(e, 23))) +
			((e & f) ^ (~e & g)));

		d = d + h;
		h = h + (((Bits::RotateLeft64(a, 36)) ^ (Bits::RotateLeft64(a, 30))
			^ (Bits::RotateLeft64(a, 25))) + ((a & b) ^ (a & c) ^ (b & c)));

		g = g + (0x1E376C085141AB53 + data[49] + ((Bits::RotateLeft64(d, 50))
			^ (Bits::RotateLeft64(d, 46)) ^ (Bits::RotateLeft64(d, 23))) +
			((d & e) ^ (~d & f)));

		c = c + g;
		g = g + (((Bits::RotateLeft64(h, 36)) ^ (Bits::RotateLeft64(h, 30))
			^ (Bits::RotateLeft64(h, 25))) + ((h & a) ^ (h & b) ^ (a & b)));

		f = f + (0x2748774CDF8EEB99 + data[50] + ((Bits::RotateLeft64(c, 50))
			^ (Bits::RotateLeft64(c, 46)) ^ (Bits::RotateLeft64(c, 23))) +
			((c & d) ^ (~c & e)));

		b = b + f;
		f = f + (((Bits::RotateLeft64(g, 36)) ^ (Bits::RotateLeft64(g, 30))
			^ (Bits::RotateLeft64(g, 25))) + ((g & h) ^ (g & a) ^ (h & a)));

		e = e + (0x34B0BCB5E19B48A8 + data[51] + ((Bits::RotateLeft64(b, 50))
			^ (Bits::RotateLeft64(b, 46)) ^ (Bits::RotateLeft64(b, 23))) +
			((b & c) ^ (~b & d)));

		a = a + e;
		e = e + (((Bits::RotateLeft64(f, 36)) ^ (Bits::RotateLeft64(f, 30))
			^ (Bits::RotateLeft64(f, 25))) + ((f & g) ^ (f & h) ^ (g & h)));

		d = d + (0x391C0CB3C5C95A63 + data[52] + ((Bits::RotateLeft64(a, 50))
			^ (Bits::RotateLeft64(a, 46)) ^ (Bits::RotateLeft64(a, 23))) +
			((a & b) ^ (~a & c)));

		h = h + d;
		d = d + (((Bits::RotateLeft64(e, 36)) ^ (Bits::RotateLeft64(e, 30))
			^ (Bits::RotateLeft64(e, 25))) + ((e & f) ^ (e & g) ^ (f & g)));

		c = c + (0x4ED8AA4AE3418ACB + data[53] + ((Bits::RotateLeft64(h, 50))
			^ (Bits::RotateLeft64(h, 46)) ^ (Bits::RotateLeft64(h, 23))) +
			((h & a) ^ (~h & b)));

		g = g + c;
		c = c + (((Bits::RotateLeft64(d, 36)) ^ (Bits::RotateLeft64(d, 30))
			^ (Bits::RotateLeft64(d, 25))) + ((d & e) ^ (d & f) ^ (e & f)));

		b = b + (0x5B9CCA4F7763E373 + data[54] + ((Bits::RotateLeft64(g, 50))
			^ (Bits::RotateLeft64(g, 46)) ^ (Bits::RotateLeft64(g, 23))) +
			((g & h) ^ (~g & a)));

		f = f + b;
		b = b + (((Bits::RotateLeft64(c, 36)) ^ (Bits::RotateLeft64(c, 30))
			^ (Bits::RotateLeft64(c, 25))) + ((c & d) ^ (c & e) ^ (d & e)));

		a = a + (0x682E6FF3D6B2B8A3 + data[55] + ((Bits::RotateLeft64(f, 50))
			^ (Bits::RotateLeft64(f, 46)) ^ (Bits::RotateLeft64(f, 23))) +
			((f & g) ^ (~f & h)));

		e = e + a;
		a = a + (((Bits::RotateLeft64(b, 36)) ^ (Bits::RotateLeft64(b, 30))
			^ (Bits::RotateLeft64(b, 25))) + ((b & c) ^ (b & d) ^ (c & d)));

		// R7

		h = h + (0x748F82EE5DEFB2FC + data[56] + ((Bits::RotateLeft64(e, 50))
			^ (Bits::RotateLeft64(e, 46)) ^ (Bits::RotateLeft64(e, 23))) +
			((e & f) ^ (~e & g)));

		d = d + h;
		h = h + (((Bits::RotateLeft64(a, 36)) ^ (Bits::RotateLeft64(a, 30))
			^ (Bits::RotateLeft64(a, 25))) + ((a & b) ^ (a & c) ^ (b & c)));

		g = g + (0x78A5636F43172F60 + data[57] + ((Bits::RotateLeft64(d, 50))
			^ (Bits::RotateLeft64(d, 46)) ^ (Bits::RotateLeft64(d, 23))) +
			((d & e) ^ (~d & f)));

		c = c + g;
		g = g + (((Bits::RotateLeft64(h, 36)) ^ (Bits::RotateLeft64(h, 30))
			^ (Bits::RotateLeft64(h, 25))) + ((h & a) ^ (h & b) ^ (a & b)));

		f = f + (0x84C87814A1F0AB72 + data[58] + ((Bits::RotateLeft64(c, 50))
			^ (Bits::RotateLeft64(c, 46)) ^ (Bits::RotateLeft64(c, 23))) +
			((c & d) ^ (~c & e)));

		b = b + f;
		f = f + (((Bits::RotateLeft64(g, 36)) ^ (Bits::RotateLeft64(g, 30))
			^ (Bits::RotateLeft64(g, 25))) + ((g & h) ^ (g & a) ^ (h & a)));

		e = e + (0x8CC702081A6439EC + data[59] + ((Bits::RotateLeft64(b, 50))
			^ (Bits::RotateLeft64(b, 46)) ^ (Bits::RotateLeft64(b, 23))) +
			((b & c) ^ (~b & d)));

		a = a + e;
		e = e + (((Bits::RotateLeft64(f, 36)) ^ (Bits::RotateLeft64(f, 30))
			^ (Bits::RotateLeft64(f, 25))) + ((f & g) ^ (f & h) ^ (g & h)));

		d = d + (0x90BEFFFA23631E28 + data[60] + ((Bits::RotateLeft64(a, 50))
			^ (Bits::RotateLeft64(a, 46)) ^ (Bits::RotateLeft64(a, 23))) +
			((a & b) ^ (~a & c)));

		h = h + d;
		d = d + (((Bits::RotateLeft64(e, 36)) ^ (Bits::RotateLeft64(e, 30))
			^ (Bits::RotateLeft64(e, 25))) + ((e & f) ^ (e & g) ^ (f & g)));

		c = c + (0xA4506CEBDE82BDE9 + data[61] + ((Bits::RotateLeft64(h, 50))
			^ (Bits::RotateLeft64(h, 46)) ^ (Bits::RotateLeft64(h, 23))) +
			((h & a) ^ (~h & b)));

		g = g + c;
		c = c + (((Bits::RotateLeft64(d, 36)) ^ (Bits::RotateLeft64(d, 30))
			^ (Bits::RotateLeft64(d, 25))) + ((d & e) ^ (d & f) ^ (e & f)));

		b = b + (0xBEF9A3F7B2C67915 + data[62] + ((Bits::RotateLeft64(g, 50))
			^ (Bits::RotateLeft64(g, 46)) ^ (Bits::RotateLeft64(g, 23))) +
			((g & h) ^ (~g & a)));

		f = f + b;
		b = b + (((Bits::RotateLeft64(c, 36)) ^ (Bits::RotateLeft64(c, 30))
			^ (Bits::RotateLeft64(c, 25))) + ((c & d) ^ (c & e) ^ (d & e)));

		a = a + (0xC67178F2E372532B + data[63] + ((Bits::RotateLeft64(f, 50))
			^ (Bits::RotateLeft64(f, 46)) ^ (Bits::RotateLeft64(f, 23))) +
			((f & g) ^ (~f & h)));

		e = e + a;
		a = a + (((Bits::RotateLeft64(b, 36)) ^ (Bits::RotateLeft64(b, 30))
			^ (Bits::RotateLeft64(b, 25))) + ((b & c) ^ (b & d) ^ (c & d)));

		// R8

		h = h + (0xCA273ECEEA26619C + data[64] + ((Bits::RotateLeft64(e, 50))
			^ (Bits::RotateLeft64(e, 46)) ^ (Bits::RotateLeft64(e, 23))) +
			((e & f) ^ (~e & g)));

		d = d + h;
		h = h + (((Bits::RotateLeft64(a, 36)) ^ (Bits::RotateLeft64(a, 30))
			^ (Bits::RotateLeft64(a, 25))) + ((a & b) ^ (a & c) ^ (b & c)));

		g = g + (0xD186B8C721C0C207 + data[65] + ((Bits::RotateLeft64(d, 50))
			^ (Bits::RotateLeft64(d, 46)) ^ (Bits::RotateLeft64(d, 23))) +
			((d & e) ^ (~d & f)));

		c = c + g;
		g = g + (((Bits::RotateLeft64(h, 36)) ^ (Bits::RotateLeft64(h, 30))
			^ (Bits::RotateLeft64(h, 25))) + ((h & a) ^ (h & b) ^ (a & b)));

		f = f + (0xEADA7DD6CDE0EB1E + data[66] + ((Bits::RotateLeft64(c, 50))
			^ (Bits::RotateLeft64(c, 46)) ^ (Bits::RotateLeft64(c, 23))) +
			((c & d) ^ (~c & e)));

		b = b + f;
		f = f + (((Bits::RotateLeft64(g, 36)) ^ (Bits::RotateLeft64(g, 30))
			^ (Bits::RotateLeft64(g, 25))) + ((g & h) ^ (g & a) ^ (h & a)));

		e = e + (0xF57D4F7FEE6ED178 + data[67] + ((Bits::RotateLeft64(b, 50))
			^ (Bits::RotateLeft64(b, 46)) ^ (Bits::RotateLeft64(b, 23))) +
			((b & c) ^ (~b & d)));

		a = a + e;
		e = e + (((Bits::RotateLeft64(f, 36)) ^ (Bits::RotateLeft64(f, 30))
			^ (Bits::RotateLeft64(f, 25))) + ((f & g) ^ (f & h) ^ (g & h)));

		d = d + (0x06F067AA72176FBA + data[68] + ((Bits::RotateLeft64(a, 50))
			^ (Bits::RotateLeft64(a, 46)) ^ (Bits::RotateLeft64(a, 23))) +
			((a & b) ^ (~a & c)));

		h = h + d;
		d = d + (((Bits::RotateLeft64(e, 36)) ^ (Bits::RotateLeft64(e, 30))
			^ (Bits::RotateLeft64(e, 25))) + ((e & f) ^ (e & g) ^ (f & g)));

		c = c + (0x0A637DC5A2C898A6 + data[69] + ((Bits::RotateLeft64(h, 50))
			^ (Bits::RotateLeft64(h, 46)) ^ (Bits::RotateLeft64(h, 23))) +
			((h & a) ^ (~h & b)));

		g = g + c;
		c = c + (((Bits::RotateLeft64(d, 36)) ^ (Bits::RotateLeft64(d, 30))
			^ (Bits::RotateLeft64(d, 25))) + ((d & e) ^ (d & f) ^ (e & f)));

		b = b + (0x113F9804BEF90DAE + data[70] + ((Bits::RotateLeft64(g, 50))
			^ (Bits::RotateLeft64(g, 46)) ^ (Bits::RotateLeft64(g, 23))) +
			((g & h) ^ (~g & a)));

		f = f + b;
		b = b + (((Bits::RotateLeft64(c, 36)) ^ (Bits::RotateLeft64(c, 30))
			^ (Bits::RotateLeft64(c, 25))) + ((c & d) ^ (c & e) ^ (d & e)));

		a = a + (0x1B710B35131C471B + data[71] + ((Bits::RotateLeft64(f, 50))
			^ (Bits::RotateLeft64(f, 46)) ^ (Bits::RotateLeft64(f, 23))) +
			((f & g) ^ (~f & h)));

		e = e + a;
		a = a + (((Bits::RotateLeft64(b, 36)) ^ (Bits::RotateLeft64(b, 30))
			^ (Bits::RotateLeft64(b, 25))) + ((b & c) ^ (b & d) ^ (c & d)));

		// R9

		h = h + (0x28DB77F523047D84 + data[72] + ((Bits::RotateLeft64(e, 50))
			^ (Bits::RotateLeft64(e, 46)) ^ (Bits::RotateLeft64(e, 23))) +
			((e & f) ^ (~e & g)));

		d = d + h;
		h = h + (((Bits::RotateLeft64(a, 36)) ^ (Bits::RotateLeft64(a, 30))
			^ (Bits::RotateLeft64(a, 25))) + ((a & b) ^ (a & c) ^ (b & c)));

		g = g + (0x32CAAB7B40C72493 + data[73] + ((Bits::RotateLeft64(d, 50))
			^ (Bits::RotateLeft64(d, 46)) ^ (Bits::RotateLeft64(d, 23))) +
			((d & e) ^ (~d & f)));

		c = c + g;
		g = g + (((Bits::RotateLeft64(h, 36)) ^ (Bits::RotateLeft64(h, 30))
			^ (Bits::RotateLeft64(h, 25))) + ((h & a) ^ (h & b) ^ (a & b)));

		f = f + (0x3C9EBE0A15C9BEBC + data[74] + ((Bits::RotateLeft64(c, 50))
			^ (Bits::RotateLeft64(c, 46)) ^ (Bits::RotateLeft64(c, 23))) +
			((c & d) ^ (~c & e)));

		b = b + f;
		f = f + (((Bits::RotateLeft64(g, 36)) ^ (Bits::RotateLeft64(g, 30))
			^ (Bits::RotateLeft64(g, 25))) + ((g & h) ^ (g & a) ^ (h & a)));

		e = e + (0x431D67C49C100D4C + data[75] + ((Bits::RotateLeft64(b, 50))
			^ (Bits::RotateLeft64(b, 46)) ^ (Bits::RotateLeft64(b, 23))) +
			((b & c) ^ (~b & d)));

		a = a + e;
		e = e + (((Bits::RotateLeft64(f, 36)) ^ (Bits::RotateLeft64(f, 30))
			^ (Bits::RotateLeft64(f, 25))) + ((f & g) ^ (f & h) ^ (g & h)));

		d = d + (0x4CC5D4BECB3E42B6 + data[76] + ((Bits::RotateLeft64(a, 50))
			^ (Bits::RotateLeft64(a, 46)) ^ (Bits::RotateLeft64(a, 23))) +
			((a & b) ^ (~a & c)));

		h = h + d;
		d = d + (((Bits::RotateLeft64(e, 36)) ^ (Bits::RotateLeft64(e, 30))
			^ (Bits::RotateLeft64(e, 25))) + ((e & f) ^ (e & g) ^ (f & g)));

		c = c + (0x597F299CFC657E2A + data[77] + ((Bits::RotateLeft64(h, 50))
			^ (Bits::RotateLeft64(h, 46)) ^ (Bits::RotateLeft64(h, 23))) +
			((h & a) ^ (~h & b)));

		g = g + c;
		c = c + (((Bits::RotateLeft64(d, 36)) ^ (Bits::RotateLeft64(d, 30))
			^ (Bits::RotateLeft64(d, 25))) + ((d & e) ^ (d & f) ^ (e & f)));

		b = b + (0x5FCB6FAB3AD6FAEC + data[78] + ((Bits::RotateLeft64(g, 50))
			^ (Bits::RotateLeft64(g, 46)) ^ (Bits::RotateLeft64(g, 23))) +
			((g & h) ^ (~g & a)));

		f = f + b;
		b = b + (((Bits::RotateLeft64(c, 36)) ^ (Bits::RotateLeft64(c, 30))
			^ (Bits::RotateLeft64(c, 25))) + ((c & d) ^ (c & e) ^ (d & e)));

		a = a + (0x6C44198C4A475817 + data[79] + ((Bits::RotateLeft64(f, 50))
			^ (Bits::RotateLeft64(f, 46)) ^ (Bits::RotateLeft64(f, 23))) +
			((f & g) ^ (~f & h)));

		e = e + a;
		a = a + (((Bits::RotateLeft64(b, 36)) ^ (Bits::RotateLeft64(b, 30))
			^ (Bits::RotateLeft64(b, 25))) + ((b & c) ^ (b & d) ^ (c & d)));

		_state[0] = _state[0] + a;
		_state[1] = _state[1] + b;
		_state[2] = _state[2] + c;
		_state[3] = _state[3] + d;
		_state[4] = _state[4] + e;
		_state[5] = _state[5] + f;
		_state[6] = _state[6] + g;
		_state[7] = _state[7] + h;

		memset(&data[0], 0, data.size() * sizeof(UInt64));
	} // end function TransformBlock

protected:
	HashLibUInt64Array _state;
	
}; // end class SHA2_512Base
