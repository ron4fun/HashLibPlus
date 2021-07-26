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

class HAS160 : public BlockHash, public virtual IICryptoNotBuildIn, public virtual IITransformBlock
{
public:
	HAS160()
		: BlockHash(20, 64)
	{
		_name = __func__;

		_hash.resize(5);		
	} // end constructor

	virtual IHash Clone() const
	{
		HAS160 HashInstance = HAS160();
		HashInstance._hash = _hash;
		HashInstance._buffer = _buffer.Clone();
		HashInstance._processed_bytes = _processed_bytes;

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<HAS160>(HashInstance);
	}

	virtual void Initialize()
	{
		_hash[0] = 0x67452301;
		_hash[1] = 0xEFCDAB89;
		_hash[2] = 0x98BADCFE;
		_hash[3] = 0x10325476;
		_hash[4] = 0xC3D2E1F0;

		BlockHash::Initialize();
	} // end function Initialize

protected:
	virtual void Finish()
	{
		Int32 pad_index;

		UInt64 bits = _processed_bytes * 8;
		if (_buffer.GetPos() < 56)
			pad_index = 56 - _buffer.GetPos();
		else
			pad_index = 120 - _buffer.GetPos();

		HashLibByteArray pad = HashLibByteArray((size_t)pad_index + 8);

		pad[0] = 0x80;

		bits = Converters::le2me_64(bits);

		Converters::ReadUInt64AsBytesLE(bits, pad, pad_index);

		pad_index = pad_index + 8;

		TransformBytes(pad, 0, pad_index);

	} // end function Finish

	virtual HashLibByteArray GetResult()
	{
		HashLibByteArray result = HashLibByteArray(5 * sizeof(UInt32));

		Converters::le32_copy(&_hash[0], 0, &result[0], 0, (Int32)result.size());

		return result;
	} // end function GetResult

	virtual void TransformBlock(const byte* a_data,
		const Int32 a_data_length, const Int32 a_index)
	{
		UInt32 A, B, C, D, E, T;

		HashLibUInt32Array data = HashLibUInt32Array(20);

		A = _hash[0];
		B = _hash[1];
		C = _hash[2];
		D = _hash[3];
		E = _hash[4];

		Converters::le32_copy(a_data, a_index, &data[0], 0, 64);

		data[16] = data[0] ^ data[1] ^ data[2] ^ data[3];
		data[17] = data[4] ^ data[5] ^ data[6] ^ data[7];
		data[18] = data[8] ^ data[9] ^ data[10] ^ data[11];
		data[19] = data[12] ^ data[13] ^ data[14] ^ data[15];

		UInt32 r = 0;
		while (r < 20)
		{
			T = data[index[r]] + (A << rot[r] | A >> tor[r]) + ((B & C) | (~B & D)) + E;
			E = D;
			D = C;
			C = B << 10 | B >> 22;
			B = A;
			A = T;
			r += 1;
		} // end while

		data[16] = data[3] ^ data[6] ^ data[9] ^ data[12];
		data[17] = data[2] ^ data[5] ^ data[8] ^ data[15];
		data[18] = data[1] ^ data[4] ^ data[11] ^ data[14];
		data[19] = data[0] ^ data[7] ^ data[10] ^ data[13];

		r = 20;
		while (r < 40)
		{
			T = data[index[r]] + 0x5A827999 + (A << rot[r - 20] | A >> tor[r - 20]) + (B ^ C ^ D) + E;
			E = D;
			D = C;
			C = B << 17 | B >> 15;
			B = A;
			A = T;
			r += 1;
		} // end while

		data[16] = data[5] ^ data[7] ^ data[12] ^ data[14];
		data[17] = data[0] ^ data[2] ^ data[9] ^ data[11];
		data[18] = data[4] ^ data[6] ^ data[13] ^ data[15];
		data[19] = data[1] ^ data[3] ^ data[8] ^ data[10];

		r = 40;
		while (r < 60)
		{
			T = data[index[r]] + 0x6ED9EBA1 + (A << rot[r - 40] | A >> tor[r - 40]) + (C ^ (B | ~D)) + E;
			E = D;
			D = C;
			C = B << 25 | B >> 7;
			B = A;
			A = T;
			r += 1;
		} // end while

		data[16] = data[2] ^ data[7] ^ data[8] ^ data[13];
		data[17] = data[3] ^ data[4] ^ data[9] ^ data[14];
		data[18] = data[0] ^ data[5] ^ data[10] ^ data[15];
		data[19] = data[1] ^ data[6] ^ data[11] ^ data[12];

		r = 60;
		while (r < 80)
		{
			T = data[index[r]] + 0x8F1BBCDC + (A << rot[r - 60] | A >> tor[r - 60]) + (B ^ C ^ D) + E;
			E = D;
			D = C;
			C = B << 30 | B >> 2;
			B = A;
			A = T;
			r += 1;
		} // end while

		_hash[0] = _hash[0] + A;
		_hash[1] = _hash[1] + B;
		_hash[2] = _hash[2] + C;
		_hash[3] = _hash[3] + D;
		_hash[4] = _hash[4] + E;

		ArrayUtils::zeroFill(data);

	} // end function TransformBlock

private:
	HashLibUInt32Array _hash;

	static const Int32 rot[20];
	static const Int32 tor[20];
	static const Int32 index[80];


}; // end class HAS160

const Int32 HAS160::rot[20] = { 5, 11, 7, 15, 6, 13, 8, 14, 7, 12, 9, 11, 8, 15, 6, 12, 9, 14, 5, 13 };

const Int32 HAS160::tor[20] = { 27, 21, 25, 17, 26, 19, 24, 18, 25, 20, 23, 21, 24, 17, 26, 20, 23, 18, 27, 19 };

const Int32 HAS160::index[80] = { 18, 0, 1, 2, 3, 19, 4, 5, 6, 7, 16, 8,
									9, 10, 11, 17, 12, 13, 14, 15, 18, 3, 6, 9, 12, 19, 15, 2, 5, 8, 16, 11,
									14, 1, 4, 17, 7, 10, 13, 0, 18, 12, 5, 14, 7, 19, 0, 9, 2, 11, 16, 4, 13,
									6, 15, 17, 8, 1, 10, 3, 18, 7, 2, 13, 8, 19, 3, 14, 9, 4, 16, 15, 10, 5,
									0, 17, 11, 6, 1, 12 };
