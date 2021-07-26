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

class WhirlPool : public BlockHash, public virtual IICryptoNotBuildIn, public virtual IITransformBlock
{
public:
	WhirlPool()
		: BlockHash(64, 64)
	{
		_name = __func__;

		_hash.resize(8);
	} // end constructor

	virtual IHash Clone() const
	{
		WhirlPool HashInstance = WhirlPool();
		HashInstance._hash = _hash;
		HashInstance._buffer = _buffer.Clone();
		HashInstance._processed_bytes = _processed_bytes;

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<WhirlPool>(HashInstance);
	}

	virtual void Initialize()
	{
		ArrayUtils::zeroFill(_hash);

		BlockHash::Initialize();
	} // end function Initialize

protected:
	virtual void Finish()
	{
		Int32 padindex;

		UInt64 bits = _processed_bytes * 8;
		if (_buffer.GetPos() > 31)
			padindex = 120 - _buffer.GetPos();
		else
			padindex = 56 - _buffer.GetPos();

		HashLibByteArray pad = HashLibByteArray((size_t)padindex + 8);

		pad[0] = 0x80;

		bits = Converters::be2me_64(bits);

		Converters::ReadUInt64AsBytesLE(bits, pad, padindex);

		padindex = padindex + 8;

		TransformBytes(pad, 0, padindex);

	} // end function Finish

	virtual HashLibByteArray GetResult()
	{
		HashLibByteArray result = HashLibByteArray(8 * sizeof(UInt64));

		Converters::be64_copy(&_hash[0], 0, &result[0], 0, (Int32)result.size());

		return result;
	} // end function GetResult

	virtual void TransformBlock(const byte* a_data,
		const Int32 a_data_length, const Int32 a_index)
	{
		HashLibUInt64Array data = HashLibUInt64Array(8), 
			k = HashLibUInt64Array(8),
			m = HashLibUInt64Array(8),
			temp = HashLibUInt64Array(8);

		Converters::be64_copy(a_data, a_index, &data[0], 0, 64);

		for (UInt32 i = 0; i < 8; i++)
		{
			k[i] = _hash[i];
			temp[i] = data[i] ^ k[i];
		} // end for

		for (UInt32 round = 1; round < ROUNDS + 1; round++)
		{
			for (UInt32 i = 0; i < 8; i++)
			{
				m[i] = 0;
				m[i] = m[i] ^ (C0[byte(k[(i - 0) & 7] >> 56)]);
				m[i] = m[i] ^ (C1[byte(k[(i - 1) & 7] >> 48)]);
				m[i] = m[i] ^ (C2[byte(k[(i - 2) & 7] >> 40)]);
				m[i] = m[i] ^ (C3[byte(k[(i - 3) & 7] >> 32)]);
				m[i] = m[i] ^ (C4[byte(k[(i - 4) & 7] >> 24)]);
				m[i] = m[i] ^ (C5[byte(k[(i - 5) & 7] >> 16)]);
				m[i] = m[i] ^ (C6[byte(k[(i - 6) & 7] >> 8)]);
				m[i] = m[i] ^ (C7[byte(k[(i - 7) & 7])]);

			} // end for

			memmove(&k[0], &m[0], 8 * sizeof(UInt64));

			k[0] = k[0] ^ rc[round];

			for (UInt32 i = 0; i < 8; i++)
			{
				m[i] = k[i];
				m[i] = m[i] ^ (C0[byte(temp[(i - 0) & 7] >> 56)]);
				m[i] = m[i] ^ (C1[byte(temp[(i - 1) & 7] >> 48)]);
				m[i] = m[i] ^ (C2[byte(temp[(i - 2) & 7] >> 40)]);
				m[i] = m[i] ^ (C3[byte(temp[(i - 3) & 7] >> 32)]);
				m[i] = m[i] ^ (C4[byte(temp[(i - 4) & 7] >> 24)]);
				m[i] = m[i] ^ (C5[byte(temp[(i - 5) & 7] >> 16)]);
				m[i] = m[i] ^ (C6[byte(temp[(i - 6) & 7] >> 8)]);
				m[i] = m[i] ^ (C7[byte(temp[(i - 7) & 7])]);

			} // end for

			memmove(&temp[0], &m[0], 8 * sizeof(UInt64));

		} // end for


		for (UInt32 i = 0; i < 8; i++)
		{
			_hash[i] = _hash[i] ^ (temp[i] ^ data[i]);
		} // end for

		ArrayUtils::zeroFill(data);
	} // end function TransformBlock

private:
	inline static UInt64 packIntoUInt64(const UInt32 b7, const UInt32 b6, const UInt32 b5,
		const UInt32 b4, const UInt32 b3, const UInt32 b2, const UInt32 b1, const UInt32 b0)
	{
		return (UInt64(b7) << 56) ^ (UInt64(b6) << 48) ^ (UInt64(b5) << 40)
			^ (UInt64(b4) << 32) ^ (UInt64(b3) << 24) ^ (UInt64(b2) << 16)
			^ (UInt64(b1) << 8) ^ b0;
	} // end function  packIntoUInt64

	inline static UInt32 maskWithReductionPolynomial(const UInt32 input)
	{
		UInt32 result = input;

		if (result >= 0x100)
			result = result ^ REDUCTION_POLYNOMIAL;

		return result;
	} // end function maskWithReductionPolynomial

	static char initializedStaticLoader()
	{
		UInt32 v1, v2, v4, v5, v8, v9;

		for (UInt32 i = 0; i < 256; i++)
		{
			v1 = SBOX[i];
			v2 = maskWithReductionPolynomial(v1 << 1);
			v4 = maskWithReductionPolynomial(v2 << 1);
			v5 = v4 ^ v1;
			v8 = maskWithReductionPolynomial(v4 << 1);
			v9 = v8 ^ v1;

			C0[i] = packIntoUInt64(v1, v1, v4, v1, v8, v5, v2, v9);
			C1[i] = packIntoUInt64(v9, v1, v1, v4, v1, v8, v5, v2);
			C2[i] = packIntoUInt64(v2, v9, v1, v1, v4, v1, v8, v5);
			C3[i] = packIntoUInt64(v5, v2, v9, v1, v1, v4, v1, v8);
			C4[i] = packIntoUInt64(v8, v5, v2, v9, v1, v1, v4, v1);
			C5[i] = packIntoUInt64(v1, v8, v5, v2, v9, v1, v1, v4);
			C6[i] = packIntoUInt64(v4, v1, v8, v5, v2, v9, v1, v1);
			C7[i] = packIntoUInt64(v1, v4, v1, v8, v5, v2, v9, v1);

		} // end for

		rc[0] = 0;

		for (UInt32 r = 1, i; r < ROUNDS + 1; r++)
		{

			i = 8 * (r - 1);
			rc[r] = (C0[i] & 0xFF00000000000000)
				^ (C1[(size_t)i + 1] & 0x00FF000000000000)
				^ (C2[(size_t)i + 2] & 0x0000FF0000000000)
				^ (C3[(size_t)i + 3] & 0x000000FF00000000)
				^ (C4[(size_t)i + 4] & 0x00000000FF000000)
				^ (C5[(size_t)i + 5] & 0x0000000000FF0000)
				^ (C6[(size_t)i + 6] & 0x000000000000FF00)
				^ (C7[(size_t)i + 7] & 0x00000000000000FF);
		} // end for

		return 'I';
	}

private:
	HashLibUInt64Array _hash;
	
	static char _initialized;
	static HashLibUInt64Array C0, C1, C2, C3, C4, C5, C6, C7, rc;

	static const UInt32 ROUNDS = 10;

	static const UInt32  REDUCTION_POLYNOMIAL = 0x011D;

	static const UInt32 SBOX[256];

}; // end class WhirlPool


HashLibUInt64Array WhirlPool::C0 = HashLibUInt64Array(256);
HashLibUInt64Array WhirlPool::C1 = HashLibUInt64Array(256);
HashLibUInt64Array WhirlPool::C2 = HashLibUInt64Array(256);
HashLibUInt64Array WhirlPool::C3 = HashLibUInt64Array(256);
HashLibUInt64Array WhirlPool::C4 = HashLibUInt64Array(256);
HashLibUInt64Array WhirlPool::C5 = HashLibUInt64Array(256);
HashLibUInt64Array WhirlPool::C6 = HashLibUInt64Array(256);
HashLibUInt64Array WhirlPool::C7 = HashLibUInt64Array(256);
HashLibUInt64Array WhirlPool::rc = HashLibUInt64Array(WhirlPool::ROUNDS + 1);

char WhirlPool::_initialized = WhirlPool::initializedStaticLoader();

const UInt32 WhirlPool::SBOX[256] = { 0x18, 0x23, 0xC6, 0xE8, 0x87, 0xB8, 0x01,
	0x4F, 0x36, 0xA6, 0xD2, 0xF5, 0x79, 0x6F, 0x91, 0x52, 0x60, 0xBC, 0x9B, 0x8E, 0xA3, 0x0C,
	0x7B, 0x35, 0x1D, 0xE0, 0xD7, 0xC2, 0x2E, 0x4B, 0xFE, 0x57, 0x15, 0x77, 0x37, 0xE5, 0x9F,
	0xF0, 0x4A, 0xDA, 0x58, 0xC9, 0x29, 0x0A, 0xB1, 0xA0, 0x6B, 0x85, 0xBD, 0x5D, 0x10, 0xF4,
	0xCB, 0x3E, 0x05, 0x67, 0xE4, 0x27, 0x41, 0x8B, 0xA7, 0x7D, 0x95, 0xD8, 0xFB, 0xEE, 0x7C,
	0x66, 0xDD, 0x17, 0x47, 0x9E, 0xCA, 0x2D, 0xBF, 0x07, 0xAD, 0x5A, 0x83, 0x33, 0x63, 0x02,
	0xAA, 0x71, 0xC8, 0x19, 0x49, 0xD9, 0xF2, 0xE3, 0x5B, 0x88, 0x9A, 0x26, 0x32, 0xB0, 0xE9,
	0x0F, 0xD5, 0x80, 0xBE, 0xCD, 0x34, 0x48, 0xFF, 0x7A, 0x90, 0x5F, 0x20, 0x68, 0x1A, 0xAE,
	0xB4, 0x54, 0x93, 0x22, 0x64, 0xF1, 0x73, 0x12, 0x40, 0x08, 0xC3, 0xEC, 0xDB, 0xA1, 0x8D,
	0x3D, 0x97, 0x00, 0xCF, 0x2B, 0x76, 0x82, 0xD6, 0x1B, 0xB5, 0xAF, 0x6A, 0x50, 0x45, 0xF3,
	0x30, 0xEF, 0x3F, 0x55, 0xA2, 0xEA, 0x65, 0xBA, 0x2F, 0xC0, 0xDE, 0x1C, 0xFD, 0x4D, 0x92,
	0x75, 0x06, 0x8A, 0xB2, 0xE6, 0x0E, 0x1F, 0x62, 0xD4, 0xA8, 0x96, 0xF9, 0xC5, 0x25, 0x59,
	0x84, 0x72, 0x39, 0x4C, 0x5E, 0x78, 0x38, 0x8C, 0xD1, 0xA5, 0xE2, 0x61, 0xB3, 0x21, 0x9C,
	0x1E, 0x43, 0xC7, 0xFC, 0x04, 0x51, 0x99, 0x6D, 0x0D, 0xFA, 0xDF, 0x7E, 0x24, 0x3B, 0xAB,
	0xCE, 0x11, 0x8F, 0x4E, 0xB7, 0xEB, 0x3C, 0x81, 0x94, 0xF7, 0xB9, 0x13, 0x2C, 0xD3, 0xE7,
	0x6E, 0xC4, 0x03, 0x56, 0x44, 0x7F, 0xA9, 0x2A, 0xBB, 0xC1, 0x53, 0xDC, 0x0B, 0x9D, 0x6C,
	0x31, 0x74, 0xF6, 0x46, 0xAC, 0x89, 0x14, 0xE1, 0x16, 0x3A, 0x69, 0x09, 0x70, 0xB6, 0xD0,
	0xED, 0xCC, 0x42, 0x98, 0xA4, 0x28, 0x5C, 0xF8, 0x86 };
