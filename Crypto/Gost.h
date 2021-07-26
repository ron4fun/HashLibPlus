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

class Gost : public BlockHash, public virtual IICryptoNotBuildIn, public virtual IITransformBlock
{
public:
	Gost()
		: BlockHash(32, 32)
	{
		_name = __func__;

		_state.resize(8);
		_hash.resize(8);
	} // end constructor

	virtual IHash Clone() const
	{
		Gost HashInstance = Gost();
		HashInstance._state = _state;
		HashInstance._hash = _hash;
		HashInstance._buffer = _buffer.Clone();
		HashInstance._processed_bytes = _processed_bytes;

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<Gost>(HashInstance);
	}

	virtual void Initialize()
	{
		ArrayUtils::zeroFill(_state);
		ArrayUtils::zeroFill(_hash);

		BlockHash::Initialize();
	} // end function Initialize

private:
	inline void Compress(UInt32* a_m)
	{
		UInt32 u0, u1, u2, u3, u4, u5, u6, u7, v0, v1, v2, v3, v4, v5, v6, v7, w0, w1, w2,
			w3, w4, w5, w6, w7, key0, key1, key2, key3, key4, key5, key6, key7, r, l, t;
		
		HashLibUInt32Array s = HashLibUInt32Array(8);

		u0 = _hash[0];
		u1 = _hash[1];
		u2 = _hash[2];
		u3 = _hash[3];
		u4 = _hash[4];
		u5 = _hash[5];
		u6 = _hash[6];
		u7 = _hash[7];

		v0 = a_m[0];
		v1 = a_m[1];
		v2 = a_m[2];
		v3 = a_m[3];
		v4 = a_m[4];
		v5 = a_m[5];
		v6 = a_m[6];
		v7 = a_m[7];

		UInt32 i = 0;

		while (i < 8)
		{
			w0 = u0 ^ v0;
			w1 = u1 ^ v1;
			w2 = u2 ^ v2;
			w3 = u3 ^ v3;
			w4 = u4 ^ v4;
			w5 = u5 ^ v5;
			w6 = u6 ^ v6;
			w7 = u7 ^ v7;

			key0 = UInt32(byte(w0)) | (UInt32(byte(w2)) << 8) |
				(UInt32(byte(w4)) << 16) | (UInt32(byte(w6)) << 24);
			key1 = UInt32(byte(w0 >> 8)) | (w2 & 0x0000FF00) |
				((w4 & 0x0000FF00) << 8) | ((w6 & 0x0000FF00) << 16);
			key2 = UInt32(byte(w0 >> 16)) | ((w2 & 0x00FF0000) >> 8) |
				(w4 & 0x00FF0000) | ((w6 & 0x00FF0000) << 8);
			key3 = (w0 >> 24) | ((w2 & 0xFF000000) >> 16) |
				((w4 & 0xFF000000) >> 8) | (w6 & 0xFF000000);
			key4 = UInt32(byte(w1)) | ((w3 & 0x000000FF) << 8) |
				((w5 & 0x000000FF) << 16) | ((w7 & 0x000000FF) << 24);
			key5 = UInt32(byte(w1 >> 8)) | (w3 & 0x0000FF00) |
				((w5 & 0x0000FF00) << 8) | ((w7 & 0x0000FF00) << 16);
			key6 = UInt32(byte(w1 >> 16)) | ((w3 & 0x00FF0000) >> 8) |
				(w5 & 0x00FF0000) | ((w7 & 0x00FF0000) << 8);
			key7 = (w1 >> 24) | ((w3 & 0xFF000000) >> 16) |
				((w5 & 0xFF000000) >> 8) | (w7 & 0xFF000000);

			r = _hash[i];
			l = _hash[(size_t)i + 1];

			t = key0 + r;
			l = l ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);
			t = key1 + l;
			r = r ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);
			t = key2 + r;
			l = l ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);
			t = key3 + l;
			r = r ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);
			t = key4 + r;
			l = l ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);
			t = key5 + l;
			r = r ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);
			t = key6 + r;
			l = l ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);
			t = key7 + l;
			r = r ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);
			t = key0 + r;
			l = l ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);
			t = key1 + l;
			r = r ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);
			t = key2 + r;
			l = l ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);
			t = key3 + l;
			r = r ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);
			t = key4 + r;
			l = l ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);
			t = key5 + l;
			r = r ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);
			t = key6 + r;
			l = l ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);
			t = key7 + l;
			r = r ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);
			t = key0 + r;
			l = l ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);
			t = key1 + l;
			r = r ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);
			t = key2 + r;
			l = l ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);
			t = key3 + l;
			r = r ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);
			t = key4 + r;
			l = l ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);
			t = key5 + l;
			r = r ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);
			t = key6 + r;
			l = l ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);
			t = key7 + l;
			r = r ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);
			t = key7 + r;
			l = l ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);
			t = key6 + l;
			r = r ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);
			t = key5 + r;
			l = l ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);
			t = key4 + l;
			r = r ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);
			t = key3 + r;
			l = l ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);
			t = key2 + l;
			r = r ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);
			t = key1 + r;
			l = l ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);
			t = key0 + l;
			r = r ^ (sbox1[byte(t)] ^ sbox2[byte(t >> 8)] ^ sbox3
				[byte(t >> 16)] ^ sbox4[t >> 24]);

			t = r;
			r = l;
			l = t;

			s[i] = r;
			s[(size_t)i + 1] = l;

			if (i == 6)
				break;

			l = u0 ^ u2;
			r = u1 ^ u3;
			u0 = u2;
			u1 = u3;
			u2 = u4;
			u3 = u5;
			u4 = u6;
			u5 = u7;
			u6 = l;
			u7 = r;

			if (i == 2)
			{
				u0 = u0 ^ 0xFF00FF00;
				u1 = u1 ^ 0xFF00FF00;
				u2 = u2 ^ 0x00FF00FF;
				u3 = u3 ^ 0x00FF00FF;
				u4 = u4 ^ 0x00FFFF00;
				u5 = u5 ^ 0xFF0000FF;
				u6 = u6 ^ 0x000000FF;
				u7 = u7 ^ 0xFF00FFFF;
			} // end if

			l = v0;
			r = v2;
			v0 = v4;
			v2 = v6;
			v4 = l ^ r;
			v6 = v0 ^ r;
			l = v1;
			r = v3;
			v1 = v5;
			v3 = v7;
			v5 = l ^ r;
			v7 = v1 ^ r;

			i += 2;
		} // end while

		u0 = a_m[0] ^ s[6];
		u1 = a_m[1] ^ s[7];
		u2 = a_m[2] ^ (s[0] << 16) ^ (s[0] >> 16) ^ (s[0] & 0xFFFF)
			^ (s[1] & 0xFFFF) ^ (s[1] >> 16) ^ (s[2] << 16)
			^ s[6] ^ (s[6] << 16) ^ (s[7] & 0xFFFF0000) ^ (s[7] >> 16);
		u3 = a_m[3] ^ (s[0] & 0xFFFF) ^ (s[0] << 16) ^ (s[1] & 0xFFFF)
			^ (s[1] << 16) ^ (s[1] >> 16) ^ (s[2] << 16) ^ (s[2] >> 16)
			^ (s[3] << 16) ^ s[6] ^ (s[6] << 16) ^ (s[6] >> 16)
			^ (s[7] & 0xFFFF) ^ (s[7] << 16) ^ (s[7] >> 16);
		u4 = a_m[4] ^ (s[0] & 0xFFFF0000) ^ (s[0] << 16) ^ (s[0] >> 16)
			^ (s[1] & 0xFFFF0000) ^ (s[1] >> 16) ^ (s[2] << 16)
			^ (s[2] >> 16) ^ (s[3] << 16) ^ (s[3] >> 16) ^ (s[4] << 16)
			^ (s[6] << 16) ^ (s[6] >> 16) ^ (s[7] & 0xFFFF) ^ (s[7] << 16)
			^ (s[7] >> 16);
		u5 = a_m[5] ^ (s[0] << 16) ^ (s[0] >> 16) ^ (s[0] & 0xFFFF0000)
			^ (s[1] & 0xFFFF) ^ s[2] ^ (s[2] >> 16) ^ (s[3] << 16)
			^ (s[3] >> 16) ^ (s[4] << 16) ^ (s[4] >> 16) ^ (s[5] << 16)
			^ (s[6] << 16) ^ (s[6] >> 16) ^ (s[7] & 0xFFFF0000)
			^ (s[7] << 16) ^ (s[7] >> 16);
		u6 = a_m[6] ^ s[0] ^ (s[1] >> 16) ^ (s[2] << 16)
			^ s[3] ^ (s[3] >> 16) ^ (s[4] << 16) ^ (s[4] >> 16)
			^ (s[5] << 16) ^ (s[5] >> 16) ^ s[6] ^ (s[6] << 16)
			^ (s[6] >> 16) ^ (s[7] << 16);
		u7 = a_m[7] ^ (s[0] & 0xFFFF0000) ^ (s[0] << 16) ^ (s[1] & 0xFFFF)
			^ (s[1] << 16) ^ (s[2] >> 16) ^ (s[3] << 16)
			^ s[4] ^ (s[4] >> 16) ^ (s[5] << 16) ^ (s[5] >> 16)
			^ (s[6] >> 16) ^ (s[7] & 0xFFFF) ^ (s[7] << 16) ^ (s[7] >> 16);

		v0 = _hash[0] ^ (u1 << 16) ^ (u0 >> 16);
		v1 = _hash[1] ^ (u2 << 16) ^ (u1 >> 16);
		v2 = _hash[2] ^ (u3 << 16) ^ (u2 >> 16);
		v3 = _hash[3] ^ (u4 << 16) ^ (u3 >> 16);
		v4 = _hash[4] ^ (u5 << 16) ^ (u4 >> 16);
		v5 = _hash[5] ^ (u6 << 16) ^ (u5 >> 16);
		v6 = _hash[6] ^ (u7 << 16) ^ (u6 >> 16);
		v7 = _hash[7] ^ (u0 & 0xFFFF0000) ^ (u0 << 16) ^ (u7 >> 16)
			^ (u1 & 0xFFFF0000) ^ (u1 << 16) ^ (u6 << 16)
			^ (u7 & 0xFFFF0000);

		_hash[0] = (v0 & 0xFFFF0000) ^ (v0 << 16) ^ (v0 >> 16)
			^ (v1 >> 16) ^ (v1 & 0xFFFF0000) ^ (v2 << 16) ^ (v3 >> 16)
			^ (v4 << 16) ^ (v5 >> 16) ^ v5 ^ (v6 >> 16) ^ (v7 << 16)
			^ (v7 >> 16) ^ (v7 & 0xFFFF);
		_hash[1] = (v0 << 16) ^ (v0 >> 16) ^ (v0 & 0xFFFF0000)
			^ (v1 & 0xFFFF) ^ v2 ^ (v2 >> 16) ^ (v3 << 16) ^ (v4 >> 16)
			^ (v5 << 16) ^ (v6 << 16) ^ v6 ^ (v7 & 0xFFFF0000)
			^ (v7 >> 16);
		_hash[2] = (v0 & 0xFFFF) ^ (v0 << 16) ^ (v1 << 16) ^ (v1 >> 16)
			^ (v1 & 0xFFFF0000) ^ (v2 << 16) ^ (v3 >> 16)
			^ v3 ^ (v4 << 16) ^ (v5 >> 16) ^ v6 ^ (v6 >> 16)
			^ (v7 & 0xFFFF) ^ (v7 << 16) ^ (v7 >> 16);
		_hash[3] = (v0 << 16) ^ (v0 >> 16) ^ (v0 & 0xFFFF0000)
			^ (v1 & 0xFFFF0000) ^ (v1 >> 16) ^ (v2 << 16) ^ (v2 >> 16)
			^ v2 ^ (v3 << 16) ^ (v4 >> 16) ^ v4 ^ (v5 << 16)
			^ (v6 << 16) ^ (v7 & 0xFFFF) ^ (v7 >> 16);
		_hash[4] = (v0 >> 16) ^ (v1 << 16) ^ v1 ^ (v2 >> 16)
			^ v2 ^ (v3 << 16) ^ (v3 >> 16) ^ v3 ^ (v4 << 16)
			^ (v5 >> 16) ^ v5 ^ (v6 << 16) ^ (v6 >> 16) ^ (v7 << 16);
		_hash[5] = (v0 << 16) ^ (v0 & 0xFFFF0000) ^ (v1 << 16)
			^ (v1 >> 16) ^ (v1 & 0xFFFF0000) ^ (v2 << 16)
			^ v2 ^ (v3 >> 16) ^ v3 ^ (v4 << 16) ^ (v4 >> 16)
			^ v4 ^ (v5 << 16) ^ (v6 << 16) ^ (v6 >> 16)
			^ v6 ^ (v7 << 16) ^ (v7 >> 16) ^ (v7 & 0xFFFF0000);
		_hash[6] = v0 ^ v2 ^ (v2 >> 16) ^ v3 ^ (v3 << 16)
			^ v4 ^ (v4 >> 16) ^ (v5 << 16) ^ (v5 >> 16)
			^ v5 ^ (v6 << 16) ^ (v6 >> 16) ^ v6 ^ (v7 << 16) ^ v7;
		_hash[7] = v0 ^ (v0 >> 16) ^ (v1 << 16) ^ (v1 >> 16)
			^ (v2 << 16) ^ (v3 >> 16) ^ v3 ^ (v4 << 16)
			^ v4 ^ (v5 >> 16) ^ v5 ^ (v6 << 16) ^ (v6 >> 16)
			^ (v7 << 16) ^ v7;

	} // end function Compress

protected:
	virtual void Finish()
	{
		UInt64 bits = _processed_bytes * 8;

		if (_buffer.GetPos() > 0)
		{
			HashLibByteArray pad = HashLibByteArray(32 - (size_t)_buffer.GetPos());
			TransformBytes(pad, 0, 32 - _buffer.GetPos());
		} // end if

		HashLibUInt32Array length = HashLibUInt32Array(8);
		length[0] = (UInt32)bits;
		length[1] = (UInt32)(bits >> 32);

		Compress(&length[0]);

		Compress(&_state[0]);

	} // end function Finish

	virtual HashLibByteArray GetResult()
	{
		HashLibByteArray result = HashLibByteArray(8 * sizeof(UInt32));

		Converters::le32_copy((UInt32*)(&_hash[0]), 0, (byte*)&result[0], 0, (Int32)result.size());

		return result;
	} // end function GetResult

	virtual void TransformBlock(const byte* a_data,
		const Int32 a_data_length, const Int32 a_index)
	{
		UInt32 c, a, b;
		
		HashLibUInt32Array data = HashLibUInt32Array(8);
		HashLibUInt32Array m = HashLibUInt32Array(8);

		c = 0;

		Converters::le32_copy(a_data, a_index, &data[0], 0, 32);

		for (UInt32 i = 0; i < 8; i++)
		{
			a = data[i];
			m[i] = a;
			b = _state[i];
			c = a + c + _state[i];
			_state[i] = c;

			if ((c < a) || (c < b))
				c = 1;
			else
				c = 0;

		} // end for

		Compress(&m[0]);

		ArrayUtils::zeroFill(m);
		ArrayUtils::zeroFill(data);
	} // end function TransformBlock

	static char initializedStaticLoader()
	{
		UInt32 ax, bx, cx, dx;

		HashLibMatrixUInt32Array sbox = HashLibMatrixUInt32Array({ HashLibUInt32Array({ 4, 10, 9,
			2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3 }), HashLibUInt32Array({ 14,
				11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9 }),
			HashLibUInt32Array({ 5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9,
				11 }), HashLibUInt32Array({ 7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11,
					2, 5, 3 }), HashLibUInt32Array({ 6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9,
						14, 0, 3, 11, 2 }), HashLibUInt32Array({ 4, 11, 10, 0, 7, 2, 1, 13, 3,
							6, 8, 5, 9, 12, 15, 14 }), HashLibUInt32Array({ 13, 11, 4, 1, 3, 15, 5,
								9, 0, 10, 14, 7, 6, 8, 2, 12 }), HashLibUInt32Array({ 1, 15, 13, 0, 5,
									7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12 }) });

		UInt32 i = 0;

		for (UInt32 a = 0; a < 16; a++)
		{
			ax = sbox[1][a] << 15;
			bx = sbox[3][a] << 23;
			cx = sbox[5][a];
			cx = Bits::RotateRight32(cx, 1);
			dx = sbox[7][a] << 7;

			for (UInt32 b = 0; b < 16; b++)
			{
				sbox1[i] = ax | (sbox[0][b] << 11);
				sbox2[i] = bx | (sbox[2][b] << 19);
				sbox3[i] = cx | (sbox[4][b] << 27);
				sbox4[i] = dx | (sbox[6][b] << 3);
				i++;
			} // end for
		} // end for

		return 'I';
	}

protected:
	HashLibUInt32Array _state;
	HashLibUInt32Array _hash;

	static char _initialized;
	static HashLibUInt32Array sbox1;
	static HashLibUInt32Array sbox2;
	static HashLibUInt32Array sbox3;
	static HashLibUInt32Array sbox4;
}; // end class Gost

HashLibUInt32Array Gost::sbox1 = HashLibUInt32Array(256);
HashLibUInt32Array Gost::sbox2 = HashLibUInt32Array(256);
HashLibUInt32Array Gost::sbox3 = HashLibUInt32Array(256);
HashLibUInt32Array Gost::sbox4 = HashLibUInt32Array(256);

char Gost::_initialized = Gost::initializedStaticLoader();
