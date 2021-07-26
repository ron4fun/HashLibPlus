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

#include "MDBase.h"

class MD5 : public MDBase, public virtual IITransformBlock
{
public:
	MD5()
		: MDBase(4, 16)
	{
		_name = __func__;
	} // end constructor

	virtual IHash Clone() const
	{
		MD5 HashInstance = MD5();
		HashInstance._state = _state;
		HashInstance._buffer = _buffer.Clone();
		HashInstance._processed_bytes = _processed_bytes;

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<MD5>(HashInstance);
	}

protected:
	virtual void TransformBlock(const byte* a_data,
		const Int32 a_data_length, const Int32 a_index)
	{
		UInt32 A, B, C, D;
		HashLibUInt32Array data = HashLibUInt32Array(16);

		Converters::le32_copy(a_data, a_index, &data[0], 0, 64);

		A = _state[0];
		B = _state[1];
		C = _state[2];
		D = _state[3];

		A = data[0] + 0xD76AA478 + A + ((B & C) | ((~B) & D));
		A = Bits::RotateLeft32(A, 7) + B;
		D = data[1] + 0xE8C7B756 + D + ((A & B) | (~A & C));
		D = Bits::RotateLeft32(D, 12) + A;
		C = data[2] + 0x242070DB + C + ((D & A) | (~D & B));
		C = Bits::RotateLeft32(C, 17) + D;
		B = data[3] + 0xC1BDCEEE + B + ((C & D) | (~C & A));
		B = Bits::RotateLeft32(B, 22) + C;
		A = data[4] + 0xF57C0FAF + A + ((B & C) | (~B & D));
		A = Bits::RotateLeft32(A, 7) + B;
		D = data[5] + 0x4787C62A + D + ((A & B) | (~A & C));
		D = Bits::RotateLeft32(D, 12) + A;
		C = data[6] + 0xA8304613 + C + ((D & A) | (~D & B));
		C = Bits::RotateLeft32(C, 17) + D;
		B = data[7] + 0xFD469501 + B + ((C & D) | (~C & A));
		B = Bits::RotateLeft32(B, 22) + C;
		A = data[8] + 0x698098D8 + A + ((B & C) | (~B & D));
		A = Bits::RotateLeft32(A, 7) + B;
		D = data[9] + 0x8B44F7AF + D + ((A & B) | (~A & C));
		D = Bits::RotateLeft32(D, 12) + A;
		C = data[10] + 0xFFFF5BB1 + C + ((D & A) | (~D & B));
		C = Bits::RotateLeft32(C, 17) + D;
		B = data[11] + 0x895CD7BE + B + ((C & D) | (~C & A));
		B = Bits::RotateLeft32(B, 22) + C;
		A = data[12] + 0x6B901122 + A + ((B & C) | (~B & D));
		A = Bits::RotateLeft32(A, 7) + B;
		D = data[13] + 0xFD987193 + D + ((A & B) | (~A & C));
		D = Bits::RotateLeft32(D, 12) + A;
		C = data[14] + 0xA679438E + C + ((D & A) | (~D & B));
		C = Bits::RotateLeft32(C, 17) + D;
		B = data[15] + 0x49B40821 + B + ((C & D) | (~C & A));
		B = Bits::RotateLeft32(B, 22) + C;

		A = data[1] + 0xF61E2562 + A + ((B & D) | (C & ~D));
		A = Bits::RotateLeft32(A, 5) + B;
		D = data[6] + 0xC040B340 + D + ((A & C) | (B & ~C));
		D = Bits::RotateLeft32(D, 9) + A;
		C = data[11] + 0x265E5A51 + C + ((D & B) | (A & ~B));
		C = Bits::RotateLeft32(C, 14) + D;
		B = data[0] + 0xE9B6C7AA + B + ((C & A) | (D & ~A));
		B = Bits::RotateLeft32(B, 20) + C;
		A = data[5] + 0xD62F105D + A + ((B & D) | (C & ~D));
		A = Bits::RotateLeft32(A, 5) + B;
		D = data[10] + 0x2441453 + D + ((A & C) | (B & ~C));
		D = Bits::RotateLeft32(D, 9) + A;
		C = data[15] + 0xD8A1E681 + C + ((D & B) | (A & ~B));
		C = Bits::RotateLeft32(C, 14) + D;
		B = data[4] + 0xE7D3FBC8 + B + ((C & A) | (D & ~A));
		B = Bits::RotateLeft32(B, 20) + C;
		A = data[9] + 0x21E1CDE6 + A + ((B & D) | (C & ~D));
		A = Bits::RotateLeft32(A, 5) + B;
		D = data[14] + 0xC33707D6 + D + ((A & C) | (B & ~C));
		D = Bits::RotateLeft32(D, 9) + A;
		C = data[3] + 0xF4D50D87 + C + ((D & B) | (A & ~B));
		C = Bits::RotateLeft32(C, 14) + D;
		B = data[8] + 0x455A14ED + B + ((C & A) | (D & ~A));
		B = Bits::RotateLeft32(B, 20) + C;
		A = data[13] + 0xA9E3E905 + A + ((B & D) | (C & ~D));
		A = Bits::RotateLeft32(A, 5) + B;
		D = data[2] + 0xFCEFA3F8 + D + ((A & C) | (B & ~C));
		D = Bits::RotateLeft32(D, 9) + A;
		C = data[7] + 0x676F02D9 + C + ((D & B) | (A & ~B));
		C = Bits::RotateLeft32(C, 14) + D;
		B = data[12] + 0x8D2A4C8A + B + ((C & A) | (D & ~A));
		B = Bits::RotateLeft32(B, 20) + C;

		A = data[5] + 0xFFFA3942 + A + (B ^ C ^ D);
		A = Bits::RotateLeft32(A, 4) + B;
		D = data[8] + 0x8771F681 + D + (A ^ B ^ C);
		D = Bits::RotateLeft32(D, 11) + A;
		C = data[11] + 0x6D9D6122 + C + (D ^ A ^ B);
		C = Bits::RotateLeft32(C, 16) + D;
		B = data[14] + 0xFDE5380C + B + (C ^ D ^ A);
		B = Bits::RotateLeft32(B, 23) + C;
		A = data[1] + 0xA4BEEA44 + A + (B ^ C ^ D);
		A = Bits::RotateLeft32(A, 4) + B;
		D = data[4] + 0x4BDECFA9 + D + (A ^ B ^ C);
		D = Bits::RotateLeft32(D, 11) + A;
		C = data[7] + 0xF6BB4B60 + C + (D ^ A ^ B);
		C = Bits::RotateLeft32(C, 16) + D;
		B = data[10] + 0xBEBFBC70 + B + (C ^ D ^ A);
		B = Bits::RotateLeft32(B, 23) + C;
		A = data[13] + 0x289B7EC6 + A + (B ^ C ^ D);
		A = Bits::RotateLeft32(A, 4) + B;
		D = data[0] + 0xEAA127FA + D + (A ^ B ^ C);
		D = Bits::RotateLeft32(D, 11) + A;
		C = data[3] + 0xD4EF3085 + C + (D ^ A ^ B);
		C = Bits::RotateLeft32(C, 16) + D;
		B = data[6] + 0x4881D05 + B + (C ^ D ^ A);
		B = Bits::RotateLeft32(B, 23) + C;
		A = data[9] + 0xD9D4D039 + A + (B ^ C ^ D);
		A = Bits::RotateLeft32(A, 4) + B;
		D = data[12] + 0xE6DB99E5 + D + (A ^ B ^ C);
		D = Bits::RotateLeft32(D, 11) + A;
		C = data[15] + 0x1FA27CF8 + C + (D ^ A ^ B);
		C = Bits::RotateLeft32(C, 16) + D;
		B = data[2] + 0xC4AC5665 + B + (C ^ D ^ A);
		B = Bits::RotateLeft32(B, 23) + C;

		A = data[0] + 0xF4292244 + A + (C ^ (B | ~D));
		A = Bits::RotateLeft32(A, 6) + B;
		D = data[7] + 0x432AFF97 + D + (B ^ (A | ~C));
		D = Bits::RotateLeft32(D, 10) + A;
		C = data[14] + 0xAB9423A7 + C + (A ^ (D | ~B));
		C = Bits::RotateLeft32(C, 15) + D;
		B = data[5] + 0xFC93A039 + B + (D ^ (C | ~A));
		B = Bits::RotateLeft32(B, 21) + C;
		A = data[12] + 0x655B59C3 + A + (C ^ (B | ~D));
		A = Bits::RotateLeft32(A, 6) + B;
		D = data[3] + 0x8F0CCC92 + D + (B ^ (A | ~C));
		D = Bits::RotateLeft32(D, 10) + A;
		C = data[10] + 0xFFEFF47D + C + (A ^ (D | ~B));
		C = Bits::RotateLeft32(C, 15) + D;
		B = data[1] + 0x85845DD1 + B + (D ^ (C | ~A));
		B = Bits::RotateLeft32(B, 21) + C;
		A = data[8] + 0x6FA87E4F + A + (C ^ (B | ~D));
		A = Bits::RotateLeft32(A, 6) + B;
		D = data[15] + 0xFE2CE6E0 + D + (B ^ (A | ~C));
		D = Bits::RotateLeft32(D, 10) + A;
		C = data[6] + 0xA3014314 + C + (A ^ (D | ~B));
		C = Bits::RotateLeft32(C, 15) + D;
		B = data[13] + 0x4E0811A1 + B + (D ^ (C | ~A));
		B = Bits::RotateLeft32(B, 21) + C;
		A = data[4] + 0xF7537E82 + A + (C ^ (B | ~D));
		A = Bits::RotateLeft32(A, 6) + B;
		D = data[11] + 0xBD3AF235 + D + (B ^ (A | ~C));
		D = Bits::RotateLeft32(D, 10) + A;
		C = data[2] + 0x2AD7D2BB + C + (A ^ (D | ~B));
		C = Bits::RotateLeft32(C, 15) + D;
		B = data[9] + 0xEB86D391 + B + (D ^ (C | ~A));
		B = Bits::RotateLeft32(B, 21) + C;

		_state[0] = _state[0] + A;
		_state[1] = _state[1] + B;
		_state[2] = _state[2] + C;
		_state[3] = _state[3] + D;

		memset(&data[0], 0, data.size() * sizeof(UInt32));
	} // end function TransformBlock
	
}; // end class MD5
