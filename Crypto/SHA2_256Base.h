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

class SHA2_256Base : public BlockHash, public virtual IICryptoNotBuildIn, public virtual IITransformBlock
{
protected:
	SHA2_256Base() {}

	SHA2_256Base(const Int32 a_hash_size)
		: BlockHash(a_hash_size, 64)
	{
		_state.resize(8);		
	} // end constructor

	virtual void Finish()
	{
		Int32 padindex;

		UInt64 bits = _processed_bytes * 8;
		if (_buffer.GetPos() < 56)
			padindex = 56 - _buffer.GetPos();
		else
			padindex = 120 - _buffer.GetPos();

		HashLibByteArray pad = HashLibByteArray((size_t)padindex + 8);

		pad[0] = 0x80;

		bits = Converters::be2me_64(bits);

		Converters::ReadUInt64AsBytesLE(bits, pad, padindex);

		padindex = padindex + 8;

		TransformBytes(pad, 0, padindex);

	} // end function Finish

	virtual void TransformBlock(const byte* a_data,
		const Int32 a_data_length, const Int32 a_index)
	{
		UInt32 A, B, C, D, E, F, G, H, T, T2;
		
		HashLibUInt32Array data = HashLibUInt32Array(64);

		Converters::be32_copy(a_data, a_index, &data[0], 0, 64);

		A = _state[0];
		B = _state[1];
		C = _state[2];
		D = _state[3];
		E = _state[4];
		F = _state[5];
		G = _state[6];
		H = _state[7];

		// Step 1

		T = data[14];
		T2 = data[1];
		data[16] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[9] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[0];

		T = data[15];
		T2 = data[2];
		data[17] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[10] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[1];

		T = data[16];
		T2 = data[3];
		data[18] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[11] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[2];

		T = data[17];
		T2 = data[4];
		data[19] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[12] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[3];

		T = data[18];
		T2 = data[5];
		data[20] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[13] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[4];

		T = data[19];
		T2 = data[6];
		data[21] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[14] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[5];

		T = data[20];
		T2 = data[7];
		data[22] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[15] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[6];

		T = data[21];
		T2 = data[8];
		data[23] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[16] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[7];

		T = data[22];
		T2 = data[9];
		data[24] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[17] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[8];

		T = data[23];
		T2 = data[10];
		data[25] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[18] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[9];

		T = data[24];
		T2 = data[11];
		data[26] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[19] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[10];

		T = data[25];
		T2 = data[12];
		data[27] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[20] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[11];

		T = data[26];
		T2 = data[13];
		data[28] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[21] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[12];

		T = data[27];
		T2 = data[14];
		data[29] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[22] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[13];

		T = data[28];
		T2 = data[15];
		data[30] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[23] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[14];

		T = data[29];
		T2 = data[16];
		data[31] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[24] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[15];

		T = data[30];
		T2 = data[17];
		data[32] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[25] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[16];

		T = data[31];
		T2 = data[18];
		data[33] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[26] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[17];

		T = data[32];
		T2 = data[19];
		data[34] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[27] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[18];

		T = data[33];
		T2 = data[20];
		data[35] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[28] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[19];

		T = data[34];
		T2 = data[21];
		data[36] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[29] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[20];

		T = data[35];
		T2 = data[22];
		data[37] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[30] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[21];

		T = data[36];
		T2 = data[23];
		data[38] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[31] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[22];

		T = data[37];
		T2 = data[24];
		data[39] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[32] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[23];

		T = data[38];
		T2 = data[25];
		data[40] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[33] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[24];

		T = data[39];
		T2 = data[26];
		data[41] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[34] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[25];

		T = data[40];
		T2 = data[27];
		data[42] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[35] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[26];

		T = data[41];
		T2 = data[28];
		data[43] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[36] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[27];

		T = data[42];
		T2 = data[29];
		data[44] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[37] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[28];

		T = data[43];
		T2 = data[30];
		data[45] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[38] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[29];

		T = data[44];
		T2 = data[31];
		data[46] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[39] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[30];

		T = data[45];
		T2 = data[32];
		data[47] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[40] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[31];

		T = data[46];
		T2 = data[33];
		data[48] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[41] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[32];

		T = data[47];
		T2 = data[34];
		data[49] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[42] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[33];

		T = data[48];
		T2 = data[35];
		data[50] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[43] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[34];

		T = data[49];
		T2 = data[36];
		data[51] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[44] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[35];

		T = data[50];
		T2 = data[37];
		data[52] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[45] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[36];

		T = data[51];
		T2 = data[38];
		data[53] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[46] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[37];

		T = data[52];
		T2 = data[39];
		data[54] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[47] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[38];

		T = data[53];
		T2 = data[40];
		data[55] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[48] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[39];

		T = data[54];
		T2 = data[41];
		data[56] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[49] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[40];

		T = data[55];
		T2 = data[42];
		data[57] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[50] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[41];

		T = data[56];
		T2 = data[43];
		data[58] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[51] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[42];

		T = data[57];
		T2 = data[44];
		data[59] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[52] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[43];

		T = data[58];
		T2 = data[45];
		data[60] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[53] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[44];

		T = data[59];
		T2 = data[46];
		data[61] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[54] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[45];

		T = data[60];
		T2 = data[47];
		data[62] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[55] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[46];

		T = data[61];
		T2 = data[48];
		data[63] = ((Bits::RotateRight32(T, 17)) ^ (Bits::RotateRight32(T, 19))
			^ (T >> 10)) + data[56] +
			((Bits::RotateRight32(T2, 7)) ^ (Bits::RotateRight32(T2, 18))
				^ (T2 >> 3)) + data[47];

		// Step 2

		T = H + ((Bits::RotateRight32(E, 6)) ^ (Bits::RotateRight32(E, 11))
			^ (Bits::RotateRight32(E, 25))) + ((E & F) ^ (~E & G)) +
			0x428A2F98 + data[0];
		T2 = ((Bits::RotateRight32(A, 2)) ^ (Bits::RotateRight32(A, 13))
			^ ((A >> 22) ^ (A << 10))) + ((A & B) ^ (A & C) ^ (B & C));
		H = T + T2;
		D = D + T;
		T = G + ((Bits::RotateRight32(D, 6)) ^ (Bits::RotateRight32(D, 11))
			^ (Bits::RotateRight32(D, 25))) + ((D & E) ^ (~D & F)) +
			0x71374491 + data[1];
		T2 = ((Bits::RotateRight32(H, 2)) ^ (Bits::RotateRight32(H, 13))
			^ ((H >> 22) ^ (H << 10))) + ((H & A) ^ (H & B) ^ (A & B));
		G = T + T2;
		C = C + T;
		T = F + ((Bits::RotateRight32(C, 6)) ^ (Bits::RotateRight32(C, 11))
			^ (Bits::RotateRight32(C, 25))) + ((C & D) ^ (~C & E)) +
			0xB5C0FBCF + data[2];
		T2 = ((Bits::RotateRight32(G, 2)) ^ (Bits::RotateRight32(G, 13))
			^ ((G >> 22) ^ (G << 10))) + ((G & H) ^ (G & A) ^ (H & A));
		F = T + T2;
		B = B + T;
		T = E + ((Bits::RotateRight32(B, 6)) ^ (Bits::RotateRight32(B, 11))
			^ (Bits::RotateRight32(B, 25))) + ((B & C) ^ (~B & D)) +
			0xE9B5DBA5 + data[3];
		T2 = ((Bits::RotateRight32(F, 2)) ^ (Bits::RotateRight32(F, 13))
			^ ((F >> 22) ^ (F << 10))) + ((F & G) ^ (F & H) ^ (G & H));
		E = T + T2;
		A = A + T;
		T = D + ((Bits::RotateRight32(A, 6)) ^ (Bits::RotateRight32(A, 11))
			^ (Bits::RotateRight32(A, 25))) + ((A & B) ^ (~A & C)) +
			0x3956C25B + data[4];
		T2 = ((Bits::RotateRight32(E, 2)) ^ (Bits::RotateRight32(E, 13))
			^ ((E >> 22) ^ (E << 10))) + ((E & F) ^ (E & G) ^ (F & G));
		D = T + T2;
		H = H + T;
		T = C + ((Bits::RotateRight32(H, 6)) ^ (Bits::RotateRight32(H, 11))
			^ (Bits::RotateRight32(H, 25))) + ((H & A) ^ (~H & B)) +
			0x59F111F1 + data[5];
		T2 = ((Bits::RotateRight32(D, 2)) ^ (Bits::RotateRight32(D, 13))
			^ ((D >> 22) ^ (D << 10))) + ((D & E) ^ (D & F) ^ (E & F));
		C = T + T2;
		G = G + T;
		T = B + ((Bits::RotateRight32(G, 6)) ^ (Bits::RotateRight32(G, 11))
			^ (Bits::RotateRight32(G, 25))) + ((G & H) ^ (~G & A)) +
			0x923F82A4 + data[6];
		T2 = ((Bits::RotateRight32(C, 2)) ^ (Bits::RotateRight32(C, 13))
			^ ((C >> 22) ^ (C << 10))) + ((C & D) ^ (C & E) ^ (D & E));
		B = T + T2;
		F = F + T;
		T = A + ((Bits::RotateRight32(F, 6)) ^ (Bits::RotateRight32(F, 11))
			^ (Bits::RotateRight32(F, 25))) + ((F & G) ^ (~F & H)) +
			0xAB1C5ED5 + data[7];
		T2 = ((Bits::RotateRight32(B, 2)) ^ (Bits::RotateRight32(B, 13))
			^ ((B >> 22) ^ (B << 10))) + ((B & C) ^ (B & D) ^ (C & D));
		A = T + T2;
		E = E + T;
		T = H + ((Bits::RotateRight32(E, 6)) ^ (Bits::RotateRight32(E, 11))
			^ (Bits::RotateRight32(E, 25))) + ((E & F) ^ (~E & G)) +
			0xD807AA98 + data[8];
		T2 = ((Bits::RotateRight32(A, 2)) ^ (Bits::RotateRight32(A, 13))
			^ ((A >> 22) ^ (A << 10))) + ((A & B) ^ (A & C) ^ (B & C));
		H = T + T2;
		D = D + T;
		T = G + ((Bits::RotateRight32(D, 6)) ^ (Bits::RotateRight32(D, 11))
			^ (Bits::RotateRight32(D, 25))) + ((D & E) ^ (~D & F)) +
			0x12835B01 + data[9];
		T2 = ((Bits::RotateRight32(H, 2)) ^ (Bits::RotateRight32(H, 13))
			^ ((H >> 22) ^ (H << 10))) + ((H & A) ^ (H & B) ^ (A & B));
		G = T + T2;
		C = C + T;
		T = F + ((Bits::RotateRight32(C, 6)) ^ (Bits::RotateRight32(C, 11))
			^ (Bits::RotateRight32(C, 25))) + ((C & D) ^ (~C & E)) +
			0x243185BE + data[10];
		T2 = ((Bits::RotateRight32(G, 2)) ^ (Bits::RotateRight32(G, 13))
			^ ((G >> 22) ^ (G << 10))) + ((G & H) ^ (G & A) ^ (H & A));
		F = T + T2;
		B = B + T;
		T = E + ((Bits::RotateRight32(B, 6)) ^ (Bits::RotateRight32(B, 11))
			^ (Bits::RotateRight32(B, 25))) + ((B & C) ^ (~B & D)) +
			0x550C7DC3 + data[11];
		T2 = ((Bits::RotateRight32(F, 2)) ^ (Bits::RotateRight32(F, 13))
			^ ((F >> 22) ^ (F << 10))) + ((F & G) ^ (F & H) ^ (G & H));
		E = T + T2;
		A = A + T;
		T = D + ((Bits::RotateRight32(A, 6)) ^ (Bits::RotateRight32(A, 11))
			^ (Bits::RotateRight32(A, 25))) + ((A & B) ^ (~A & C)) +
			0x72BE5D74 + data[12];
		T2 = ((Bits::RotateRight32(E, 2)) ^ (Bits::RotateRight32(E, 13))
			^ ((E >> 22) ^ (E << 10))) + ((E & F) ^ (E & G) ^ (F & G));
		D = T + T2;
		H = H + T;
		T = C + ((Bits::RotateRight32(H, 6)) ^ (Bits::RotateRight32(H, 11))
			^ (Bits::RotateRight32(H, 25))) + ((H & A) ^ (~H & B)) +
			0x80DEB1FE + data[13];
		T2 = ((Bits::RotateRight32(D, 2)) ^ (Bits::RotateRight32(D, 13))
			^ ((D >> 22) ^ (D << 10))) + ((D & E) ^ (D & F) ^ (E & F));
		C = T + T2;
		G = G + T;
		T = B + ((Bits::RotateRight32(G, 6)) ^ (Bits::RotateRight32(G, 11))
			^ (Bits::RotateRight32(G, 25))) + ((G & H) ^ (~G & A)) +
			0x9BDC06A7 + data[14];
		T2 = ((Bits::RotateRight32(C, 2)) ^ (Bits::RotateRight32(C, 13))
			^ ((C >> 22) ^ (C << 10))) + ((C & D) ^ (C & E) ^ (D & E));
		B = T + T2;
		F = F + T;
		T = A + ((Bits::RotateRight32(F, 6)) ^ (Bits::RotateRight32(F, 11))
			^ (Bits::RotateRight32(F, 25))) + ((F & G) ^ (~F & H)) +
			0xC19BF174 + data[15];
		T2 = ((Bits::RotateRight32(B, 2)) ^ (Bits::RotateRight32(B, 13))
			^ ((B >> 22) ^ (B << 10))) + ((B & C) ^ (B & D) ^ (C & D));
		A = T + T2;
		E = E + T;
		T = H + ((Bits::RotateRight32(E, 6)) ^ (Bits::RotateRight32(E, 11))
			^ (Bits::RotateRight32(E, 25))) + ((E & F) ^ (~E & G)) +
			0xE49B69C1 + data[16];
		T2 = ((Bits::RotateRight32(A, 2)) ^ (Bits::RotateRight32(A, 13))
			^ ((A >> 22) ^ (A << 10))) + ((A & B) ^ (A & C) ^ (B & C));
		H = T + T2;
		D = D + T;
		T = G + ((Bits::RotateRight32(D, 6)) ^ (Bits::RotateRight32(D, 11))
			^ (Bits::RotateRight32(D, 25))) + ((D & E) ^ (~D & F)) +
			0xEFBE4786 + data[17];
		T2 = ((Bits::RotateRight32(H, 2)) ^ (Bits::RotateRight32(H, 13))
			^ ((H >> 22) ^ (H << 10))) + ((H & A) ^ (H & B) ^ (A & B));
		G = T + T2;
		C = C + T;
		T = F + ((Bits::RotateRight32(C, 6)) ^ (Bits::RotateRight32(C, 11))
			^ (Bits::RotateRight32(C, 25))) + ((C & D) ^ (~C & E)) +
			0x0FC19DC6 + data[18];
		T2 = ((Bits::RotateRight32(G, 2)) ^ (Bits::RotateRight32(G, 13))
			^ ((G >> 22) ^ (G << 10))) + ((G & H) ^ (G & A) ^ (H & A));
		F = T + T2;
		B = B + T;
		T = E + ((Bits::RotateRight32(B, 6)) ^ (Bits::RotateRight32(B, 11))
			^ (Bits::RotateRight32(B, 25))) + ((B & C) ^ (~B & D)) +
			0x240CA1CC + data[19];
		T2 = ((Bits::RotateRight32(F, 2)) ^ (Bits::RotateRight32(F, 13))
			^ ((F >> 22) ^ (F << 10))) + ((F & G) ^ (F & H) ^ (G & H));
		E = T + T2;
		A = A + T;
		T = D + ((Bits::RotateRight32(A, 6)) ^ (Bits::RotateRight32(A, 11))
			^ (Bits::RotateRight32(A, 25))) + ((A & B) ^ (~A & C)) +
			0x2DE92C6F + data[20];
		T2 = ((Bits::RotateRight32(E, 2)) ^ (Bits::RotateRight32(E, 13))
			^ ((E >> 22) ^ (E << 10))) + ((E & F) ^ (E & G) ^ (F & G));
		D = T + T2;
		H = H + T;
		T = C + ((Bits::RotateRight32(H, 6)) ^ (Bits::RotateRight32(H, 11))
			^ (Bits::RotateRight32(H, 25))) + ((H & A) ^ (~H & B)) +
			0x4A7484AA + data[21];
		T2 = ((Bits::RotateRight32(D, 2)) ^ (Bits::RotateRight32(D, 13))
			^ ((D >> 22) ^ (D << 10))) + ((D & E) ^ (D & F) ^ (E & F));
		C = T + T2;
		G = G + T;
		T = B + ((Bits::RotateRight32(G, 6)) ^ (Bits::RotateRight32(G, 11))
			^ (Bits::RotateRight32(G, 25))) + ((G & H) ^ (~G & A)) +
			0x5CB0A9DC + data[22];
		T2 = ((Bits::RotateRight32(C, 2)) ^ (Bits::RotateRight32(C, 13))
			^ ((C >> 22) ^ (C << 10))) + ((C & D) ^ (C & E) ^ (D & E));
		B = T + T2;
		F = F + T;
		T = A + ((Bits::RotateRight32(F, 6)) ^ (Bits::RotateRight32(F, 11))
			^ (Bits::RotateRight32(F, 25))) + ((F & G) ^ (~F & H)) +
			0x76F988DA + data[23];
		T2 = ((Bits::RotateRight32(B, 2)) ^ (Bits::RotateRight32(B, 13))
			^ ((B >> 22) ^ (B << 10))) + ((B & C) ^ (B & D) ^ (C & D));
		A = T + T2;
		E = E + T;
		T = H + ((Bits::RotateRight32(E, 6)) ^ (Bits::RotateRight32(E, 11))
			^ (Bits::RotateRight32(E, 25))) + ((E & F) ^ (~E & G)) +
			0x983E5152 + data[24];
		T2 = ((Bits::RotateRight32(A, 2)) ^ (Bits::RotateRight32(A, 13))
			^ ((A >> 22) ^ (A << 10))) + ((A & B) ^ (A & C) ^ (B & C));
		H = T + T2;
		D = D + T;
		T = G + ((Bits::RotateRight32(D, 6)) ^ (Bits::RotateRight32(D, 11))
			^ (Bits::RotateRight32(D, 25))) + ((D & E) ^ (~D & F)) +
			0xA831C66D + data[25];
		T2 = ((Bits::RotateRight32(H, 2)) ^ (Bits::RotateRight32(H, 13))
			^ ((H >> 22) ^ (H << 10))) + ((H & A) ^ (H & B) ^ (A & B));
		G = T + T2;
		C = C + T;
		T = F + ((Bits::RotateRight32(C, 6)) ^ (Bits::RotateRight32(C, 11))
			^ (Bits::RotateRight32(C, 25))) + ((C & D) ^ (~C & E)) +
			0xB00327C8 + data[26];
		T2 = ((Bits::RotateRight32(G, 2)) ^ (Bits::RotateRight32(G, 13))
			^ ((G >> 22) ^ (G << 10))) + ((G & H) ^ (G & A) ^ (H & A));
		F = T + T2;
		B = B + T;
		T = E + ((Bits::RotateRight32(B, 6)) ^ (Bits::RotateRight32(B, 11))
			^ (Bits::RotateRight32(B, 25))) + ((B & C) ^ (~B & D)) +
			0xBF597FC7 + data[27];
		T2 = ((Bits::RotateRight32(F, 2)) ^ (Bits::RotateRight32(F, 13))
			^ ((F >> 22) ^ (F << 10))) + ((F & G) ^ (F & H) ^ (G & H));
		E = T + T2;
		A = A + T;
		T = D + ((Bits::RotateRight32(A, 6)) ^ (Bits::RotateRight32(A, 11))
			^ (Bits::RotateRight32(A, 25))) + ((A & B) ^ (~A & C)) +
			0xC6E00BF3 + data[28];
		T2 = ((Bits::RotateRight32(E, 2)) ^ (Bits::RotateRight32(E, 13))
			^ ((E >> 22) ^ (E << 10))) + ((E & F) ^ (E & G) ^ (F & G));
		D = T + T2;
		H = H + T;
		T = C + ((Bits::RotateRight32(H, 6)) ^ (Bits::RotateRight32(H, 11))
			^ (Bits::RotateRight32(H, 25))) + ((H & A) ^ (~H & B)) +
			0xD5A79147 + data[29];
		T2 = ((Bits::RotateRight32(D, 2)) ^ (Bits::RotateRight32(D, 13))
			^ ((D >> 22) ^ (D << 10))) + ((D & E) ^ (D & F) ^ (E & F));
		C = T + T2;
		G = G + T;
		T = B + ((Bits::RotateRight32(G, 6)) ^ (Bits::RotateRight32(G, 11))
			^ (Bits::RotateRight32(G, 25))) + ((G & H) ^ (~G & A)) +
			0x06CA6351 + data[30];
		T2 = ((Bits::RotateRight32(C, 2)) ^ (Bits::RotateRight32(C, 13))
			^ ((C >> 22) ^ (C << 10))) + ((C & D) ^ (C & E) ^ (D & E));
		B = T + T2;
		F = F + T;
		T = A + ((Bits::RotateRight32(F, 6)) ^ (Bits::RotateRight32(F, 11))
			^ (Bits::RotateRight32(F, 25))) + ((F & G) ^ (~F & H)) +
			0x14292967 + data[31];
		T2 = ((Bits::RotateRight32(B, 2)) ^ (Bits::RotateRight32(B, 13))
			^ ((B >> 22) ^ (B << 10))) + ((B & C) ^ (B & D) ^ (C & D));
		A = T + T2;
		E = E + T;
		T = H + ((Bits::RotateRight32(E, 6)) ^ (Bits::RotateRight32(E, 11))
			^ (Bits::RotateRight32(E, 25))) + ((E & F) ^ (~E & G)) +
			0x27B70A85 + data[32];
		T2 = ((Bits::RotateRight32(A, 2)) ^ (Bits::RotateRight32(A, 13))
			^ ((A >> 22) ^ (A << 10))) + ((A & B) ^ (A & C) ^ (B & C));
		H = T + T2;
		D = D + T;
		T = G + ((Bits::RotateRight32(D, 6)) ^ (Bits::RotateRight32(D, 11))
			^ (Bits::RotateRight32(D, 25))) + ((D & E) ^ (~D & F)) +
			0x2E1B2138 + data[33];
		T2 = ((Bits::RotateRight32(H, 2)) ^ (Bits::RotateRight32(H, 13))
			^ ((H >> 22) ^ (H << 10))) + ((H & A) ^ (H & B) ^ (A & B));
		G = T + T2;
		C = C + T;
		T = F + ((Bits::RotateRight32(C, 6)) ^ (Bits::RotateRight32(C, 11))
			^ (Bits::RotateRight32(C, 25))) + ((C & D) ^ (~C & E)) +
			0x4D2C6DFC + data[34];
		T2 = ((Bits::RotateRight32(G, 2)) ^ (Bits::RotateRight32(G, 13))
			^ ((G >> 22) ^ (G << 10))) + ((G & H) ^ (G & A) ^ (H & A));
		F = T + T2;
		B = B + T;
		T = E + ((Bits::RotateRight32(B, 6)) ^ (Bits::RotateRight32(B, 11))
			^ (Bits::RotateRight32(B, 25))) + ((B & C) ^ (~B & D)) +
			0x53380D13 + data[35];
		T2 = ((Bits::RotateRight32(F, 2)) ^ (Bits::RotateRight32(F, 13))
			^ ((F >> 22) ^ (F << 10))) + ((F & G) ^ (F & H) ^ (G & H));
		E = T + T2;
		A = A + T;
		T = D + ((Bits::RotateRight32(A, 6)) ^ (Bits::RotateRight32(A, 11))
			^ (Bits::RotateRight32(A, 25))) + ((A & B) ^ (~A & C)) +
			0x650A7354 + data[36];
		T2 = ((Bits::RotateRight32(E, 2)) ^ (Bits::RotateRight32(E, 13))
			^ ((E >> 22) ^ (E << 10))) + ((E & F) ^ (E & G) ^ (F & G));
		D = T + T2;
		H = H + T;
		T = C + ((Bits::RotateRight32(H, 6)) ^ (Bits::RotateRight32(H, 11))
			^ (Bits::RotateRight32(H, 25))) + ((H & A) ^ (~H & B)) +
			0x766A0ABB + data[37];
		T2 = ((Bits::RotateRight32(D, 2)) ^ (Bits::RotateRight32(D, 13))
			^ ((D >> 22) ^ (D << 10))) + ((D & E) ^ (D & F) ^ (E & F));
		C = T + T2;
		G = G + T;
		T = B + ((Bits::RotateRight32(G, 6)) ^ (Bits::RotateRight32(G, 11))
			^ (Bits::RotateRight32(G, 25))) + ((G & H) ^ (~G & A)) +
			0x81C2C92E + data[38];
		T2 = ((Bits::RotateRight32(C, 2)) ^ (Bits::RotateRight32(C, 13))
			^ ((C >> 22) ^ (C << 10))) + ((C & D) ^ (C & E) ^ (D & E));
		B = T + T2;
		F = F + T;
		T = A + ((Bits::RotateRight32(F, 6)) ^ (Bits::RotateRight32(F, 11))
			^ (Bits::RotateRight32(F, 25))) + ((F & G) ^ (~F & H)) +
			0x92722C85 + data[39];
		T2 = ((Bits::RotateRight32(B, 2)) ^ (Bits::RotateRight32(B, 13))
			^ ((B >> 22) ^ (B << 10))) + ((B & C) ^ (B & D) ^ (C & D));
		A = T + T2;
		E = E + T;
		T = H + ((Bits::RotateRight32(E, 6)) ^ (Bits::RotateRight32(E, 11))
			^ (Bits::RotateRight32(E, 25))) + ((E & F) ^ (~E & G)) +
			0xA2BFE8A1 + data[40];
		T2 = ((Bits::RotateRight32(A, 2)) ^ (Bits::RotateRight32(A, 13))
			^ ((A >> 22) ^ (A << 10))) + ((A & B) ^ (A & C) ^ (B & C));
		H = T + T2;
		D = D + T;
		T = G + ((Bits::RotateRight32(D, 6)) ^ (Bits::RotateRight32(D, 11))
			^ (Bits::RotateRight32(D, 25))) + ((D & E) ^ (~D & F)) +
			0xA81A664B + data[41];
		T2 = ((Bits::RotateRight32(H, 2)) ^ (Bits::RotateRight32(H, 13))
			^ ((H >> 22) ^ (H << 10))) + ((H & A) ^ (H & B) ^ (A & B));
		G = T + T2;
		C = C + T;
		T = F + ((Bits::RotateRight32(C, 6)) ^ (Bits::RotateRight32(C, 11))
			^ (Bits::RotateRight32(C, 25))) + ((C & D) ^ (~C & E)) +
			0xC24B8B70 + data[42];
		T2 = ((Bits::RotateRight32(G, 2)) ^ (Bits::RotateRight32(G, 13))
			^ ((G >> 22) ^ (G << 10))) + ((G & H) ^ (G & A) ^ (H & A));
		F = T + T2;
		B = B + T;
		T = E + ((Bits::RotateRight32(B, 6)) ^ (Bits::RotateRight32(B, 11))
			^ (Bits::RotateRight32(B, 25))) + ((B & C) ^ (~B & D)) +
			0xC76C51A3 + data[43];
		T2 = ((Bits::RotateRight32(F, 2)) ^ (Bits::RotateRight32(F, 13))
			^ ((F >> 22) ^ (F << 10))) + ((F & G) ^ (F & H) ^ (G & H));
		E = T + T2;
		A = A + T;
		T = D + ((Bits::RotateRight32(A, 6)) ^ (Bits::RotateRight32(A, 11))
			^ (Bits::RotateRight32(A, 25))) + ((A & B) ^ (~A & C)) +
			0xD192E819 + data[44];
		T2 = ((Bits::RotateRight32(E, 2)) ^ (Bits::RotateRight32(E, 13))
			^ ((E >> 22) ^ (E << 10))) + ((E & F) ^ (E & G) ^ (F & G));
		D = T + T2;
		H = H + T;
		T = C + ((Bits::RotateRight32(H, 6)) ^ (Bits::RotateRight32(H, 11))
			^ (Bits::RotateRight32(H, 25))) + ((H & A) ^ (~H & B)) +
			0xD6990624 + data[45];
		T2 = ((Bits::RotateRight32(D, 2)) ^ (Bits::RotateRight32(D, 13))
			^ ((D >> 22) ^ (D << 10))) + ((D & E) ^ (D & F) ^ (E & F));
		C = T + T2;
		G = G + T;
		T = B + ((Bits::RotateRight32(G, 6)) ^ (Bits::RotateRight32(G, 11))
			^ (Bits::RotateRight32(G, 25))) + ((G & H) ^ (~G & A)) +
			0xF40E3585 + data[46];
		T2 = ((Bits::RotateRight32(C, 2)) ^ (Bits::RotateRight32(C, 13))
			^ ((C >> 22) ^ (C << 10))) + ((C & D) ^ (C & E) ^ (D & E));
		B = T + T2;
		F = F + T;
		T = A + ((Bits::RotateRight32(F, 6)) ^ (Bits::RotateRight32(F, 11))
			^ (Bits::RotateRight32(F, 25))) + ((F & G) ^ (~F & H)) +
			0x106AA070 + data[47];
		T2 = ((Bits::RotateRight32(B, 2)) ^ (Bits::RotateRight32(B, 13))
			^ ((B >> 22) ^ (B << 10))) + ((B & C) ^ (B & D) ^ (C & D));
		A = T + T2;
		E = E + T;
		T = H + ((Bits::RotateRight32(E, 6)) ^ (Bits::RotateRight32(E, 11))
			^ (Bits::RotateRight32(E, 25))) + ((E & F) ^ (~E & G)) +
			0x19A4C116 + data[48];
		T2 = ((Bits::RotateRight32(A, 2)) ^ (Bits::RotateRight32(A, 13))
			^ ((A >> 22) ^ (A << 10))) + ((A & B) ^ (A & C) ^ (B & C));
		H = T + T2;
		D = D + T;
		T = G + ((Bits::RotateRight32(D, 6)) ^ (Bits::RotateRight32(D, 11))
			^ (Bits::RotateRight32(D, 25))) + ((D & E) ^ (~D & F)) +
			0x1E376C08 + data[49];
		T2 = ((Bits::RotateRight32(H, 2)) ^ (Bits::RotateRight32(H, 13))
			^ ((H >> 22) ^ (H << 10))) + ((H & A) ^ (H & B) ^ (A & B));
		G = T + T2;
		C = C + T;
		T = F + ((Bits::RotateRight32(C, 6)) ^ (Bits::RotateRight32(C, 11))
			^ (Bits::RotateRight32(C, 25))) + ((C & D) ^ (~C & E)) +
			0x2748774C + data[50];
		T2 = ((Bits::RotateRight32(G, 2)) ^ (Bits::RotateRight32(G, 13))
			^ ((G >> 22) ^ (G << 10))) + ((G & H) ^ (G & A) ^ (H & A));
		F = T + T2;
		B = B + T;
		T = E + ((Bits::RotateRight32(B, 6)) ^ (Bits::RotateRight32(B, 11))
			^ (Bits::RotateRight32(B, 25))) + ((B & C) ^ (~B & D)) +
			0x34B0BCB5 + data[51];
		T2 = ((Bits::RotateRight32(F, 2)) ^ (Bits::RotateRight32(F, 13))
			^ ((F >> 22) ^ (F << 10))) + ((F & G) ^ (F & H) ^ (G & H));
		E = T + T2;
		A = A + T;
		T = D + ((Bits::RotateRight32(A, 6)) ^ (Bits::RotateRight32(A, 11))
			^ (Bits::RotateRight32(A, 25))) + ((A & B) ^ (~A & C)) +
			0x391C0CB3 + data[52];
		T2 = ((Bits::RotateRight32(E, 2)) ^ (Bits::RotateRight32(E, 13))
			^ ((E >> 22) ^ (E << 10))) + ((E & F) ^ (E & G) ^ (F & G));
		D = T + T2;
		H = H + T;
		T = C + ((Bits::RotateRight32(H, 6)) ^ (Bits::RotateRight32(H, 11))
			^ (Bits::RotateRight32(H, 25))) + ((H & A) ^ (~H & B)) +
			0x4ED8AA4A + data[53];
		T2 = ((Bits::RotateRight32(D, 2)) ^ (Bits::RotateRight32(D, 13))
			^ ((D >> 22) ^ (D << 10))) + ((D & E) ^ (D & F) ^ (E & F));
		C = T + T2;
		G = G + T;
		T = B + ((Bits::RotateRight32(G, 6)) ^ (Bits::RotateRight32(G, 11))
			^ (Bits::RotateRight32(G, 25))) + ((G & H) ^ (~G & A)) +
			0x5B9CCA4F + data[54];
		T2 = ((Bits::RotateRight32(C, 2)) ^ (Bits::RotateRight32(C, 13))
			^ ((C >> 22) ^ (C << 10))) + ((C & D) ^ (C & E) ^ (D & E));
		B = T + T2;
		F = F + T;
		T = A + ((Bits::RotateRight32(F, 6)) ^ (Bits::RotateRight32(F, 11))
			^ (Bits::RotateRight32(F, 25))) + ((F & G) ^ (~F & H)) +
			0x682E6FF3 + data[55];
		T2 = ((Bits::RotateRight32(B, 2)) ^ (Bits::RotateRight32(B, 13))
			^ ((B >> 22) ^ (B << 10))) + ((B & C) ^ (B & D) ^ (C & D));
		A = T + T2;
		E = E + T;
		T = H + ((Bits::RotateRight32(E, 6)) ^ (Bits::RotateRight32(E, 11))
			^ (Bits::RotateRight32(E, 25))) + ((E & F) ^ (~E & G)) +
			0x748F82EE + data[56];
		T2 = ((Bits::RotateRight32(A, 2)) ^ (Bits::RotateRight32(A, 13))
			^ ((A >> 22) ^ (A << 10))) + ((A & B) ^ (A & C) ^ (B & C));
		H = T + T2;
		D = D + T;
		T = G + ((Bits::RotateRight32(D, 6)) ^ (Bits::RotateRight32(D, 11))
			^ (Bits::RotateRight32(D, 25))) + ((D & E) ^ (~D & F)) +
			0x78A5636F + data[57];
		T2 = ((Bits::RotateRight32(H, 2)) ^ (Bits::RotateRight32(H, 13))
			^ ((H >> 22) ^ (H << 10))) + ((H & A) ^ (H & B) ^ (A & B));
		G = T + T2;
		C = C + T;
		T = F + ((Bits::RotateRight32(C, 6)) ^ (Bits::RotateRight32(C, 11))
			^ (Bits::RotateRight32(C, 25))) + ((C & D) ^ (~C & E)) +
			0x84C87814 + data[58];
		T2 = ((Bits::RotateRight32(G, 2)) ^ (Bits::RotateRight32(G, 13))
			^ ((G >> 22) ^ (G << 10))) + ((G & H) ^ (G & A) ^ (H & A));
		F = T + T2;
		B = B + T;
		T = E + ((Bits::RotateRight32(B, 6)) ^ (Bits::RotateRight32(B, 11))
			^ (Bits::RotateRight32(B, 25))) + ((B & C) ^ (~B & D)) +
			0x8CC70208 + data[59];
		T2 = ((Bits::RotateRight32(F, 2)) ^ (Bits::RotateRight32(F, 13))
			^ ((F >> 22) ^ (F << 10))) + ((F & G) ^ (F & H) ^ (G & H));
		E = T + T2;
		A = A + T;
		T = D + ((Bits::RotateRight32(A, 6)) ^ (Bits::RotateRight32(A, 11))
			^ (Bits::RotateRight32(A, 25))) + ((A & B) ^ (~A & C)) +
			0x90BEFFFA + data[60];
		T2 = ((Bits::RotateRight32(E, 2)) ^ (Bits::RotateRight32(E, 13))
			^ ((E >> 22) ^ (E << 10))) + ((E & F) ^ (E & G) ^ (F & G));
		D = T + T2;
		H = H + T;
		T = C + ((Bits::RotateRight32(H, 6)) ^ (Bits::RotateRight32(H, 11))
			^ (Bits::RotateRight32(H, 25))) + ((H & A) ^ (~H & B)) +
			0xA4506CEB + data[61];
		T2 = ((Bits::RotateRight32(D, 2)) ^ (Bits::RotateRight32(D, 13))
			^ ((D >> 22) ^ (D << 10))) + ((D & E) ^ (D & F) ^ (E & F));
		C = T + T2;
		G = G + T;
		T = B + ((Bits::RotateRight32(G, 6)) ^ (Bits::RotateRight32(G, 11))
			^ (Bits::RotateRight32(G, 25))) + ((G & H) ^ (~G & A)) +
			0xBEF9A3F7 + data[62];
		T2 = ((Bits::RotateRight32(C, 2)) ^ (Bits::RotateRight32(C, 13))
			^ ((C >> 22) ^ (C << 10))) + ((C & D) ^ (C & E) ^ (D & E));
		B = T + T2;
		F = F + T;
		T = A + ((Bits::RotateRight32(F, 6)) ^ (Bits::RotateRight32(F, 11))
			^ (Bits::RotateRight32(F, 25))) + ((F & G) ^ (~F & H)) +
			0xC67178F2 + data[63];
		T2 = ((Bits::RotateRight32(B, 2)) ^ (Bits::RotateRight32(B, 13))
			^ ((B >> 22) ^ (B << 10))) + ((B & C) ^ (B & D) ^ (C & D));
		A = T + T2;
		E = E + T;

		_state[0] = _state[0] + A;
		_state[1] = _state[1] + B;
		_state[2] = _state[2] + C;
		_state[3] = _state[3] + D;
		_state[4] = _state[4] + E;
		_state[5] = _state[5] + F;
		_state[6] = _state[6] + G;
		_state[7] = _state[7] + H;

		memset(&data[0], 0, data.size() * sizeof(UInt32));

	} // end function TransformBlock

protected:
	HashLibUInt32Array _state;

}; // end class SHA2_256Base
