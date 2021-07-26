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

class Grindahl256 : public BlockHash, public virtual IICryptoNotBuildIn, public virtual IITransformBlock
{
public:
	Grindahl256()
		: BlockHash(32, 4)
	{
		_name = __func__;

		if (_initialized == 'N') initializedStaticLoader();

		_state.resize(13);
	} // end constructor

	virtual IHash Clone() const
	{
		Grindahl256 HashInstance = Grindahl256();
		HashInstance._state = _state;
		HashInstance._buffer = _buffer.Clone();
		HashInstance._processed_bytes = _processed_bytes;

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<Grindahl256>(HashInstance);
	}

	virtual void Initialize()
	{
		ArrayUtils::zeroFill(_state);

		BlockHash::Initialize();
	} // end function Initialize

protected:
	virtual void Finish()
	{
		Int32 padding_size = 12 - Int32(_processed_bytes & 3);
		uint64_t msg_length = (_processed_bytes >> 2) + 1;

		HashLibByteArray pad = HashLibByteArray(padding_size);

		pad[0] = 0x80;

		msg_length = Converters::be2me_64(msg_length);

		Converters::ReadUInt64AsBytesLE(msg_length, pad, padding_size - 8);

		TransformBytes(pad, 0, padding_size - 4);

		_state[0] = Converters::ReadBytesAsUInt32LE((byte*)&pad[0], padding_size - 4);

		_state[0] = Converters::be2me_32(_state[0]);

		InjectMsg(true);

		for (UInt32 i = 0; i < 8; i++)
		{
			InjectMsg(true);
		} // end while

	} // end function Finish

	virtual HashLibByteArray GetResult()
	{
		HashLibByteArray result = HashLibByteArray(8 * sizeof(UInt32));

		Converters::be32_copy(&_state[0] + 5, 0, &result[0], 0, (Int32)result.size());

		return result;
	} // end function GetResult

	virtual void TransformBlock(const byte* a_data,
		const Int32 a_data_length, const Int32 a_index)
	{
		_state[0] = Converters::ReadBytesAsUInt32LE(a_data, a_index);

		_state[0] = Converters::be2me_32(_state[0]);

		InjectMsg(false);
	} // end function TransformBlock

private:
	inline static void CalcTable(const Int32 i, UInt32* result)
	{
		for (UInt32 j = 0; j < 256; j++)
		{
			result[j] = ((master_table[j] >> (i * 8)) | (master_table[j] << (32 - i * 8)));
		} // end for

	} // end function CalcTable

	inline void InjectMsg(const bool a_full_process)
	{
		HashLibUInt32Array temp = HashLibUInt32Array(13);

		_state[12] = _state[12] ^ 0x01;

		if (a_full_process)
			temp[0] = table_0[byte(_state[12] >> 24)] ^ table_1
			[byte(_state[11] >> 16)] ^ table_2[byte(_state[9] >> 8)
			] ^ table_3[byte(_state[3])];

		temp[1] = table_0[byte(_state[0] >> 24)] ^ table_1
			[byte(_state[12] >> 16)] ^ table_2[byte(_state[10] >> 8)
			] ^ table_3[byte(_state[4])];

		temp[2] = table_0[byte(_state[1] >> 24)] ^ table_1
			[byte(_state[0] >> 16)] ^ table_2[byte(_state[11] >> 8)
			] ^ table_3[byte(_state[5])];

		temp[3] = table_0[byte(_state[2] >> 24)] ^ table_1
			[byte(_state[1] >> 16)] ^ table_2[byte(_state[12] >> 8)
			] ^ table_3[byte(_state[6])];

		temp[4] = table_0[byte(_state[3] >> 24)] ^ table_1
			[byte(_state[2] >> 16)] ^ table_2[byte(_state[0] >> 8)
			] ^ table_3[byte(_state[7])];

		temp[5] = table_0[byte(_state[4] >> 24)] ^ table_1
			[byte(_state[3] >> 16)] ^ table_2[byte(_state[1] >> 8)
			] ^ table_3[byte(_state[8])];

		temp[6] = table_0[byte(_state[5] >> 24)] ^ table_1
			[byte(_state[4] >> 16)] ^ table_2[byte(_state[2] >> 8)
			] ^ table_3[byte(_state[9])];

		temp[7] = table_0[byte(_state[6] >> 24)] ^ table_1
			[byte(_state[5] >> 16)] ^ table_2[byte(_state[3] >> 8)
			] ^ table_3[byte(_state[10])];

		temp[8] = table_0[byte(_state[7] >> 24)] ^ table_1
			[byte(_state[6] >> 16)] ^ table_2[byte(_state[4] >> 8)
			] ^ table_3[byte(_state[11])];

		temp[9] = table_0[byte(_state[8] >> 24)] ^ table_1
			[byte(_state[7] >> 16)] ^ table_2[byte(_state[5] >> 8)
			] ^ table_3[byte(_state[12])];

		temp[10] = table_0[byte(_state[9] >> 24)] ^ table_1
			[byte(_state[8] >> 16)] ^ table_2[byte(_state[6] >> 8)
			] ^ table_3[byte(_state[0])];

		temp[11] = table_0[byte(_state[10] >> 24)] ^ table_1
			[byte(_state[9] >> 16)] ^ table_2[byte(_state[7] >> 8)
			] ^ table_3[byte(_state[1])];

		temp[12] = table_0[byte(_state[11] >> 24)] ^ table_1
			[byte(_state[10] >> 16)] ^ table_2[byte(_state[8] >> 8)
			] ^ table_3[byte(_state[2])];


		::swap(temp, _state);

	} // end function InjectMsg

	static char initializedStaticLoader()
	{
		memmove(&table_0[0], master_table, 256 * sizeof(UInt32));

		CalcTable(1, &table_1[0]);
		CalcTable(2, &table_2[0]);
		CalcTable(3, &table_3[0]);

		return 'I';
	}

private:
	HashLibUInt32Array _state;

	static char _initialized;
	static HashLibUInt32Array table_0;
	static HashLibUInt32Array table_1;
	static HashLibUInt32Array table_2;
	static HashLibUInt32Array table_3;

	static const UInt32 master_table[256];

}; // end class Grindahl256

HashLibUInt32Array Grindahl256::table_0 = HashLibUInt32Array(256);
HashLibUInt32Array Grindahl256::table_1 = HashLibUInt32Array(256);
HashLibUInt32Array Grindahl256::table_2 = HashLibUInt32Array(256);
HashLibUInt32Array Grindahl256::table_3 = HashLibUInt32Array(256);

char Grindahl256::_initialized = 'N';// Grindahl256::initializedStaticLoader();

const UInt32 Grindahl256::master_table[256] = { 0xC66363A5, 0xF87C7C84,
	0xEE777799, 0xF67B7B8D, 0xFFF2F20D, 0xD66B6BBD, 0xDE6F6FB1, 0x91C5C554,
	0x60303050, 0x02010103, 0xCE6767A9, 0x562B2B7D, 0xE7FEFE19, 0xB5D7D762,
	0x4DABABE6, 0xEC76769A, 0x8FCACA45, 0x1F82829D, 0x89C9C940, 0xFA7D7D87,
	0xEFFAFA15, 0xB25959EB, 0x8E4747C9, 0xFBF0F00B, 0x41ADADEC, 0xB3D4D467,
	0x5FA2A2FD, 0x45AFAFEA, 0x239C9CBF, 0x53A4A4F7, 0xE4727296, 0x9BC0C05B,
	0x75B7B7C2, 0xE1FDFD1C, 0x3D9393AE, 0x4C26266A, 0x6C36365A, 0x7E3F3F41,
	0xF5F7F702, 0x83CCCC4F, 0x6834345C, 0x51A5A5F4, 0xD1E5E534, 0xF9F1F108,
	0xE2717193, 0xABD8D873, 0x62313153, 0x2A15153F, 0x0804040C, 0x95C7C752,
	0x46232365, 0x9DC3C35E, 0x30181828, 0x379696A1, 0x0A05050F, 0x2F9A9AB5,
	0x0E070709, 0x24121236, 0x1B80809B, 0xDFE2E23D, 0xCDEBEB26, 0x4E272769,
	0x7FB2B2CD, 0xEA75759F, 0x1209091B, 0x1D83839E, 0x582C2C74, 0x341A1A2E,
	0x361B1B2D, 0xDC6E6EB2, 0xB45A5AEE, 0x5BA0A0FB, 0xA45252F6, 0x763B3B4D,
	0xB7D6D661, 0x7DB3B3CE, 0x5229297B, 0xDDE3E33E, 0x5E2F2F71, 0x13848497,
	0xA65353F5, 0xB9D1D168, 0x00000000, 0xC1EDED2C, 0x40202060, 0xE3FCFC1F,
	0x79B1B1C8, 0xB65B5BED, 0xD46A6ABE, 0x8DCBCB46, 0x67BEBED9, 0x7239394B,
	0x944A4ADE, 0x984C4CD4, 0xB05858E8, 0x85CFCF4A, 0xBBD0D06B, 0xC5EFEF2A,
	0x4FAAAAE5, 0xEDFBFB16, 0x864343C5, 0x9A4D4DD7, 0x66333355, 0x11858594,
	0x8A4545CF, 0xE9F9F910, 0x04020206, 0xFE7F7F81, 0xA05050F0, 0x783C3C44,
	0x259F9FBA, 0x4BA8A8E3, 0xA25151F3, 0x5DA3A3FE, 0x804040C0, 0x058F8F8A,
	0x3F9292AD, 0x219D9DBC, 0x70383848, 0xF1F5F504, 0x63BCBCDF, 0x77B6B6C1,
	0xAFDADA75, 0x42212163, 0x20101030, 0xE5FFFF1A, 0xFDF3F30E, 0xBFD2D26D,
	0x81CDCD4C, 0x180C0C14, 0x26131335, 0xC3ECEC2F, 0xBE5F5FE1, 0x359797A2,
	0x884444CC, 0x2E171739, 0x93C4C457, 0x55A7A7F2, 0xFC7E7E82, 0x7A3D3D47,
	0xC86464AC, 0xBA5D5DE7, 0x3219192B, 0xE6737395, 0xC06060A0, 0x19818198,
	0x9E4F4FD1, 0xA3DCDC7F, 0x44222266, 0x542A2A7E, 0x3B9090AB, 0x0B888883,
	0x8C4646CA, 0xC7EEEE29, 0x6BB8B8D3, 0x2814143C, 0xA7DEDE79, 0xBC5E5EE2,
	0x160B0B1D, 0xADDBDB76, 0xDBE0E03B, 0x64323256, 0x743A3A4E, 0x140A0A1E,
	0x924949DB, 0x0C06060A, 0x4824246C, 0xB85C5CE4, 0x9FC2C25D, 0xBDD3D36E,
	0x43ACACEF, 0xC46262A6, 0x399191A8, 0x319595A4, 0xD3E4E437, 0xF279798B,
	0xD5E7E732, 0x8BC8C843, 0x6E373759, 0xDA6D6DB7, 0x018D8D8C, 0xB1D5D564,
	0x9C4E4ED2, 0x49A9A9E0, 0xD86C6CB4, 0xAC5656FA, 0xF3F4F407, 0xCFEAEA25,
	0xCA6565AF, 0xF47A7A8E, 0x47AEAEE9, 0x10080818, 0x6FBABAD5, 0xF0787888,
	0x4A25256F, 0x5C2E2E72, 0x381C1C24, 0x57A6A6F1, 0x73B4B4C7, 0x97C6C651,
	0xCBE8E823, 0xA1DDDD7C, 0xE874749C, 0x3E1F1F21, 0x964B4BDD, 0x61BDBDDC,
	0x0D8B8B86, 0x0F8A8A85, 0xE0707090, 0x7C3E3E42, 0x71B5B5C4, 0xCC6666AA,
	0x904848D8, 0x06030305, 0xF7F6F601, 0x1C0E0E12, 0xC26161A3, 0x6A35355F,
	0xAE5757F9, 0x69B9B9D0, 0x17868691, 0x99C1C158, 0x3A1D1D27, 0x279E9EB9,
	0xD9E1E138, 0xEBF8F813, 0x2B9898B3, 0x22111133, 0xD26969BB, 0xA9D9D970,
	0x078E8E89, 0x339494A7, 0x2D9B9BB6, 0x3C1E1E22, 0x15878792, 0xC9E9E920,
	0x87CECE49, 0xAA5555FF, 0x50282878, 0xA5DFDF7A, 0x038C8C8F, 0x59A1A1F8,
	0x09898980, 0x1A0D0D17, 0x65BFBFDA, 0xD7E6E631, 0x844242C6, 0xD06868B8,
	0x824141C3, 0x299999B0, 0x5A2D2D77, 0x1E0F0F11, 0x7BB0B0CB, 0xA85454FC,
	0x6DBBBBD6, 0x2C16163A };
