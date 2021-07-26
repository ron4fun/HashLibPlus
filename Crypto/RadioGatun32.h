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

class RadioGatun32 : public BlockHash, public virtual IICryptoNotBuildIn, public virtual IITransformBlock
{
public:
	RadioGatun32()
		: BlockHash(32, 12)
	{
		_name = __func__;

		_mill.resize(19);

		_belt.resize(13);
		for (UInt32 i = 0; i < 13; i++)
			_belt[i] = HashLibUInt32Array(3);

	} // end constructor

	virtual IHash Clone() const
	{
		RadioGatun32 HashInstance = RadioGatun32();
		HashInstance._mill = _mill;
		HashInstance._belt = _belt;
		HashInstance._buffer = _buffer.Clone();
		HashInstance._processed_bytes = _processed_bytes;

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<RadioGatun32>(HashInstance);
	}

	virtual void Initialize()
	{
		ArrayUtils::zeroFill(_mill);

		for (UInt32 i = 0; i < 13; i++)
			ArrayUtils::zeroFill(_belt[i]);

		BlockHash::Initialize();
	} // end function Initialize

protected:
	virtual void Finish()
	{
		Int32 padding_size = 12 - (_processed_bytes % 12);

		HashLibByteArray pad = HashLibByteArray(padding_size);

		pad[0] = 0x01;

		TransformBytes(pad, 0, padding_size);

		for (UInt32 i = 0; i < 16; i++)
			RoundFunction();

	} // end function Finish

	virtual HashLibByteArray GetResult() 
	{
		HashLibUInt32Array tempRes = HashLibUInt32Array(8);

		HashLibByteArray result = HashLibByteArray(8 * sizeof(UInt32));

		for (UInt32 i = 0; i < 4; i++)
		{
			RoundFunction();
			memmove(&tempRes[(size_t)i * 2], &_mill[1], 2 * sizeof(UInt32));
		} // end for

		Converters::le32_copy(&tempRes[0], 0, &result[0], 0, (Int32)result.size());

		return result;
	} // end function GetResult

	virtual void TransformBlock(const uint8_t* a_data,
		const Int32 a_data_length, const Int32 a_index) 
	{
		HashLibUInt32Array data = HashLibUInt32Array(3);

		Converters::le32_copy(a_data, a_index, &data[0], 0, 12);

		UInt32 i = 0;
		while (i < 3)
		{
			_mill[(size_t)i + 16] = _mill[(size_t)i + 16] ^ data[i];
			_belt[0][i] = _belt[0][i] ^ data[i];
			i++;
		} // end while

		RoundFunction();

		ArrayUtils::zeroFill(data);
	} // end function TransformBlock

private:
	inline void RoundFunction()
	{
		HashLibUInt32Array q = _belt[12];
		HashLibUInt32Array a = HashLibUInt32Array(19);

		UInt32 i = 12;
		while (i > 0)
		{
			_belt[i] = _belt[i - 1];
			i--;
		} // end while

		_belt[0] = q;

		i = 0;
		while (i < 12)
		{
			_belt[(size_t)i + 1][i % 3] = _belt[(size_t)i + 1][i % 3] ^ _mill[(size_t)i + 1];
			i++;
		} // end while

		i = 0;
		while (i < 19)
		{
			a[i] = _mill[i] ^ (_mill[(i + 1) % 19] | ~_mill[(i + 2) % 19]);
			i++;
		} // end while

		i = 0;
		while (i < 19)
		{
			_mill[i] = Bits::RotateRight32(a[(7 * i) % 19], (i * (i + 1)) >> 1);
			i++;
		} // end while

		i = 0;
		while (i < 19)
		{
			a[i] = _mill[i] ^ _mill[(i + 1) % 19] ^ _mill[(i + 4) % 19];
			i++;
		} // end while

		a[0] = a[0] ^ 1;

		i = 0;
		while (i < 19)
		{
			_mill[i] = a[i];
			i++;
		} // end while

		i = 0;
		while (i < 3)
		{
			_mill[(size_t)i + 13] = _mill[(size_t)i + 13] ^ q[i];
			i++;
		} // end while
	} // end function RoundFunction

private:
	HashLibUInt32Array _mill;

	HashLibMatrixUInt32Array _belt;

}; // end class RadioGatun32
