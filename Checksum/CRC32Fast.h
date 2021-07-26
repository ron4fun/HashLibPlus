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

#include "../Base/Hash.h"
#include "../Interfaces/IHashInfo.h"

class CRC32Fast : public Hash, public virtual IIChecksum, public virtual IIBlockHash, 
	public virtual IIHash32, public virtual IITransformBlock
{
protected:
	UInt32 _currentCRC = 0;

public:
	CRC32Fast() : Hash(4, 1)
	{ } // end constructor

	virtual void Initialize()
	{
		_currentCRC = 0;
	} // end function Initialize

	virtual IHashResult TransformFinal()
	{
		IHashResult res = make_shared<HashResult>(_currentCRC);

		Initialize();

		return res;
	} // end function TransformFinal

protected:
	void LocalCRCCompute(const HashLibUInt32Array& a_CRCTable, const HashLibByteArray& a_data,
		Int32 a_index, Int32 a_length)
	{
		UInt32 LCRC, LA, LB, LC, LD;
		HashLibUInt32Array LCRCTable;

		LCRC = ~_currentCRC; // LCRC := System.High(UInt32) xor FCurrentCRC;
		LCRCTable = a_CRCTable;
		while (a_length >= 16)
		{
			LA = LCRCTable[(3 * 256) + a_data[a_index + 12]] ^ LCRCTable
				[(2 * 256) + a_data[a_index + 13]] ^ LCRCTable
				[(1 * 256) + a_data[a_index + 14]] ^ LCRCTable
				[(0 * 256) + a_data[a_index + 15]];

			LB = LCRCTable[(7 * 256) + a_data[a_index + 8]] ^ LCRCTable
				[(6 * 256) + a_data[a_index + 9]] ^ LCRCTable
				[(5 * 256) + a_data[a_index + 10]] ^ LCRCTable
				[(4 * 256) + a_data[a_index + 11]];

			LC = LCRCTable[(11 * 256) + a_data[a_index + 4]] ^ LCRCTable
				[(10 * 256) + a_data[a_index + 5]] ^ LCRCTable
				[(9 * 256) + a_data[a_index + 6]] ^ LCRCTable
				[(8 * 256) + a_data[a_index + 7]];

			LD = LCRCTable[(15 * 256) + ((LCRC & 0xFF) ^ a_data[a_index])] ^ LCRCTable
				[(14 * 256) + (((LCRC >> 8) & 0xFF) ^ a_data[a_index + 1])] ^ LCRCTable
				[(13 * 256) + (((LCRC >> 16) & 0xFF) ^ a_data[a_index + 2])] ^ LCRCTable
				[(12 * 256) + ((LCRC >> 24) ^ a_data[a_index + 3])];

			LCRC = LD ^ LC ^ LB ^ LA;

			a_index += 16;
			a_length -= 16;
		} // end while

		a_length--;
		while (a_length >= 0)
		{
			LCRC = LCRCTable[(byte)(LCRC ^ a_data[a_index])] ^ (LCRC >> 8);
			a_index++;
			a_length--;
		} // end while

		_currentCRC = ~LCRC; // FCurrentCRC := LCRC xor System.High(UInt32);
	} // end function LocalCRCCompute

	static HashLibUInt32Array Init_CRC_Table(const UInt32 a_polynomial)
	{
		Int32 LIdx, LJIdx, LKIdx;
		UInt32 LRes;

		HashLibUInt32Array res = HashLibUInt32Array(16 * 256);

		for (LIdx = 0; LIdx < 256; LIdx++)
		{
			LRes = (UInt32)LIdx;
			for (LJIdx = 0; LJIdx < 16; LJIdx++)
			{
				LKIdx = 0;
				while (LKIdx < 8)
				{
					// faster branchless variant
					LRes = (UInt32)((LRes >> 1) ^ (-(Int32)(LRes & 1) & a_polynomial));
					res[((Int32)(LJIdx) * 256) + LIdx] = LRes;
					LKIdx++;
				} // end while
			} // end for
		} // end for

		return res;
	} // end function Init_CRC_Table

}; // end class CRC32Fast

class CRC32_PKZIP_Fast : public CRC32Fast
{
public:
	CRC32_PKZIP_Fast()
	{
		_name = "CRC32_PKZIP";

		_crc32_PKZIP_Table = Init_CRC_Table(CRC32_PKZIP_Polynomial);
	} // end constructor

	virtual IHash Clone() const
	{
		CRC32_PKZIP_Fast HashInstance = CRC32_PKZIP_Fast();
		HashInstance._currentCRC = _currentCRC;

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<CRC32_PKZIP_Fast>(HashInstance);
	} // end function Clone

	virtual void TransformBytes(const HashLibByteArray& a_data, const Int32 a_index, const Int32 a_length)
	{
		LocalCRCCompute(_crc32_PKZIP_Table, a_data, a_index, a_length);
	} // end function TransformBytes

private:
	// Polynomial Reversed
	static const UInt32 CRC32_PKZIP_Polynomial = 0xEDB88320;

	HashLibUInt32Array _crc32_PKZIP_Table;

}; // end class CRC32_PKZIP

class CRC32_CASTAGNOLI_Fast : public CRC32Fast
{
private:
	// Polynomial Reversed
	static const UInt32 CRC32_CASTAGNOLI_Polynomial = 0x82F63B78;

	HashLibUInt32Array _crc32_CASTAGNOLI_Table;

public:
	CRC32_CASTAGNOLI_Fast()
	{
		_name = "CRC32_CASTAGNOLI";

		_crc32_CASTAGNOLI_Table = Init_CRC_Table(CRC32_CASTAGNOLI_Polynomial);
	} // end constructor

	virtual IHash Clone() const
	{
		CRC32_CASTAGNOLI_Fast HashInstance = CRC32_CASTAGNOLI_Fast();
		HashInstance._currentCRC = _currentCRC;

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<CRC32_CASTAGNOLI_Fast>(HashInstance);
	} // end function Clone

	virtual void TransformBytes(const HashLibByteArray &a_data, const Int32 a_index, const Int32 a_length)
	{
		LocalCRCCompute(_crc32_CASTAGNOLI_Table, a_data, a_index, a_length);
	} // end function TransformBytes

}; // end class CRC32_CASTAGNOLI
