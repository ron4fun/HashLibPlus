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
#include "../Interfaces/ICRC.h"

class _CRC : public Hash, public virtual IICRC, public virtual IIChecksum, 
	public virtual IITransformBlock
{
public:
	_CRC(const Int32 _Width, const UInt64 _poly, const UInt64 _Init,
		const bool _refIn, const bool _refOut, const UInt64 _XorOut,
		const UInt64 _check, const HashLibStringArray& _Names)
		: Hash(0, 0) // Ok, Nothing serious..
	{
		if (!(_Width >= 3 && _Width <= 64))
			throw ArgumentOutOfRangeHashLibException(
				Utils::string_format(_CRC::WidthOutOfRange, _Width));

		_isTableGenerated = false;

		if (_Width >= 0 && _Width <= 7)
		{
			_hash_size = 1;
			_block_size = 1;
		} // end if
		else if (_Width >= 8 && _Width <= 16)
		{
			_hash_size = 2;
			_block_size = 1;
		} // end else if
		else if (_Width >= 17 && _Width <= 39)
		{
			_hash_size = 4;
			_block_size = 1;
		} // end else if
		else
		{
			_hash_size = 8;
			_block_size = 1;
		} // end else

		_names = _Names;
		_width = _Width;
		_polynomial = _poly;
		_init = _Init;
		_reflectIn = _refIn;
		_reflectOut = _refOut;
		_xorOut = _XorOut;
		_checkValue = _check;

	} // end constructor

	virtual IHash Clone() const
	{
		IHash _hash = make_shared<_CRC>(Copy());
		_hash->SetBufferSize(GetBufferSize());

		return _hash;
	}

	virtual string GetName() const
	{
		return _names[0];
	}

	virtual void Initialize()
	{
		// initialize some bitmasks
		_crcMask = (((UInt64(1) << (_width - 1)) - 1) << 1) | 1;
		_crcHighBitMask = UInt64(1) << (_width - 1);
		_hash = _init;

		if (_width > Delta) // then use table
		{
			if (!_isTableGenerated)
				GenerateTable();

			if (_reflectIn)
				_hash = Reflect(_hash, _width);
		} // end if
	} // end function Initialize

	virtual IHashResult TransformFinal()
	{
		UInt64 LUInt64;
		UInt32 LUInt32;
		UInt16 LUInt16;
		byte LUInt8;

		if (_width > Delta)
		{
			if (_reflectIn ^ _reflectOut)
				_hash = Reflect(_hash, _width);
		} // end if
		else
		{
			if (_reflectOut)
				_hash = Reflect(_hash, _width);
		} // end else

		_hash = _hash ^ _xorOut;
		_hash = _hash & _crcMask;

		if (_width == 21) // special case
		{
			LUInt32 = (UInt32)_hash;

			IHashResult result(new HashResult(LUInt32));

			Initialize();

			return result;
		} // end if

		int64_t value = _width >> 3;

		if (value == 0)
		{
			LUInt8 = (byte)_hash;
			Initialize();
			return IHashResult(new HashResult(LUInt8));
		} // end result
		else if (value == 1 || value == 2)
		{
			LUInt16 = (UInt16)_hash;
			Initialize();
			return IHashResult(new HashResult(LUInt16));
		} // end else if
		else if (value == 3 || value == 4)
		{
			LUInt32 = (UInt32)_hash;
			Initialize();
			return IHashResult(new HashResult(LUInt32));
		} // end else if

		LUInt64 = _hash;
		Initialize();
		return IHashResult(new HashResult(LUInt64));
	} // end function TransformFinal

	virtual void TransformBytes(const HashLibByteArray& a_data, const Int32 a_index, const Int32 a_length)
	{
		// table driven CRC reportedly only works for 8, 16, 24, 32 bits
		// HOWEVER, it seems to work for everything > 7 bits, so use it
		// accordingly

		if (a_data.empty()) return;

		Int32 i = a_index;

		byte* ptr_a_data = (byte*)& a_data[0];

		if (_width > Delta)
			CalculateCRCbyTable(ptr_a_data, a_length, i);
		else
			CalculateCRCdirect(ptr_a_data, a_length, i);

	} // end function TransformBytes

	static ICRC CreateCRCObject(const CRCStandard& a_value)
	{
		switch (a_value)
		{
		case CRC3_GSM:
			return make_shared<_CRC>(3, 0x3, 0x0, false, false, 0x7, 0x4, HashLibStringArray({ "CRC-3/GSM" }));

		case CRC3_ROHC:
			return make_shared<_CRC>(3, 0x3, 0x7, true, true, 0x0, 0x6, HashLibStringArray({ "CRC-3/ROHC" }));

		case CRC4_INTERLAKEN:
			return make_shared<_CRC>(4, 0x3, 0xF, false, false, 0xF, 0xB, HashLibStringArray({ "CRC-4/INTERLAKEN" }));

		case CRC4_ITU:
			return make_shared<_CRC>(4, 0x3, 0x0, true, true, 0x0, 0x7, HashLibStringArray({ "CRC-4/ITU" }));

		case CRC5_EPC:
			return make_shared<_CRC>(5, 0x9, 0x9, false, false, 0x00, 0x00, HashLibStringArray({ "CRC-5/EPC" }));

		case CRC5_ITU:
			return make_shared<_CRC>(5, 0x15, 0x00, true, true, 0x00, 0x07, HashLibStringArray({ "CRC-5/ITU" }));

		case CRC5_USB:
			return make_shared<_CRC>(5, 0x05, 0x1F, true, true, 0x1F, 0x19, HashLibStringArray({ "CRC-5/USB" }));

		case CRC6_CDMA2000A:
			return make_shared<_CRC>(6, 0x27, 0x3F, false, false, 0x00, 0x0D, HashLibStringArray({ "CRC-6/CDMA2000-A" }));

		case CRC6_CDMA2000B:
			return make_shared<_CRC>(6, 0x07, 0x3F, false, false, 0x00, 0x3B, HashLibStringArray({ "CRC-6/CDMA2000-B" }));

		case CRC6_DARC:
			return make_shared<_CRC>(6, 0x19, 0x00, true, true, 0x00, 0x26, HashLibStringArray({ "CRC-6/DARC" }));

		case CRC6_GSM:
			return make_shared<_CRC>(6, 0x2F, 0x00, false, false, 0x3F, 0x13, HashLibStringArray({ "CRC-6/GSM" }));

		case CRC6_ITU:
			return make_shared<_CRC>(6, 0x03, 0x00, true, true, 0x00, 0x06, HashLibStringArray({ "CRC-6/ITU" }));

		case CRC7:
			return make_shared<_CRC>(7, 0x09, 0x00, false, false, 0x00, 0x75, HashLibStringArray({ "CRC-7" }));

		case CRC7_ROHC:
			return make_shared<_CRC>(7, 0x4F, 0x7F, true, true, 0x00, 0x53, HashLibStringArray({ "CRC-7/ROHC" }));

		case CRC7_UMTS:
			return make_shared<_CRC>(7, 0x45, 0x00, false, false, 0x00, 0x61, HashLibStringArray({ "CRC-7/UMTS" }));

		case CRC8:
			return make_shared<_CRC>(8, 0x07, 0x00, false, false, 0x00, 0xF4, HashLibStringArray({ "CRC-8" }));

		case CRC8_AUTOSAR:
			return make_shared<_CRC>(8, 0x2F, 0xFF, false, false, 0xFF, 0xDF, HashLibStringArray({ "CRC-8/AUTOSAR" }));

		case CRC8_BLUETOOTH:
			return make_shared<_CRC>(8, 0xA7, 0x00, true, true, 0x00, 0x26, HashLibStringArray({ "CRC-8/BLUETOOTH" }));

		case CRC8_CDMA2000:
			return make_shared<_CRC>(8, 0x9B, 0xFF, false, false, 0x00, 0xDA, HashLibStringArray({ "CRC-8/CDMA2000" }));

		case CRC8_DARC:
			return make_shared<_CRC>(8, 0x39, 0x00, true, true, 0x00, 0x15, HashLibStringArray({ "CRC-8/DARC" }));

		case CRC8_DVBS2:
			return make_shared<_CRC>(8, 0xD5, 0x00, false, false, 0x00, 0xBC, HashLibStringArray({ "CRC-8/DVB-S2" }));

		case CRC8_EBU:
			return make_shared<_CRC>(8, 0x1D, 0xFF, true, true, 0x00, 0x97, HashLibStringArray({ "CRC-8/EBU", "CRC-8/AES" }));

		case CRC8_GSMA:
			return make_shared<_CRC>(8, 0x1D, 0x00, false, false, 0x00, 0x37, HashLibStringArray({ "CRC-8/GSM-A" }));

		case CRC8_GSMB:
			return make_shared<_CRC>(8, 0x49, 0x00, false, false, 0xFF, 0x94, HashLibStringArray({ "CRC-8/GSM-B" }));

		case CRC8_ICODE:
			return make_shared<_CRC>(8, 0x1D, 0xFD, false, false, 0x00, 0x7E, HashLibStringArray({ "CRC-8/I-CODE" }));

		case CRC8_ITU:
			return make_shared<_CRC>(8, 0x07, 0x00, false, false, 0x55, 0xA1, HashLibStringArray({ "CRC-8/ITU" }));

		case CRC8_LTE:
			return make_shared<_CRC>(8, 0x9B, 0x00, false, false, 0x00, 0xEA, HashLibStringArray({ "CRC-8/LTE" }));

		case CRC8_MAXIM:
			return make_shared<_CRC>(8, 0x31, 0x00, true, true, 0x00, 0xA1, HashLibStringArray({ "CRC-8/MAXIM", "DOW-CRC" }));

		case CRC8_OPENSAFETY:
			return make_shared<_CRC>(8, 0x2F, 0x00, false, false, 0x00, 0x3E, HashLibStringArray({ "CRC-8/OPENSAFETY" }));

		case CRC8_ROHC:
			return make_shared<_CRC>(8, 0x07, 0xFF, true, true, 0x00, 0xD0, HashLibStringArray({ "CRC-8/ROHC" }));

		case CRC8_SAEJ1850:
			return make_shared<_CRC>(8, 0x1D, 0xFF, false, false, 0xFF, 0x4B, HashLibStringArray({ "CRC-8/SAE-J1850" }));

		case CRC8_WCDMA:
			return make_shared<_CRC>(8, 0x9B, 0x00, true, true, 0x00, 0x25, HashLibStringArray({ "CRC-8/WCDMA" }));

		case CRC10:
			return make_shared<_CRC>(10, 0x233, 0x000, false, false, 0x000, 0x199, HashLibStringArray({ "CRC-10" }));

		case CRC10_CDMA2000:
			return make_shared<_CRC>(10, 0x3D9, 0x3FF, false, false, 0x000, 0x233, HashLibStringArray({ "CRC-10/CDMA2000" }));

		case CRC10_GSM:
			return make_shared<_CRC>(10, 0x175, 0x000, false, false, 0x3FF, 0x12A, HashLibStringArray({ "CRC-10/GSM" }));

		case CRC11:
			return make_shared<_CRC>(11, 0x385, 0x01A, false, false, 0x000, 0x5A3, HashLibStringArray({ "CRC-11" }));

		case CRC11_UMTS:
			return make_shared<_CRC>(11, 0x307, 0x000, false, false, 0x000, 0x061, HashLibStringArray({ "CRC-11/UMTS" }));

		case CRC12_CDMA2000:
			return make_shared<_CRC>(12, 0xF13, 0xFFF, false, false, 0x000, 0xD4D, HashLibStringArray({ "CRC-12/CDMA2000" }));

		case CRC12_DECT:
			return make_shared<_CRC>(12, 0x80F, 0x000, false, false, 0x000, 0xF5B, HashLibStringArray({ "CRC-12/DECT", "X-CRC-12" }));

		case CRC12_GSM:
			return make_shared<_CRC>(12, 0xD31, 0x000, false, false, 0xFFF, 0xB34, HashLibStringArray({ "CRC-12/GSM" }));

		case CRC12_UMTS:
			return make_shared<_CRC>(12, 0x80F, 0x000, false, true, 0x000, 0xDAF, HashLibStringArray({ "CRC-12/UMTS", "CRC-12/3GPP" }));

		case CRC13_BBC:
			return make_shared<_CRC>(13, 0x1CF5, 0x0000, false, false, 0x0000, 0x04FA, HashLibStringArray({ "CRC-13/BBC" }));

		case CRC14_DARC:
			return make_shared<_CRC>(14, 0x0805, 0x0000, true, true, 0x0000, 0x082D, HashLibStringArray({ "CRC-14/DARC" }));

		case CRC14_GSM:
			return make_shared<_CRC>(14, 0x202D, 0x0000, false, false, 0x3FFF, 0x30AE, HashLibStringArray({ "CRC-14/GSM" }));

		case CRC15:
			return make_shared<_CRC>(15, 0x4599, 0x0000, false, false, 0x0000, 0x059E, HashLibStringArray({ "CRC-15" }));

		case CRC15_MPT1327:
			return make_shared<_CRC>(15, 0x6815, 0x0000, false, false, 0x0001, 0x2566, HashLibStringArray({ "CRC-15/MPT1327" }));

		case ARC:
			return make_shared<_CRC>(16, 0x8005, 0x0000, true, true, 0x0000, 0xBB3D, HashLibStringArray({ "CRC-16", "ARC", "CRC-IBM", "CRC-16/ARC", "CRC-16/LHA" }));

		case CRC16_AUGCCITT:
			return make_shared<_CRC>(16, 0x1021, 0x1D0F, false, false, 0x0000, 0xE5CC, HashLibStringArray({ "CRC-16/AUG-CCITT", "CRC-16/SPI-FUJITSU" }));

		case CRC16_BUYPASS:
			return make_shared<_CRC>(16, 0x8005, 0x0000, false, false, 0x0000, 0xFEE8, HashLibStringArray({ "CRC-16/BUYPASS", "CRC-16/VERIFONE" }));

		case CRC16_CCITTFALSE:
			return make_shared<_CRC>(16, 0x1021, 0xFFFF, false, false, 0x0000, 0x29B1, HashLibStringArray({ "CRC-16/CCITT-FALSE" }));

		case CRC16_CDMA2000:
			return make_shared<_CRC>(16, 0xC867, 0xFFFF, false, false, 0x0000, 0x4C06, HashLibStringArray({ "CRC-16/CDMA2000" }));

		case CRC16_CMS:
			return make_shared<_CRC>(16, 0x8005, 0xFFFF, false, false, 0x0000, 0xAEE7, HashLibStringArray({ "CRC-16/CMS" }));

		case CRC16_DDS110:
			return make_shared<_CRC>(16, 0x8005, 0x800D, false, false, 0x0000, 0x9ECF, HashLibStringArray({ "CRC-16/DDS-110" }));

		case CRC16_DECTR:
			return make_shared<_CRC>(16, 0x0589, 0x0000, false, false, 0x0001, 0x007E, HashLibStringArray({ "CRC-16/DECT-R", "R-CRC-16" }));

		case CRC16_DECTX:
			return make_shared<_CRC>(16, 0x0589, 0x0000, false, false, 0x0000, 0x007F, HashLibStringArray({ "CRC-16/DECT-X", "X-CRC-16" }));

		case CRC16_DNP:
			return make_shared<_CRC>(16, 0x3D65, 0x0000, true, true, 0xFFFF, 0xEA82, HashLibStringArray({ "CRC-16/DNP" }));

		case CRC16_EN13757:
			return make_shared<_CRC>(16, 0x3D65, 0x0000, false, false, 0xFFFF, 0xC2B7, HashLibStringArray({ "CRC-16/EN13757" }));

		case CRC16_GENIBUS:
			return make_shared<_CRC>(16, 0x1021, 0xFFFF, false, false, 0xFFFF, 0xD64E, HashLibStringArray({ "CRC-16/GENIBUS", "CRC-16/EPC", "CRC-16/I-CODE", "CRC-16/DARC" }));

		case CRC16_GSM:
			return make_shared<_CRC>(16, 0x1021, 0x0000, false, false, 0xFFFF, 0xCE3C, HashLibStringArray({ "CRC-16/GSM" }));

		case CRC16_LJ1200:
			return make_shared<_CRC>(16, 0x6F63, 0x0000, false, false, 0x0000, 0xBDF4, HashLibStringArray({ "CRC-16/LJ1200" }));

		case CRC16_MAXIM:
			return make_shared<_CRC>(16, 0x8005, 0x0000, true, true, 0xFFFF, 0x44C2, HashLibStringArray({ "CRC-16/MAXIM" }));

		case CRC16_MCRF4XX:
			return make_shared<_CRC>(16, 0x1021, 0xFFFF, true, true, 0x0000, 0x6F91, HashLibStringArray({ "CRC-16/MCRF4XX" }));

		case CRC16_OPENSAFETYA:
			return make_shared<_CRC>(16, 0x5935, 0x0000, false, false, 0x0000, 0x5D38, HashLibStringArray({ "CRC-16/OPENSAFETY-A" }));

		case CRC16_OPENSAFETYB:
			return make_shared<_CRC>(16, 0x755B, 0x0000, false, false, 0x0000, 0x20FE, HashLibStringArray({ "CRC-16/OPENSAFETY-B" }));

		case CRC16_PROFIBUS:
			return make_shared<_CRC>(16, 0x1DCF, 0xFFFF, false, false, 0xFFFF, 0xA819, HashLibStringArray({ "CRC-16/PROFIBUS", "CRC-16/IEC-61158-2" }));

		case CRC16_RIELLO:
			return make_shared<_CRC>(16, 0x1021, 0xB2AA, true, true, 0x0000, 0x63D0, HashLibStringArray({ "CRC-16/RIELLO" }));

		case CRC16_T10DIF:
			return make_shared<_CRC>(16, 0x8BB7, 0x0000, false, false, 0x0000, 0xD0DB, HashLibStringArray({ "CRC-16/T10-DIF" }));

		case CRC16_TELEDISK:
			return make_shared<_CRC>(16, 0xA097, 0x0000, false, false, 0x0000, 0x0FB3, HashLibStringArray({ "CRC-16/TELEDISK" }));

		case CRC16_TMS37157:
			return make_shared<_CRC>(16, 0x1021, 0x89EC, true, true, 0x0000, 0x26B1, HashLibStringArray({ "CRC-16/TMS37157" }));

		case CRC16_USB:
			return make_shared<_CRC>(16, 0x8005, 0xFFFF, true, true, 0xFFFF, 0xB4C8, HashLibStringArray({ "CRC-16/USB" }));

		case CRCA:
			return make_shared<_CRC>(16, 0x1021, 0xC6C6, true, true, 0x0000, 0xBF05, HashLibStringArray({ "CRC-A" }));

		case KERMIT:
			return make_shared<_CRC>(16, 0x1021, 0x0000, true, true, 0x0000, 0x2189, HashLibStringArray({ "KERMIT", "CRC-16/CCITT", "CRC-16/CCITT-TRUE", "CRC-CCITT" }));

		case MODBUS:
			return make_shared<_CRC>(16, 0x8005, 0xFFFF, true, true, 0x0000, 0x4B37, HashLibStringArray({ "MODBUS" }));

		case X25:
			return make_shared<_CRC>(16, 0x1021, 0xFFFF, true, true, 0xFFFF, 0x906E, HashLibStringArray({ "X-25", "CRC-16/IBM-SDLC", "CRC-16/ISO-HDLC", "CRC-B" }));

		case XMODEM:
			return make_shared<_CRC>(16, 0x1021, 0x0000, false, false, 0x0000, 0x31C3, HashLibStringArray({ "XMODEM", "ZMODEM", "CRC-16/ACORN" }));

		case CRC17_CANFD:
			return make_shared<_CRC>(17, 0x1685B, 0x00000, false, false, 0x00000, 0x04F03, HashLibStringArray({ "CRC-17/CAN-FD" }));

		case CRC21_CANFD:
			return make_shared<_CRC>(21, 0x102899, 0x00000, false, false, 0x00000, 0x0ED841, HashLibStringArray({ "CRC-21/CAN-FD" }));

		case CRC24:
			return make_shared<_CRC>(24, 0x864CFB, 0xB704CE, false, false, 0x000000, 0x21CF02, HashLibStringArray({ "CRC-24", "CRC-24/OPENPGP" }));

		case CRC24_BLE:
			return make_shared<_CRC>(24, 0x00065B, 0x555555, true, true, 0x000000, 0xC25A56, HashLibStringArray({ "CRC-24/BLE" }));

		case CRC24_FLEXRAYA:
			return make_shared<_CRC>(24, 0x5D6DCB, 0xFEDCBA, false, false, 0x000000, 0x7979BD, HashLibStringArray({ "CRC-24/FLEXRAY-A" }));

		case CRC24_FLEXRAYB:
			return make_shared<_CRC>(24, 0x5D6DCB, 0xABCDEF, false, false, 0x000000, 0x1F23B8, HashLibStringArray({ "CRC-24/FLEXRAY-B" }));

		case CRC24_INTERLAKEN:
			return make_shared<_CRC>(24, 0x328B63, 0xFFFFFF, false, false, 0xFFFFFF, 0xB4F3E6, HashLibStringArray({ "CRC-24/INTERLAKEN" }));

		case CRC24_LTEA:
			return make_shared<_CRC>(24, 0x864CFB, 0x000000, false, false, 0x000000, 0xCDE703, HashLibStringArray({ "CRC-24/LTE-A" }));

		case CRC24_LTEB:
			return make_shared<_CRC>(24, 0x800063, 0x000000, false, false, 0x000000, 0x23EF52, HashLibStringArray({ "CRC-24/LTE-B" }));

		case CRC30_CDMA:
			return make_shared<_CRC>(30, 0x2030B9C7, 0x3FFFFFFF, false, false, 0x3FFFFFFF, 0x04C34ABF, HashLibStringArray({ "CRC-30/CDMA" }));

		case CRC31_PHILIPS:
			return make_shared<_CRC>(31, 0x04C11DB7, 0x7FFFFFFF, false, false, 0x7FFFFFFF, 0x0CE9E46C, HashLibStringArray({ "CRC-31/PHILLIPS" }));

		case CRC32:
			return make_shared<_CRC>(32, 0x04C11DB7, 0xFFFFFFFF, true, true, 0xFFFFFFFF, 0xCBF43926, HashLibStringArray({ "CRC-32", "CRC-32/ADCCP", "PKZIP" }));

		case CRC32_AUTOSAR:
			return make_shared<_CRC>(32, 0xF4ACFB13, 0xFFFFFFFF, true, true, 0xFFFFFFFF, 0x1697D06A, HashLibStringArray({ "CRC-32/AUTOSAR" }));

		case CRC32_BZIP2:
			return make_shared<_CRC>(32, 0x04C11DB7, 0xFFFFFFFF, false, false, 0xFFFFFFFF, 0xFC891918, HashLibStringArray({ "CRC-32/BZIP2", "CRC-32/AAL5",	"CRC-32/DECT-B", "B-CRC-32" }));

		case CRC32C:
			return make_shared<_CRC>(32, 0x1EDC6F41, 0xFFFFFFFF, true, true, 0xFFFFFFFF, 0xE3069283, HashLibStringArray({ "CRC-32C", "CRC-32/ISCSI", "CRC-32/CASTAGNOLI", "CRC-32/INTERLAKEN" }));

		case CRC32D:
			return make_shared<_CRC>(32, 0xA833982B, 0xFFFFFFFF, true, true, 0xFFFFFFFF, 0x87315576, HashLibStringArray({ "CRC-32D" }));

		case CRC32_MPEG2:
			return make_shared<_CRC>(32, 0x04C11DB7, 0xFFFFFFFF, false, false, 0x00000000, 0x0376E6E7, HashLibStringArray({ "CRC-32/MPEG-2" }));

		case CRC32_POSIX:
			return make_shared<_CRC>(32, 0x04C11DB7, 0xFFFFFFFF, false, false, 0x00000000, 0x0376E6E7, HashLibStringArray({ "CRC-32/POSIX", "CKSUM" }));

		case CRC32Q:
			return make_shared<_CRC>(32, 0x814141AB, 0x00000000, false, false, 0x00000000, 0x3010BF7F, HashLibStringArray({ "CRC-32Q" }));

		case JAMCRC:
			return make_shared<_CRC>(32, 0x04C11DB7, 0xFFFFFFFF, true, true, 0x00000000, 0x340BC6D9, HashLibStringArray({ "JAMCRC" }));

		case XFER:
			return make_shared<_CRC>(32, 0x000000AF, 0x00000000, false, false, 0x00000000, 0xBD0BE338, HashLibStringArray({ "XFER" }));

		case CRC40_GSM:
			return make_shared<_CRC>(40, 0x0004820009, 0x0000000000, false, false, 0xFFFFFFFFFF, 0xD4164FC646, HashLibStringArray({ "CRC-40/GSM" }));

		case CRC64:
			return make_shared<_CRC>(64, 0x42F0E1EBA9EA3693, 0x0000000000000000, false, false, 0x0000000000000000, 0x6C40DF5F0B497347, HashLibStringArray({ "CRC-64", "CRC-64/ECMA-182" }));

		case CRC64_GOISO:
			return make_shared<_CRC>(64, 0x000000000000001B, 0xFFFFFFFFFFFFFFFF, true, true, 0xFFFFFFFFFFFFFFFF, 0xB90956C775A41001, HashLibStringArray({ "CRC-64/GO-ISO" }));

		case CRC64_WE:
			return make_shared<_CRC>(64, 0x42F0E1EBA9EA3693, UInt64(0xFFFFFFFFFFFFFFFF), false, false, UInt64(0xFFFFFFFFFFFFFFFF), 0x62EC59E3F1A4F00A, HashLibStringArray({ "CRC-64/WE" }));

		case CRC64_XZ:
			return make_shared<_CRC>(64, 0x42F0E1EBA9EA3693, UInt64(0xFFFFFFFFFFFFFFFF), true, true, UInt64(0xFFFFFFFFFFFFFFFF), UInt64(0x995DC9BBDF1939FA), HashLibStringArray({ "CRC-64/XZ", "CRC-64/GO-ECMA" }));

		} // end switch

		throw ArgumentInvalidHashLibException(Utils::string_format(UnSupportedCRCType, a_value));
	} // end function CreateCRCObject

private:
	_CRC Copy() const
	{
		_CRC HashInstance = _CRC(_width, _polynomial, _init, _reflectIn, _reflectOut, _xorOut, _checkValue, _names);
		HashInstance._crcMask = _crcMask;
		HashInstance._crcHighBitMask = _crcHighBitMask;
		HashInstance._hash = _hash;
		HashInstance._isTableGenerated = _isTableGenerated;
		HashInstance._crcTable = _crcTable;

		return HashInstance;
	}

	inline void SetNames(const HashLibStringArray& value)
	{
		_names = value;
	} // end function SetNames

	inline void SetWidth(const Int32 value)
	{
		_width = value;
	} // end function SetWidth

	inline void SetPolynomial(const UInt64 value)
	{
		_polynomial = value;
	} // end function SetPolynomial

	inline void SetInit(const UInt64 value)
	{
		_init = value;
	} // end function SetInit

	inline void SetReflectIn(const bool value)
	{
		_reflectIn = value;
	} // end function SetReflectIn

	inline void SetReflectOut(const bool value)
	{
		_reflectOut = value;
	} // end function SetReflectOut

	inline void SetXOROut(const UInt64 value)
	{
		_xorOut = value;
	} // end function SetXOROut

	inline void SetCheckValue(const UInt64 value)
	{
		_checkValue = value;
	} // end function SetCheckValue

public:
	inline virtual HashLibStringArray GetNames() const
	{
		return _names;
	} // end function GetNames

	inline virtual Int32 GetWidth() const
	{
		return _width;
	} // end function GetWidth

	inline virtual UInt64 GetPolynomial() const
	{
		return _polynomial;
	} // end function GetPolynomial

	inline virtual UInt64 GetInit() const
	{
		return _init;
	} // end function GetInit

	inline virtual bool GetReflectIn() const
	{
		return _reflectIn;
	} // end function GetReflectIn

	inline virtual bool GetReflectOut() const
	{
		return _reflectOut;
	} // end function GetReflectOut 

	inline virtual UInt64 GetXOROut() const
	{
		return _xorOut;
	} // end function GetXOROut

	inline virtual UInt64 GetCheckValue() const
	{
		return _checkValue;
	} // end function GetCheckValue

private:
	void GenerateTable()
	{
		UInt64 bit, crc;
		UInt32 i = 0, j = 0;

		_crcTable = HashLibUInt64Array(256);
		_ptr_Fm_CRCTable = &_crcTable[0];

		while (i < 256)
		{
			crc = i;
			if (_reflectIn)
				crc = Reflect(crc, 8);

			crc = crc << (_width - 8);
			j = 0;
			while (j < 8)
			{
				bit = crc & _crcHighBitMask;
				crc = crc << 1;
				if (bit != 0)
					crc = (crc ^ _polynomial);
				j++;
			} // end while

			if (_reflectIn)
				crc = Reflect(crc, _width);

			crc = crc & _crcMask;
			_ptr_Fm_CRCTable[i] = crc;
			i++;
		} // end while

		_isTableGenerated = true;
	} // end function GenerateTable

	// tables work only for 8, 16, 24, 32 bit CRC
	void CalculateCRCbyTable(const byte* a_data, const Int32 a_data_length, const Int32 a_index)
	{
		Int32 Length, i;
		UInt64 tmp;

		Length = a_data_length;
		i = a_index;
		tmp = _hash;

		if (_reflectIn)
		{
			while (Length > 0)
			{
				tmp = (tmp >> 8) ^ _ptr_Fm_CRCTable[byte(tmp ^ a_data[i])];
				i++;
				Length--;
			} // end while
		} // end if
		else
		{
			while (Length > 0)
			{
				tmp = (tmp << 8) ^ _ptr_Fm_CRCTable
					[byte((tmp >> (_width - 8)) ^ a_data[i])];
				i++;
				Length--;
			} // end while
		} // end else

		_hash = tmp;
	} // end function CalculateCRCbyTable

	// fast bit by bit algorithm without augmented zero bytes.
	// does not use lookup table, suited for polynomial orders between 1...32.
	void CalculateCRCdirect(const byte* a_data, const Int32 a_data_length, const Int32 a_index)
	{
		Int32 Length, i;
		UInt64 c, bit, j;

		Length = a_data_length;
		i = a_index;

		while (Length > 0)
		{
			c = a_data[i];
			if (_reflectIn)
				c = Reflect(c, 8);

			j = 0x80;
			while (j > 0)
			{
				bit = _hash & _crcHighBitMask;
				_hash = _hash << 1;
				if ((c & j) > 0)
					bit = bit ^ _crcHighBitMask;
				if (bit > 0)
					_hash = _hash ^ _polynomial;
				j = j >> 1;
			} // end while

			i++;
			Length--;
		} // end while

	} // end function CalculateCRCdirect

	// reflects the lower 'width' bits of 'value'
	static UInt64 Reflect(const UInt64 a_value, const Int32 a_width)
	{
		UInt64 j, i, result = 0;

		j = 1;
		i = UInt64(1) << (a_width - 1);
		while (i != 0)
		{
			if ((a_value & i) != 0)
				result = result | j;

			j = j << 1;
			i = i >> 1;
		} // end while

		return result;
	} // end function Reflect

private:
	HashLibStringArray _names;
	Int32 _width;
	UInt64 _polynomial, _init, _xorOut, _checkValue, _crcMask, _crcHighBitMask, _hash;
	bool _reflectIn, _reflectOut;
	bool _isTableGenerated;

	HashLibUInt64Array _crcTable;
	UInt64* _ptr_Fm_CRCTable = nullptr;

	static const Int32 Delta = 7;

	static const char* UnSupportedCRCType;
	static const char* WidthOutOfRange;

}; // end class _CRC

const char* _CRC::UnSupportedCRCType = "UnSupported CRC Type: \"%u\"";
const char* _CRC::WidthOutOfRange = "Width must be between 3 and 64. \"%u\"";
