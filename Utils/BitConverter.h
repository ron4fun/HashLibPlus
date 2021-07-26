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

#include "HashLibTypes.h"

class BitConverter
{
public:
	BitConverter()
	{
		Int32 IntValue = 1;
		int * PIIntValueAddress = &IntValue;
		byte *PBIntValueAddress = (byte *)PIIntValueAddress;
		byte ByteValue = *PBIntValueAddress;
		
		IsLittleEndian = (ByteValue == 1) ? true : false;
	} // end constructor

	inline static bool GetIsLittleEndian()
	{
		return IsLittleEndian;
	} // end function GetIsLittleEndian

	inline static char GetHexValue(const Int32 i)
	{
		if (i < 10)
		{
			return i + '0';
		} // end if
		
		return (i - 10) + 'A';
	} // end function GetHexValue

	inline static HashLibByteArray GetBytes(const Int16 value)
	{
		HashLibByteArray result = HashLibByteArray(sizeof(value));
		*(Int16 *)(&(result[0])) = value;

		return result;
	} // end function GetBytes

	inline static HashLibByteArray GetBytes(const Int32 value)
	{
		HashLibByteArray result = HashLibByteArray(sizeof(value));
		*(Int32 *)(&(result[0])) = value;

		return result;
	} // end function GetBytes

	inline static HashLibByteArray GetBytes(const float value)
	{
		HashLibByteArray result = HashLibByteArray(sizeof(value));
		*(float *)(&(result[0])) = value;

		return result;
	} // end function GetBytes

	inline static HashLibByteArray GetBytes(const double value)
	{
		HashLibByteArray result = HashLibByteArray(sizeof(value));
		*(double *)(&(result[0])) = value;

		return result;
	} // end function GetBytes

	inline static HashLibByteArray GetBytes(const bool value)
	{
		HashLibByteArray result = HashLibByteArray(sizeof(value));
		*(bool *)(&(result[0])) = value;

		return result;
	} // end function GetBytes

	inline static HashLibByteArray GetBytes(const char value)
	{
		HashLibByteArray result = HashLibByteArray(sizeof(value));
		*(char *)(&(result[0])) = value;

		return result;
	} // end function GetBytes

	inline static HashLibByteArray GetBytes(const byte value)
	{
		HashLibByteArray result = HashLibByteArray(sizeof(value));
		*(byte *)(&(result[0])) = value;

		return result;
	} // end function GetBytes

	inline static HashLibByteArray GetBytes(const UInt16 value)
	{
		HashLibByteArray result = HashLibByteArray(sizeof(value));
		*(UInt16 *)(&(result[0])) = value;

		return result;
	} // end function GetBytes

	inline static HashLibByteArray GetBytes(const UInt32 value)
	{
		HashLibByteArray result = HashLibByteArray(sizeof(value));
		*(UInt32 *)(&(result[0])) = value;

		return result;
	} // end function GetBytes

	inline static HashLibByteArray GetBytes(const Int64 value)
	{
		HashLibByteArray result = HashLibByteArray(sizeof(value));
		*(Int64 *)(&(result[0])) = value;

		return result;
	} // end function GetBytes

	inline static HashLibByteArray GetBytes(const UInt64 value)
	{
		HashLibByteArray result = HashLibByteArray(sizeof(value));
		*(UInt64 *)(&(result[0])) = value;

		return result;
	} // end function GetBytes

	inline static bool ToBoolean(const HashLibByteArray &value, const Int32 StartIndex)
	{
		return *(bool *)(&value[StartIndex]);
	} // end function ToBoolean

	inline static char ToChar(const HashLibByteArray &value, const Int32 StartIndex)
	{
		if (IsLittleEndian)
		{
			return  (value[StartIndex] | (value[size_t(StartIndex) + 1] << 8));
		} // end if

		return ((value[StartIndex] << 8) | value[size_t(StartIndex) + 1]);
	} // end function ToChar

	inline static double ToDouble(const HashLibByteArray &value, const Int32 StartIndex)
	{
		Int32 i1, i2;
		Int64 val;

		if (IsLittleEndian)
		{
			i1 = value[StartIndex] | (value[size_t(StartIndex) + 1] << 8) |
				(value[size_t(StartIndex) + 2] << 16) | (value[size_t(StartIndex) + 3] << 24);
			i2 = (value[size_t(StartIndex) + 4]) | (value[size_t(StartIndex) + 5] << 8) |
				(value[size_t(StartIndex) + 6] << 16) | (value[size_t(StartIndex) + 7] << 24);
			val = UInt32(i1) | (Int64(i2) << 32);
			return *(double *)(&val);
		}

		i1 = (value[StartIndex] << 24) | (value[size_t(StartIndex) + 1] << 16) |
		(value[size_t(StartIndex) + 2] << 8) | (value[size_t(StartIndex) + 3]);
		i2 = (value[size_t(StartIndex) + 4] << 24) | (value[size_t(StartIndex) + 5] << 16) |
		(value[size_t(StartIndex) + 6] << 8) | (value[size_t(StartIndex) + 7]);
		val = UInt32(i2) | (Int64(i1) << 32);
		return *(double *)(&val);
	} // end function ToDouble

	inline static Int16 ToInt16(const HashLibByteArray &value, const Int32 StartIndex)
	{
		if (IsLittleEndian)
		{
			return (value[StartIndex] | (value[size_t(StartIndex) + 1] << 8));
		} // end if

		return ((value[StartIndex] << 8) | value[size_t(StartIndex) + 1]);
	} // end function ToInt16

	inline static Int32 ToInt32(const HashLibByteArray &value, const Int32 StartIndex)
	{
		if (IsLittleEndian)
		{
			return value[StartIndex] | (value[size_t(StartIndex) + 1] << 8) |
				(value[size_t(StartIndex) + 2] << 16) | (value[size_t(StartIndex) + 3] << 24);
		} // end if

		return (value[StartIndex] << 24) | (value[size_t(StartIndex) + 1] << 16) |
			(value[size_t(StartIndex) + 2] << 8) | (value[size_t(StartIndex) + 3]);
	} // end function ToInt32
	
	inline static Int64 ToInt64(const HashLibByteArray &value, const Int32 StartIndex)
	{
		Int32 i1, i2;

		if (IsLittleEndian)
		{
			i1 = value[StartIndex] | (value[size_t(StartIndex) + 1] << 8) |
			(value[size_t(StartIndex) + 2] << 16) | (value[size_t(StartIndex) + 3] << 24);
			i2 = (value[size_t(StartIndex) + 4]) | (value[size_t(StartIndex) + 5] << 8) |
			(value[size_t(StartIndex) + 6] << 16) | (value[size_t(StartIndex) + 7] << 24);
			return UInt32(i1) | (Int64(i2) << 32);
		} // end if
		
		i1 = (value[StartIndex] << 24) | (value[size_t(StartIndex) + 1] << 16) |
			(value[size_t(StartIndex) + 2] << 8) | (value[size_t(StartIndex) + 3]);
		i2 = (value[size_t(StartIndex) + 4] << 24) | (value[size_t(StartIndex) + 5] << 16) |
		(value[size_t(StartIndex) + 6] << 8) | (value[size_t(StartIndex) + 7]);
		return UInt32(i2) | (Int64(i1) << 32);
	} // end function ToInt64
	
	inline static float ToFloat(const HashLibByteArray &value, const Int32 StartIndex)
	{
		Int32 val;

		if (IsLittleEndian)
		{
			val = (value[StartIndex] | (value[size_t(StartIndex) + 1] << 8) |
			(value[size_t(StartIndex) + 2] << 16) | (value[size_t(StartIndex) + 3] << 24));
			return *(float *)(&val);
		} // end if
	
		val = (value[StartIndex] << 24) | (value[size_t(StartIndex) + 1] << 16) |
		(value[size_t(StartIndex) + 2] << 8) | (value[size_t(StartIndex) + 3]);
		return *(float *)(&val);
	} // end function ToFloat
	
	inline static string ToString(const HashLibByteArray &value)
	{
		return BitConverter::ToString(value, 0);
	} // end function ToString
	
	inline static string ToString(const HashLibByteArray &value, const Int32 StartIndex)
	{
		return BitConverter::ToString((byte *)&value[0], StartIndex, (Int32)value.size() - StartIndex);
	} // end function ToString

	inline static string ToString(const byte *value, const Int32 StartIndex, const Int32 Length)
	{
		string result;

		Int32 chArrayLength = Length * 3;

		char* chArray = new char[chArrayLength];

		Int32 Idx = 0;
		Int32 Index = StartIndex;
		while (Idx < chArrayLength)
		{
			byte b = value[Index];
			Index += 1;

			chArray[Idx] = BitConverter::GetHexValue(b >> 4);
			chArray[Idx + 1] = BitConverter::GetHexValue(b & 15);
			chArray[Idx + 2] = '-';

			Idx += 3;
		} // end while
		
		result = string((char *)&chArray[0], size_t(chArrayLength) - 1);

		delete[] chArray;

		return result;
	} // end function ToString

	inline static byte ToUInt8(const HashLibByteArray &value, const Int32 StartIndex)
	{
		return *(byte *)(&value[StartIndex]);
	} // end function ToUInt8

	inline static UInt16 ToUInt16(const HashLibByteArray &value, const Int32 StartIndex)
	{
		if (IsLittleEndian)
		{
			return (value[StartIndex] | (value[size_t(StartIndex) + 1] << 8));
		} // end if
		
		return ((value[StartIndex] << 8) | value[size_t(StartIndex) + 1]);
	} // end function ToUInt16

	inline static UInt32 ToUInt32(const HashLibByteArray &value, const Int32 StartIndex)
	{
		if (IsLittleEndian)
		{
			return (value[StartIndex] | (value[size_t(StartIndex) + 1] << 8) |
				(value[size_t(StartIndex) + 2] << 16) | (value[size_t(StartIndex) + 3] << 24));
		} // end if
		
		return ((value[StartIndex] << 24) |
				(value[size_t(StartIndex) + 1] << 16) | (value[size_t(StartIndex) + 2] << 8) |
				(value[size_t(StartIndex) + 3]));
	} // end function ToUInt32

	inline static UInt32 ToUInt32(const byte *value, const Int32 StartIndex)
	{
		if (IsLittleEndian)
		{
			return (value[StartIndex] | (value[StartIndex + 1] << 8) |
				(value[StartIndex + 2] << 16) | (value[StartIndex + 3] << 24));
		} // end if
		
		return ((value[StartIndex] << 24) |
				(value[StartIndex + 1] << 16) | (value[StartIndex + 2] << 8) |
				(value[StartIndex + 3]));
	} // end function ToUInt32

	inline static UInt64 ToUInt64(const HashLibByteArray &value, const Int32 StartIndex)
	{
		Int32 i1, i2;
		
		if (IsLittleEndian)
		{
			i1 = value[StartIndex] | (value[size_t(StartIndex) + 1] << 8) |
			(value[size_t(StartIndex) + 2] << 16) | (value[size_t(StartIndex) + 3] << 24);
			i2 = (value[size_t(StartIndex) + 4]) | (value[size_t(StartIndex) + 5] << 8) |
			(value[size_t(StartIndex) + 6] << 16) | (value[size_t(StartIndex) + 7] << 24);
			return UInt64(UInt32(i1) | (Int64(i2) << 32));
		} // end if
		
		i1= (value[StartIndex] << 24) | (value[size_t(StartIndex) + 1] << 16) |
			(value[size_t(StartIndex) + 2] << 8) | (value[size_t(StartIndex) + 3]);
		i2 = (value[size_t(StartIndex) + 4] << 24) | (value[size_t(StartIndex) + 5] << 16) |
			(value[size_t(StartIndex) + 6] << 8) | (value[size_t(StartIndex) + 7]);
		return UInt64(UInt32(i2) | (Int64(i1) << 32));
	} // end function ToUInt64
	
	inline static UInt64 ToUInt64(const byte *value, const Int32 StartIndex)
	{
		Int32 i1, i2;
		
		if (IsLittleEndian)
		{
			i1 = value[StartIndex] | (value[StartIndex + 1] << 8) |
			(value[StartIndex + 2] << 16) | (value[StartIndex + 3] << 24);
			i2 = (value[StartIndex + 4]) | (value[StartIndex + 5] << 8) |
			(value[StartIndex + 6] << 16) | (value[StartIndex + 7] << 24);
			return UInt64(UInt32(i1) | (Int64(i2) << 32));
		} // end if
			
		i1 = (value[StartIndex] << 24) | (value[StartIndex + 1] << 16) |
			(value[StartIndex + 2] << 8) | (value[StartIndex + 3]);
		i2 = (value[StartIndex + 4] << 24) | (value[StartIndex + 5] << 16) |
			(value[StartIndex + 6] << 8) | (value[StartIndex + 7]);
		return UInt64(UInt32(i2) | (Int64(i1) << 32));
	} // end function ToUInt64
	
private:
	inline static bool staticConstructor()
	{
		Int32 IntValue = 1;
		int * PIIntValueAddress = &IntValue;
		byte *PBIntValueAddress = (byte *)PIIntValueAddress;
		byte ByteValue = *PBIntValueAddress;

		return (ByteValue == 1) ? true : false;
	} // end function staticConstructor

	static bool IsLittleEndian;

}; // end class BitConverter
