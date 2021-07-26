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

class Bits
{
public:
	static void ReverseByteArray(const void *Source, void * Dest, Int64 size)
	{
		byte *ptr_src = (byte *)Source;
		byte *ptr_dest = (byte *)Dest;

		ptr_dest = ptr_dest + (size - 1);
		while (size > 0)
		{
			*ptr_dest = *ptr_src;
			ptr_src += 1;
			ptr_dest -= 1;
			size -= 1;
		} // end while
	} // end function ReverseByteArray
	
	inline static Int32 ReverseBytesInt32(const Int32 value)
	{
		Int32 i1 = value & 0xFF;
		Int32 i2 = Bits::Asr32(value, 8) & 0xFF;
		Int32 i3 = Bits::Asr32(value, 16) & 0xFF;
		Int32 i4 = Bits::Asr32(value, 24) & 0xFF;

		return (i1 << 24) | (i2 << 16) | (i3 << 8) | (i4 << 0);
	} // end function ReverseBytesInt32

	inline static byte ReverseBitsUInt8(const byte value)
	{
		byte result = ((value >> 1) & 0x55) | ((value << 1) & 0xAA);
		result = ((result >> 2) & 0x33) | ((result << 2) & 0xCC);
		return ((result >> 4) & 0x0F) | ((result << 4) & 0xF0);
	} // end function ReverseBitsUInt8

	inline static UInt16 ReverseBytesUInt16(const UInt16 value)
	{
		return ((value & UInt32(0xFF)) << 8 | (value & UInt32(0xFF00)) >> 8);
	} // end function ReverseBytesUInt16

	inline static UInt32 ReverseBytesUInt32(const UInt32 value)
	{
		return (value & UInt32(0x000000FF)) << 24 | 
			(value & UInt32(0x0000FF00)) << 8 | 
			(value & UInt32(0x00FF0000)) >> 8 |
			(value & UInt32(0xFF000000)) >> 24;
	} // end function ReverseBytesUInt32

	inline static UInt64 ReverseBytesUInt64(const UInt64 value)
	{
		return (value & UInt64(0x00000000000000FF)) << 56 |
			(value & UInt64(0x000000000000FF00)) << 40 |
			(value & UInt64(0x0000000000FF0000)) << 24 |
			(value & UInt64(0x00000000FF000000)) << 8 |
			(value & UInt64(0x000000FF00000000)) >> 8 |
			(value & UInt64(0x0000FF0000000000)) >> 24 |
			(value & UInt64(0x00FF000000000000)) >> 40 |
			(value & UInt64(0xFF00000000000000)) >> 56;
	} // end function ReverseBytesUInt64

	inline static Int32 Asr32(const Int32 value, const Int32 ShiftBits)
	{
		return Int32(UInt32(UInt32(UInt32(value) >> (ShiftBits & 31)) |
			(UInt32(Int32(UInt32(0 - UInt32(UInt32(value) >> 31)) &
				UInt32(Int32(0 - (bool((ShiftBits & 31) != 0)))))) << (32 - (ShiftBits & 31)))));		
	} // end function Asr32

	inline static Int64 Asr64(const Int64 value, const Int32 ShiftBits)
	{
		return Int64(UInt64(UInt64(UInt64(value) >> (ShiftBits & 63)) |
			(UInt64(Int64(UInt64(0 - UInt64(UInt64(value) >> 63)) &
				UInt64(Int64(size_t(0) - (bool((ShiftBits & 63) != 0)))))) << (64 - (ShiftBits & 63)))));
	} // end function Asr64

	inline static UInt32 RotateLeft32(const UInt32 a_value, Int32 a_n)
	{
		a_n = a_n & 31;
		return (a_value << a_n) | (a_value >> (32 - a_n));
	} // end function RotateLeft32
	
	inline static UInt64 RotateLeft64(const UInt64 a_value, Int32 a_n)
	{
		a_n = a_n & 63;
		return (a_value << a_n) | (a_value >> (64 - a_n));
	} // end function RotateLeft64

	inline static UInt32 RotateRight32(const UInt32 a_value, Int32 a_n)
	{
		a_n = a_n & 31;
		return (a_value >> a_n) | (a_value << (32 - a_n));
	} // end function RotateRight32

	inline static UInt64 RotateRight64(const UInt64 a_value, Int32 a_n)
	{
		a_n = a_n & 63;
		return (a_value >> a_n) | (a_value << (64 - a_n));
	} // end function RotateRight64

}; // end class Bits
