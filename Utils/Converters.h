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

#include <algorithm>
#include <iterator>
#include "../Utils/Bits.h"
#include "../Utils/BitConverter.h"

class Converters
{
public:
	inline static void toUpper(byte* value, const UInt32 length)
	{
		for (UInt32 i = 0; i < length; i++)
		{
			value[i] = toupper(value[i]);
		} // end for

	} // end function toUpper

	inline static string toUpper(const string& value)
	{
		string temp;
		for (UInt32 i = 0; i < value.length(); i++)
		{
			temp += toupper(value[i]);
		} // end for
		return temp;
	} // end function toUpper

	static void swap_copy_str_to_u32(const void* src, const Int32 src_index,
		void* dest, Int32 dest_index, const Int32 length)
	{
		UInt32* lsrc, * ldest, * lend;
		byte* lbsrc;
		Int32	lLength;

		// if all pointers and length are 32-bits aligned
		if (((Int32((byte*)(dest)-(byte*)(0)) | ((byte*)(src)-(byte*)(0)) | src_index |
			dest_index | length) & 3) == 0)
		{
			// copy memory as 32-bit words
			lsrc = (UInt32*)((byte*)(src)+src_index);
			lend = (UInt32*)(((byte*)(src)+src_index) + length);
			ldest = (UInt32*)((byte*)(dest)+dest_index);
			while (lsrc < lend)
			{
				*ldest = Bits::ReverseBytesUInt32(*lsrc);
				ldest += 1;
				lsrc += 1;
			} // end while
		} // end if

		else
		{
			lbsrc = ((byte*)(src)+src_index);

			lLength = length + dest_index;
			while (dest_index < lLength)
			{
				((byte*)dest)[dest_index ^ 3] = *lbsrc;

				lbsrc += 1;
				dest_index += 1;
			} // end while
		} // end else

	} // end function swap_copy_str_to_u32

	static void swap_copy_str_to_u64(const void* src, const Int32 src_index,
		void* dest, Int32 dest_index, const Int32 length)
	{
		UInt64* lsrc, * ldest, * lend;
		byte* lbsrc;
		Int32	lLength;

		// if all pointers and length are 64-bits aligned
		if (((Int32((byte*)(dest)-(byte*)(0)) | ((byte*)(src)-(byte*)(0)) | src_index |
			dest_index | length) & 7) == 0)
		{
			// copy aligned memory block as 64-bit integers
			lsrc = (UInt64*)((byte*)(src)+src_index);
			lend = (UInt64*)(((byte*)(src)+src_index) + length);
			ldest = (UInt64*)((byte*)(dest)+dest_index);
			while (lsrc < lend)
			{
				*ldest = Bits::ReverseBytesUInt64(*lsrc);
				ldest += 1;
				lsrc += 1;
			} // end while
		} // end if
		else
		{
			lbsrc = ((byte*)(src)+src_index);

			lLength = length + dest_index;
			while (dest_index < lLength)
			{
				((byte*)dest)[dest_index ^ 7] = *lbsrc;

				lbsrc += 1;
				dest_index += 1;
			} // end while				
		} // end else		
	} // end function swap_copy_str_to_u64

	inline static UInt32 be2me_32(const UInt32 x)
	{
		if (BitConverter::GetIsLittleEndian())
		{
			return Bits::ReverseBytesUInt32(x);
		} // end if

		return x;
	} // end function be2me_32

	inline static UInt64 be2me_64(const UInt64 x)
	{
		if (BitConverter::GetIsLittleEndian())
		{
			return Bits::ReverseBytesUInt64(x);
		} // end if

		return x;
	} // end function be2me_64

	inline static void be32_copy(const void* src, const Int32 src_index,
		void* dest, const Int32 dest_index, const Int32 length)
	{
		if (BitConverter::GetIsLittleEndian())
		{
			Converters::swap_copy_str_to_u32(src, src_index, dest, dest_index, length);
		} // end if	
		else
		{
			memmove(((byte*)(dest)+dest_index), ((byte*)(src)+src_index), length);
		} // end else
	} // end function be32_copy

	inline static void be64_copy(const void* src, const Int32 src_index,
		void* dest, const Int32 dest_index, const Int32 length)
	{
		if (BitConverter::GetIsLittleEndian())
		{
			Converters::swap_copy_str_to_u64(src, src_index, dest, dest_index, length);
		} // end if	
		else
		{
			memmove(((byte*)(dest)+dest_index), ((byte*)(src)+src_index), length);
		} // end else
	} // end function be64_copy

	inline static UInt32 le2me_32(const UInt32 x)
	{
		if (!BitConverter::GetIsLittleEndian())
		{
			return Bits::ReverseBytesUInt32(x);
		} // end if

		return x;
	} // end function le2me_32

	inline static UInt64 le2me_64(const UInt64 x)
	{
		if (!BitConverter::GetIsLittleEndian())
		{
			return Bits::ReverseBytesUInt64(x);
		} // end if

		return x;
	} // end function le2me_64

	inline static void le32_copy(const void* src, const Int32 src_index,
		void* dest, const Int32 dest_index, const Int32 length)
	{
		if (BitConverter::GetIsLittleEndian())
		{
			memmove(((byte*)(dest)+dest_index), ((byte*)(src)+src_index), length);
		} // end if
		else
		{
			Converters::swap_copy_str_to_u32(src, src_index, dest, dest_index, length);
		} // end else
	} // end function le32_copy

	inline static void le64_copy(const void* src, const Int32 src_index,
		void* dest, const Int32 dest_index, const Int32 length)
	{
		if (BitConverter::GetIsLittleEndian())
		{
			memmove(((byte*)(dest)+dest_index), ((byte*)(src)+src_index), length);
		} // end if
		else
		{
			Converters::swap_copy_str_to_u64(src, src_index, dest, dest_index, length);
		} // end else
	} // end function le64_copy

	inline static UInt32 ReadBytesAsUInt32LE(const byte* a_in, const Int32 a_index)
	{
		UInt32 result = *(UInt32*)(a_in + a_index);
		return Converters::le2me_32(result);
	} // end function ReadBytesAsUInt32LE

	inline static UInt64 ReadBytesAsUInt64LE(const byte* a_in, const Int32 a_index)
	{
		UInt64 result = *(UInt64*)((byte*)a_in + a_index);
		return Converters::le2me_64(result);
	} // end function ReadBytesAsUInt64LE

	inline static HashLibByteArray ReadUInt32AsBytesLE(const UInt32 a_in)
	{
		HashLibByteArray arr = HashLibByteArray(4);
		arr[0] = byte(a_in);
		arr[1] = byte(a_in >> 8);
		arr[2] = byte(a_in >> 16);
		arr[3] = byte(a_in >> 24);

		return arr;
	} // end function ReadUInt32AsBytesLE

	inline static void ReadUInt32AsBytesLE(const UInt32 a_Input, HashLibByteArray& a_Output, const Int32 a_Index)
	{
		a_Output[a_Index] = byte(a_Input); 
		a_Output[size_t(a_Index) + 1] = byte(a_Input >> 8);
		a_Output[size_t(a_Index) + 2] = byte(a_Input >> 16);
		a_Output[size_t(a_Index) + 3] = byte(a_Input >> 24);
	} // end function ReadUInt32AsBytesLE

	inline static void ReadUInt32AsBytesBE(const UInt32 a_Input, HashLibByteArray& a_Output, const Int32 a_Index)
	{
		a_Output[a_Index] = byte(a_Input >> 24);
		a_Output[size_t(a_Index) + 1] = byte(a_Input >> 16);
		a_Output[size_t(a_Index) + 2] = byte(a_Input >> 8);
		a_Output[size_t(a_Index) + 3] = byte(a_Input);
	} // end function ReadUInt32AsBytesBE

	inline static HashLibByteArray ReadUInt64AsBytesLE(const UInt64 a_in)
	{
		HashLibByteArray arr = HashLibByteArray(8);
		arr[0] = byte(a_in);
		arr[1] = byte(a_in >> 8);
		arr[2] = byte(a_in >> 16);
		arr[3] = byte(a_in >> 24);
		arr[4] = byte(a_in >> 32);
		arr[5] = byte(a_in >> 40);
		arr[6] = byte(a_in >> 48);
		arr[7] = byte(a_in >> 56);

		return arr;
	} // end function ReadUInt64AsBytesLE

	inline static void ReadUInt64AsBytesLE(const UInt64 a_in, HashLibByteArray& a_out, const Int32 a_index)
	{
		a_out[a_index] = (byte)a_in;
		a_out[size_t(a_index) + 1] = (byte)(a_in >> 8);
		a_out[size_t(a_index) + 2] = (byte)(a_in >> 16);
		a_out[size_t(a_index) + 3] = (byte)(a_in >> 24);
		a_out[size_t(a_index) + 4] = (byte)(a_in >> 32);
		a_out[size_t(a_index) + 5] = (byte)(a_in >> 40);
		a_out[size_t(a_index) + 6] = (byte)(a_in >> 48);
		a_out[size_t(a_index) + 7] = (byte)(a_in >> 56);
	} // end function ReadUInt64AsBytesLE

	inline static void ReadUInt64AsBytesBE(const UInt64 a_in, HashLibByteArray& a_out, const Int32 a_index)
	{
		a_out[a_index] = (byte)(a_in >> 56);
		a_out[size_t(a_index) + 1] = (byte)(a_in >> 48);
		a_out[size_t(a_index) + 2] = (byte)(a_in >> 40);
		a_out[size_t(a_index) + 3] = (byte)(a_in >> 32);
		a_out[size_t(a_index) + 4] = (byte)(a_in >> 24);
		a_out[size_t(a_index) + 5] = (byte)(a_in >> 16);
		a_out[size_t(a_index) + 6] = (byte)(a_in >> 8);
		a_out[size_t(a_index) + 7] = (byte)a_in;
	} // end function ReadUInt64AsBytesBE

	static string ConvertBytesToHexString(const HashLibByteArray& a_in, const bool a_group = false)
	{
		if (a_in.empty()) return string("");
		return ConvertBytesToHexString(&a_in[0], (UInt32)a_in.size(), a_group);
	} // end function ConvertBytesToHexString

	static string ConvertBytesToHexString(const byte* a_in, const UInt32 size, const bool a_group = false)
	{
		string hex = BitConverter::ToString(a_in, 0, size);
		transform(hex.begin(), hex.end(), hex.begin(), ::toupper);

		if (size == 1)
		{
			return hex;
		} // end if

		if (size == 2)
		{
			string result;
			remove_copy(hex.begin(), hex.end(), back_inserter(result), '-');

			return result;
		} // end if

		if (a_group)
		{
			string workstring = BitConverter::ToString(a_in, 0, size);
			transform(workstring.begin(), workstring.end(), workstring.begin(), ::toupper);

			HashLibStringArray arr = Converters::SplitString(workstring, '-');
			hex.clear();
			UInt32 I = 0;

			while (I < (arr.size() >> 2))
			{
				if (I != 0)
				{
					hex = hex + '-';
				} // end if

				hex = hex + (arr[size_t(I) * 4] + arr[size_t(I) * 4 + 1] + arr[size_t(I) * 4 + 2] + arr[size_t(I) * 4 + 3]);

				I += 1;
			} // end while

			return hex;
		} // end if

		string result;
		remove_copy(hex.begin(), hex.end(), back_inserter(result), '-');

		return result;
	} // end function ConvertBytesToHexString

	static inline HashLibByteArray ConvertHexStringToBytes(const string& _a_in)
	{
		string a_in = _a_in;

		remove(a_in.begin(), a_in.end(), '-');
		HashLibByteArray result(a_in.size() >> 1);

		for (UInt32 i = 0, j = 0; i < a_in.length(); i += 2, j += 1)
		{
			string byteStr = a_in.substr(i, 2);
			result[j] = (char)strtol(byteStr.c_str(), 0, 16);
		} // end for

		return result;
	} // end function ConvertHexStringToBytes

	static inline HashLibByteArray ConvertStringToBytes(const string& a_in)
	{
		HashLibByteArray arr(a_in.length());
		for (UInt32 i = 0; i < a_in.length(); i += 1)
		{
			arr[i] = byte(a_in[i]);
		} // end for

		return arr;
	} // end function ConvertStringToBytes

	static HashLibStringArray SplitString(const string& S, const char Delimiter)
	{
		Int32 PosStart, PosDel, SplitPoints, I, Len;
		HashLibStringArray result;

		if (!S.empty())
		{
			SplitPoints = 0;
			for (UInt32 i = 0; i < S.length(); i += 1)
			{
				if (Delimiter == S[i])
					SplitPoints += 1;
			} // end for

			result.resize(size_t(SplitPoints) + 1);

			I = 0;
			Len = 1;
			PosStart = 0;
			PosDel = (Int32)S.find(Delimiter, 0);
			while (PosDel != string::npos)
			{
				result[I] = S.substr(PosStart, size_t(PosDel) - PosStart);
				PosStart = PosDel + Len;
				PosDel = (Int32)S.find(Delimiter, PosStart);
				I += 1;
			} // end while

			result[I] = S.substr(PosStart, S.length());
		} // end if

		return result;
	} // end function SplitString
	
}; // end class Converters
