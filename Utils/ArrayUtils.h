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

class ArrayUtils
{
public:
	static bool constantTimeAreEqual(const HashLibByteArray& buffer1, const HashLibByteArray& buffer2)
	{
		Int32 Idx;
		UInt32 Diff;

		Diff = (UInt32)buffer1.size() ^ (UInt32)buffer2.size();

		Idx = 0;
		while ((size_t)Idx <= buffer1.size() && (size_t)Idx <= buffer2.size())
		{
			Diff = Diff | UInt32(buffer1[Idx] ^ buffer2[Idx]);
			Idx++;
		}

		return Diff == 0;
	} // end function ConstantTimeAreEqual

	static void fill(HashLibByteArray& buffer, const Int32 from, const Int32 to, const byte filler)
	{
		if (!buffer.empty())
			memset(&buffer[from], filler, (size_t(to) - from) * sizeof(byte));
	} // 

	static void fill(HashLibUInt32Array& buffer, const Int32 from, const Int32 to, const UInt32 filler)
	{
		if (!buffer.empty())
		{
			Int32 count = from;
			while (count < to)
			{
				buffer[count] = filler;
				count++;
			}
		}
	}

	static void fill(HashLibUInt64Array& buffer, const Int32 from, const Int32 to, const UInt64 filler)
	{
		if (!buffer.empty())
		{
			Int32 count = from;
			while (count < to)
			{
				buffer[count] = filler;
				count++;
			}
		}
	} //

	static void zeroFill(HashLibByteArray& buffer)
	{
		ArrayUtils::fill(buffer, 0, (Int32)buffer.size(), (byte)0);
	}

	static void zeroFill(HashLibUInt32Array& buffer)
	{
		ArrayUtils::fill(buffer, 0, (Int32)buffer.size(), (UInt32)0);
	}

	static void zeroFill(HashLibUInt64Array& buffer)
	{
		ArrayUtils::fill(buffer, 0, (Int32)buffer.size(), (UInt64)0);
	}

}; // end class ArrayUtils
