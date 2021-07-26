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

#include "../Utils/Converters.h"
#include "../Interfaces/IHashResult.h"

class HashResult : public virtual IIHashResult
{
private:
	static const char* ImpossibleRepresentationInt32;
	static const char* ImpossibleRepresentationUInt8;
	static const char* ImpossibleRepresentationUInt16;
	static const char* ImpossibleRepresentationUInt32;
	static const char* ImpossibleRepresentationUInt64;

public:
	HashResult()
		: _hash(HashLibByteArray(0))
	{} // end constructor

	HashResult(const UInt64 a_hash)
		: _hash(HashLibByteArray(8))
	{
		_hash[0] = byte(a_hash >> 56);
		_hash[1] = byte(a_hash >> 48);
		_hash[2] = byte(a_hash >> 40);
		_hash[3] = byte(a_hash >> 32);
		_hash[4] = byte(a_hash >> 24);
		_hash[5] = byte(a_hash >> 16);
		_hash[6] = byte(a_hash >> 8);
		_hash[7] = byte(a_hash);
	} // end constructor

	HashResult(const HashLibByteArray& a_hash)
	{
		_hash = a_hash;
	} // end constructor

	HashResult(const UInt32 a_hash)
		: _hash(HashLibByteArray(4))
	{
		_hash[0] = byte(a_hash >> 24);
		_hash[1] = byte(a_hash >> 16);
		_hash[2] = byte(a_hash >> 8);
		_hash[3] = byte(a_hash);
	} // end constructor

	HashResult(const byte a_hash)
		: _hash(HashLibByteArray(1))
	{
		_hash[0] = a_hash;
	} // end constructor

	HashResult(const UInt16 a_hash)
		: _hash(HashLibByteArray(2))
	{
		_hash[0] = byte(a_hash >> 8);
		_hash[1] = byte(a_hash);
	} // end constructor

	HashResult(const Int32 a_hash)
		: _hash(HashLibByteArray(4))
	{
		_hash[0] = byte(Bits::Asr32(a_hash, 24));
		_hash[1] = byte(Bits::Asr32(a_hash, 16));
		_hash[2] = byte(Bits::Asr32(a_hash, 8));
		_hash[3] = byte(a_hash);
	} // end constructor

	~HashResult()
	{} // end destructor

	const HashResult& operator=(const HashResult& right)
	{
		if (&right != this)
		{
			_hash = ::move(right._hash);
		} // end if

		return *this;
	} // end funcion operator=

	virtual bool CompareTo(const IHashResult& a_hashResult) const
	{
		return HashResult::SlowEquals(a_hashResult->GetBytes(), _hash);
	} // end function CompareTo

	bool operator==(const HashResult& a_hashResult) const
	{
		return HashResult::SlowEquals(a_hashResult.GetBytes(), _hash);
	} // end function operator==

	virtual HashLibByteArray GetBytes() const
	{
		return _hash;
	} // end function GetBytesAsVector

	virtual inline Int32 GetHashCode() const
	{
		HashLibByteArray TempHolder = HashLibByteArray(_hash);

		Converters::toUpper(&TempHolder[0], (UInt32)TempHolder.size());

		Int32 LResult = 0;
		Int32 I = 0;
		Int32 Top = (Int32)_hash.size();

		while (I < Top)
		{
			LResult = Bits::RotateLeft32(LResult, 5);
			LResult = LResult ^ UInt32(TempHolder[I]);
			I += 1;
		} // end while

		return LResult;
	} // end function GetHashCode

	virtual inline Int32 GetInt32() const
	{
		if (_hash.size() != 4)
		{
			throw InvalidOperationHashLibException(HashResult::ImpossibleRepresentationInt32);
		} // end if

		return (Int32(_hash[0]) << 24) | (Int32(_hash[1]) << 16) |
			(Int32(_hash[2]) << 8) | Int32(_hash[3]);
	} // end function GetInt32

	virtual inline byte GetUInt8() const
	{
		if (_hash.size() != 1)
		{
			throw InvalidOperationHashLibException(HashResult::ImpossibleRepresentationUInt8);
		} // end if

		return _hash[0];
	} // end function GetUInt8

	virtual inline  UInt16 GetUInt16() const
	{
		if (_hash.size() != 2)
		{
			throw InvalidOperationHashLibException(HashResult::ImpossibleRepresentationUInt16);
		} // end if

		return (UInt16(_hash[0]) << 8) | UInt16(_hash[1]);
	} // end function GetUInt16

	virtual inline UInt32 GetUInt32() const
	{
		if (_hash.size() != 4)
		{
			throw InvalidOperationHashLibException(HashResult::ImpossibleRepresentationUInt32);
		} // end if

		return (UInt32(_hash[0]) << 24) | (UInt32(_hash[1]) << 16) |
			(UInt32(_hash[2]) << 8) | UInt32(_hash[3]);
	} // end function GetUInt32

	virtual inline UInt64 GetUInt64() const
	{
		if (_hash.size() != 8)
		{
			throw InvalidOperationHashLibException(HashResult::ImpossibleRepresentationUInt64);
		} // end if

		return (UInt64(_hash[0]) << 56) | (UInt64(_hash[1]) << 48) | (UInt64(_hash[2]) << 40) | (UInt64(_hash[3]) << 32) |
			(UInt64(_hash[4]) << 24) | (UInt64(_hash[5]) << 16) | (UInt64(_hash[6]) << 8) | UInt64(_hash[7]);
	} // end function GetUInt64

	static inline bool SlowEquals(const HashLibByteArray& a_ar1, const HashLibByteArray& a_ar2)
	{
		UInt32 diff = (UInt32)(a_ar1.size() ^ a_ar2.size());
		UInt32 I = 0;

		while (I <= (a_ar1.size() - 1) && I <= (a_ar2.size() - 1))
		{
			diff = (diff | (a_ar1[I] ^ a_ar2[I]));
			I += 1;
		} // end while

		return diff == 0;
	} // end function SlowEquals

	virtual inline string ToString(const bool a_group = false) const
	{
		return Converters::ConvertBytesToHexString(_hash, a_group);
	} // end function ToString

private:
	HashLibByteArray _hash;

}; // end class HashResult
