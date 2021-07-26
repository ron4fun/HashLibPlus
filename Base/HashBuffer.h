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

#include <sstream>
#include "../Utils/HashLibTypes.h"

class HashBuffer
{
public:
	HashBuffer(const Int32 a_length = 0)
		: _pos(0)
	{
		if (a_length > 0) {
			_data.resize(a_length);
			Initialize();
		}
	} // end constructor

	~HashBuffer()
	{} // end destructor

	HashBuffer Clone() const
	{
		HashBuffer result = HashBuffer();
		result._data = _data;
		result._pos = _pos;

		return result;
	}

	bool Feed(const byte* a_data, const Int32 a_length_a_data, const Int32 a_length)
	{
		Int32 Length;

		if (a_length_a_data == 0)
		{
			return false;
		} // end if

		if (a_length == 0)
		{
			return false;
		} // end if

		Length = (Int32)_data.size() - _pos;
		if (Length > a_length)
		{
			Length = a_length;
		} // end if

		memmove(&_data[_pos], &a_data[0], Length * sizeof(byte));

		_pos = _pos + Length;

		return GetIsFull();
	} // end function Feed

	bool Feed(const byte* a_data, const Int32 a_length_a_data,
		Int32& a_start_index, Int32& a_length, UInt64& a_processed_bytes)
	{
		Int32 Length;

		if (a_length_a_data == 0)
		{
			return false;
		} // end if

		if (a_length == 0)
		{
			return false;
		} // end if

		Length = (Int32)_data.size() - _pos;
		if (Length > a_length)
		{
			Length = a_length;
		} // end if

		memmove(&_data[_pos], &a_data[a_start_index], Length * sizeof(byte));

		_pos = _pos + Length;
		a_start_index = a_start_index + Length;
		a_length = a_length - Length;
		a_processed_bytes = a_processed_bytes + UInt64(Length);

		return GetIsFull();
	} // end function Feed

	inline HashLibByteArray GetBytes()
	{
		_pos = 0;
		return _data;
	} // end function GetBytes

	inline HashLibByteArray GetBytesZeroPadded()
	{
		memset(&_data[_pos], 0, (_data.size() - _pos) * sizeof(byte));
		_pos = 0;
		return _data;
	} // end function GetBytesZeroPadded

	bool GetIsEmpty() const
	{
		return _pos == 0;
	} // end function GetIsEmpty

	bool GetIsFull() const
	{
		return _pos == _data.size();
	} // end function GetIsFull

	Int32 GetLength() const
	{
		return (Int32)_data.size();
	} // end function GetLength

	Int32 GetPos() const
	{
		return _pos;
	} // end function GetPos

	void Initialize()
	{
		_pos = 0;
		memset(&_data[0], 0, _data.size() * sizeof(byte));
	} // end function Initialize

	string ToString() const
	{
		stringstream ss;
		ss << "HashBuffer, Length: " << GetLength();
		ss << ", Pos: " << GetPos() << ", IsEmpty: " << GetIsEmpty();

		return ss.str();
	} // end function ToString


private:
	HashLibByteArray _data;
	Int32 _pos;

}; // end class HashBuffer
