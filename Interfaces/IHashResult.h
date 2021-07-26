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

#include <iostream>
#include "../Utils/HashLibTypes.h"

class IIHashResult;

typedef shared_ptr<IIHashResult> IHashResult;

class IIHashResult
{
	friend ostream& operator<<(ostream& output, const IHashResult& result)
	{
		output << result->ToString();
		return output;
	}

public:
	virtual HashLibByteArray GetBytes() const = 0;
	virtual byte GetUInt8() const = 0;
	virtual UInt16 GetUInt16() const = 0;
	virtual UInt32 GetUInt32() const = 0;
	virtual Int32 GetInt32() const = 0;
	virtual UInt64 GetUInt64() const = 0;
	virtual string ToString(const bool a_group = false) const = 0;
	virtual Int32 GetHashCode() const = 0;
	virtual bool CompareTo(const IHashResult& a_hashResult) const = 0;

}; // end class IHashResult
