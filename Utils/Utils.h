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

#include <memory>
#include <cstdio>
#include <string>

#include "HashLibTypes.h"

using namespace std;

class Utils
{
public:
	template<typename ... Args>
	static string string_format(const string &format, Args ... args)
	{
		size_t size = (size_t)snprintf(nullptr, 0, format.c_str(), args ...) + 1; // Extra space for '\0'
		unique_ptr<char[]> buf(new char[size]);
		snprintf(buf.get(), size, format.c_str(), args ...);
		return string(buf.get(), buf.get() + size - 1); // We don't want the '\0' inside
	} // end function string_format

	static HashLibByteArray concat(const HashLibByteArray& x, const HashLibByteArray& y)
	{
		HashLibByteArray result = HashLibByteArray(x);
		result.insert(result.end(), y.begin(), y.end());
		return result;
	} // end function Concat

	static HashLibUInt32Array concat(const HashLibUInt32Array& x, const HashLibUInt32Array& y)
	{
		HashLibUInt32Array result = HashLibUInt32Array(x);
		result.insert(result.end(), y.begin(), y.end());
		return result;
	} // end function Concat

}; // end class Utils
