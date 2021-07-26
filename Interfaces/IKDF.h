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

#include "../Utils/HashLibTypes.h"

class IIKDF
{
public:
	virtual void Clear() = 0;

	/// <summary>
	/// Returns the pseudo-random bytes for this object.
	/// </summary>
	/// <param name="bc">The number of pseudo-random key bytes to generate.</param>
	/// <returns>A byte array filled with pseudo-random key bytes.</returns>
	/// <exception cref="ArgumentOutOfRangeHashLibException">bc must be greater than zero.</exception>
	/// <exception cref="ArgumentHashLibException">invalid start index or end index of internal buffer.</exception>
	virtual HashLibByteArray GetBytes(const Int32 bc) = 0;

	virtual string GetName() const = 0;

}; // end class IIKDF

typedef shared_ptr<IIKDF> IKDF;
