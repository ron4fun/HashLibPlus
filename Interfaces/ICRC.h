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

#include "IHash.h"

class IICRC;

typedef shared_ptr<IICRC> ICRC;

class IICRC : public virtual IIHash
{
	friend ostream& operator<<(ostream& output, const ICRC& _hash)
	{
		output << _hash->GetName();
		return output;
	}

public:
	virtual HashLibStringArray GetNames() const = 0;
	virtual Int32 GetWidth() const = 0;
	virtual UInt64 GetPolynomial() const = 0;
	virtual UInt64 GetInit() const = 0;
	virtual bool GetReflectIn() const = 0;
	virtual bool GetReflectOut() const = 0;
	virtual UInt64 GetXOROut() const = 0;
	virtual UInt64 GetCheckValue() const = 0;
	
}; // end class ICRC
