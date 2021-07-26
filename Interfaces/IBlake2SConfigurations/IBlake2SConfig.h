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

#include "../../Utils/HashLibTypes.h"

class IIBlake2SConfig;

typedef shared_ptr<IIBlake2SConfig> IBlake2SConfig;

class IIBlake2SConfig
{
public:
	virtual HashLibByteArray GetPersonalization() const = 0;
	virtual void SetPersonalization(const HashLibByteArray& value) = 0;
	virtual HashLibByteArray GetSalt() const = 0;
	virtual void SetSalt(const HashLibByteArray& value) = 0;
	virtual HashLibByteArray GetKey() const = 0;
	virtual void SetKey(const HashLibByteArray& value) = 0;
	virtual Int32 GetHashSize() const = 0;
	virtual void SetHashSize(const Int32 value) = 0;

	virtual IBlake2SConfig Clone() const = 0;

	virtual void Clear() = 0;

}; // end class IBlake2SConfig
