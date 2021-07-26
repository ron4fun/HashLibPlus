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

class IIBlake2BTreeConfig;

typedef shared_ptr<IIBlake2BTreeConfig> IBlake2BTreeConfig;

class IIBlake2BTreeConfig
{
public:
	virtual byte GetFanOut() const = 0;
	virtual void SetFanOut(const byte value) = 0;

	virtual byte GetMaxDepth() const = 0;
	virtual void SetMaxDepth(const byte value) = 0;

	virtual byte GetNodeDepth() const = 0;
	virtual void SetNodeDepth(const byte value) = 0;

	virtual byte GetInnerHashSize() const = 0;
	virtual void SetInnerHashSize(const byte value) = 0;

	virtual UInt32 GetLeafSize() const = 0;
	virtual void SetLeafSize(const UInt32 value) = 0;

	virtual UInt64 GetNodeOffset() const = 0;
	virtual void SetNodeOffset(const UInt64 value) = 0;

	virtual bool GetIsLastNode() const = 0;
	virtual void SetIsLastNode(const bool value) = 0;

	virtual IBlake2BTreeConfig Clone() const = 0;

}; // end class IBlake2BTreeConfig
