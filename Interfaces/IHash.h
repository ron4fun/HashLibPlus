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
#include <fstream>
#include "IHashResult.h"
#include "../Utils/HashLibTypes.h"

using namespace std;

class IIHash;

typedef shared_ptr<IIHash> IHash;

class IIHash
{
	friend ostream& operator<<(ostream& output, const IHash& _hash)
	{
		output << _hash->GetName();
		return output;
	}

public:
	virtual string GetName() const = 0;
	virtual Int32 GetBlockSize() const = 0;
	virtual Int32 GetHashSize() const = 0;
	virtual Int32 GetBufferSize() const = 0;
	virtual void SetBufferSize(const Int32 value) = 0;

	virtual IHash Clone() const = 0;

	virtual IHashResult ComputeString(const string& a_data) = 0;
	virtual IHashResult ComputeBytes(const HashLibByteArray& a_data) = 0;
	virtual IHashResult ComputeUntyped(const void* a_data, const Int64 a_length) = 0;
	virtual IHashResult ComputeStream(ifstream& a_stream, const Int64 a_length = -1) = 0;
	virtual IHashResult ComputeFile(const string& a_file_name,
		const Int64 a_from = 0, const Int64 a_length = -1) = 0;

	virtual void Initialize() = 0;

	virtual void TransformBytes(const HashLibByteArray& a_data, const Int32 a_index, const Int32 a_length) = 0;
	virtual void TransformBytes(const HashLibByteArray& a_data, const Int32 a_index) = 0;
	virtual void TransformBytes(const HashLibByteArray& a_data) = 0;

	virtual void TransformUntyped(const void* a_data, const Int64 a_length) = 0;

	virtual IHashResult TransformFinal() = 0;

	virtual void TransformString(const string& a_data) = 0;
	virtual void TransformStream(ifstream& a_stream, const Int64 a_length = -1) = 0;
	virtual void TransformFile(const string& a_file_name,
		const Int64 a_from = 0, const Int64 a_length = -1) = 0;

}; // end class IHash
