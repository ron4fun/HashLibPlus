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

#include "../Base/Hash.h"
#include "../Interfaces/IHashInfo.h"

using namespace std;

class NullDigest : public Hash, public virtual IITransformBlock
{
public:
	NullDigest()
		: Hash(-1, -1) // Dummy _state
	{
		_name = __func__;

		_out = stringstream();
	} // end constructor

	NullDigest(const NullDigest& value)
	{
		_out.flush();
		_out << value._out.str();

		SetBufferSize(value.GetBufferSize());
	}

	~NullDigest()
	{
		_out.flush();
	}

	virtual Int32 GetBlockSize() const
	{
		throw NotImplementedHashLibException(Utils::string_format(BlockSizeNotImplemented, GetName().c_str()));
	} // end property GetBlockSize

	virtual Int32 GetHashSize() const
	{
		throw NotImplementedHashLibException(Utils::string_format(HashSizeNotImplemented, GetName().c_str()));
	} // end property GetHashSize

	virtual IHash Clone() const
	{
		NullDigest HashInstance = NullDigest();
		HashInstance._out << _out.str();

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<NullDigest>(HashInstance);
	}

	virtual void Initialize()
	{
		_out.flush();
		_out.str(string()); // Reset stream
	} // end function Initialize

	virtual IHashResult TransformFinal()
	{
		HashLibByteArray res;

		size_t size = (size_t)GetStreamSize(_out);

		res.resize(size);

		try
		{
			if (!res.empty()) _out.read((char*)&res[0], size);
		} 
		catch(exception&)
		{
			// empty
		} 
		
		Initialize();
				
		return make_shared<HashResult>(res);
	} // end function TransformFinal

	virtual void TransformBytes(const HashLibByteArray& a_data, const Int32 a_index, const Int32 a_length)
	{
		if (!a_data.empty())
		{
			const HashLibByteArray::const_iterator start = a_data.begin() + a_index;
			const HashLibByteArray::const_iterator end = start + a_length;

			_out << string(start, end);
		}
	} // end function TransformBytes

private:
	static streampos GetStreamSize(stringstream& a_stream)
	{
		streampos pos = a_stream.tellg();

		streampos fsize = pos;
		a_stream.seekg(pos, ios::end);
		fsize = a_stream.tellg() - fsize;

		a_stream.seekg(pos, ios::beg); // return cur to original pos

		return fsize;
	} // end function GetStreamSize

private:
	stringstream _out;

	static const char* HashSizeNotImplemented;
	static const char* BlockSizeNotImplemented;

}; // end class NullDigest

const char* NullDigest::HashSizeNotImplemented = "HashSize not implemented for \"%s\"";
const char* NullDigest::BlockSizeNotImplemented = "BlockSize not implemented for \"%s\"";
