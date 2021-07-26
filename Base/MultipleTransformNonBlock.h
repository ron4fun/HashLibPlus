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

#include "Hash.h"
#include "../Interfaces/IHashInfo.h"

class MultipleTransformNonBlock : public Hash, public virtual IINonBlockHash
{
public:
	MultipleTransformNonBlock(const Int32 a_hash_size, const Int32 a_block_size)
		: Hash(a_hash_size, a_block_size)
	{} // end constructor

	~MultipleTransformNonBlock()
	{
		_buffer.clear(); // reset buffer
	} // end destructor

	virtual void Initialize()
	{
		_buffer.clear(); // reset buffer
	} // end fucntion Initialize

	virtual void TransformBytes(const HashLibByteArray& a_data, const Int32 a_index, const Int32 a_length)
	{
		if (a_data.empty()) return;

		const HashLibByteArray::const_iterator start = a_data.begin() + a_index;
		const HashLibByteArray::const_iterator end = start + a_length;

		HashLibByteArray temp = HashLibByteArray(start, end);

		string data(start, end);
		_buffer += data;
	} // end function TransformBytes

	virtual IHashResult TransformFinal()
	{
		IHashResult result = ComputeAggregatedBytes(Aggregate());

		Initialize();

		return result;
	} // end function TransformFinal

	virtual IHashResult ComputeBytes(const HashLibByteArray& a_data)
	{
		Initialize();

		return ComputeAggregatedBytes(a_data);
	} // end function ComputeBytes

protected:
	MultipleTransformNonBlock() {}

	virtual IHashResult ComputeAggregatedBytes(const HashLibByteArray& a_data) = 0;

private:
	HashLibByteArray Aggregate()
	{
		UInt32 sum = 0, index = 0;

		string result = _buffer;
		if (result.size() > 0)
			return HashLibByteArray(result.begin(), result.end());

		return HashLibByteArray();
	} // end function Aggregate

protected:
	string _buffer; // string stream

}; // end class MultipleTransformNonBlock
