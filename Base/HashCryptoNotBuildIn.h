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
#include "HashBuffer.h"
#include "../Interfaces/IHashInfo.h"

class BlockHash : public Hash, public virtual IIBlockHash
{
protected:
	BlockHash() {}

public:
	BlockHash(const Int32 a_hash_size, const Int32 a_block_size,
		Int32 a_buffer_size = -1)
		: Hash(a_hash_size, a_block_size)
	{
		if (a_buffer_size == -1)
			a_buffer_size = a_block_size;

		_buffer = HashBuffer(a_buffer_size);
	} // end constructor

	BlockHash(const BlockHash& a_hash)
	{
		_buffer = a_hash._buffer.Clone();
		_processed_bytes = a_hash._processed_bytes;

		_name = a_hash._name;
		SetHashSize(a_hash.GetHashSize());
		SetBlockSize(a_hash.GetBlockSize());
		SetBufferSize(a_hash.GetBufferSize());
	}

	virtual void TransformBytes(const HashLibByteArray& a_data, Int32 a_index, Int32 a_length)
	{
		if (a_data.empty()) return;

		const byte* ptr_a_data = &a_data.front();

		if (!_buffer.GetIsEmpty())
		{
			if (_buffer.Feed(ptr_a_data, (Int32)a_data.size(), a_index, a_length, _processed_bytes))
				TransformBuffer();
		} // end if

		while (a_length >= _buffer.GetLength())
		{
			_processed_bytes = _processed_bytes + UInt64(_buffer.GetLength());
			TransformBlock(ptr_a_data, _buffer.GetLength(), a_index);
			a_index = a_index + _buffer.GetLength();
			a_length = a_length - _buffer.GetLength();
		} // end while

		if (a_length > 0)
			_buffer.Feed(ptr_a_data, (Int32)a_data.size(), a_index, a_length, _processed_bytes);

	} // end function TransformBytes

	virtual void Initialize()
	{
		_buffer.Initialize();
		_processed_bytes = 0;
	} // end function Initialize

	~BlockHash()
	{} // end destructor

	virtual IHashResult TransformFinal()
	{
		Finish();

		HashLibByteArray tempresult = GetResult();

		Initialize();

		return make_shared<HashResult>(tempresult);
	} // end function TransformFinal

private:
	inline void TransformBuffer()
	{
		TransformBlock(&_buffer.GetBytes()[0], _buffer.GetLength(), 0);
	} // end function TransformBuffer

	virtual void Finish() = 0;

	virtual void TransformBlock(const byte* a_data,
		const Int32 a_data_length, const Int32 a_index) = 0;

	virtual HashLibByteArray GetResult() = 0;

protected:
	HashBuffer _buffer;
	UInt64 _processed_bytes = 0;

}; // end class BlockHash
