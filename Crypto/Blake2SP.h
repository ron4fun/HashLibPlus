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

#include "Blake2S.h"

class Blake2SP : public Hash, public virtual IICryptoNotBuildIn, public virtual IITransformBlock
{
private:
	struct DataContainer
	{
		byte* PtrData;
		UInt64 Counter;
	}; // end struct DataContainer

public:
	Blake2SP(const Int32 a_HashSize, const HashLibByteArray &a_Key)
		: Hash(a_HashSize, BlockSizeInBytes)
	{
		_buffer.resize(ParallelismDegree * BlockSizeInBytes);
		_leafHashes.resize(ParallelismDegree);
		
		_key = a_Key;
		_rootHash = Blake2SPCreateRoot();

		for (Int32 i = 0; i < ParallelismDegree; i++)
			_leafHashes[i] = Blake2SPCreateLeaf(i);

	}

	~Blake2SP()
	{
		Clear();
	}

	virtual IHash Clone() const
	{
		Blake2SP HashInstance = Blake2SP(GetHashSize());
		HashInstance._key = _key;

		HashInstance._rootHash = _rootHash;
		
		HashInstance._leafHashes = _leafHashes;
		HashInstance._buffer = _buffer;
		HashInstance._bufferLength = _bufferLength;
	
		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<Blake2SP>(HashInstance);
	}

	virtual void Initialize()
	{
		_rootHash.Initialize();
		for (Int32 i = 0; i < ParallelismDegree; i++)
		{
			_leafHashes[i].Initialize();
			_leafHashes[i].SetHashSize(OutSizeInBytes);
		}
		
		ArrayUtils::zeroFill(_buffer);
		_bufferLength = 0;
	}

	virtual void TransformBytes(const HashLibByteArray& a_data, const Int32 a_index, const Int32 a_data_length)
	{
		UInt64 left, fill, dataLength;
		const byte* ptrData;
		Int32 i;
		DataContainer ptrDataContainer = DataContainer();
		
		if (a_data.empty()) return;

		dataLength = UInt64(a_data_length);
		ptrData = (const byte*)(&a_data[0]) + a_index;
		left = _bufferLength;
		fill = UInt64(_buffer.size()) - left;

		if ((left > 0) && (dataLength >= fill))
		{
			memmove(&_buffer[left], ptrData, fill);

			for (i = 0; i < ParallelismDegree; i++)
			{
				_leafHashes[i].TransformBytes(_buffer, i * BlockSizeInBytes, BlockSizeInBytes);
			}

			ptrData += fill;
			dataLength = dataLength - fill;
			left = 0;
		}

		try
		{
			ptrDataContainer.PtrData = (byte*)(ptrData);
			ptrDataContainer.Counter = dataLength;
			DoParallelComputation(ptrDataContainer);
		}
		catch (exception&) {}

		ptrData += (dataLength - (dataLength % UInt64(ParallelismDegree *
			BlockSizeInBytes)));
		dataLength = dataLength % UInt64(ParallelismDegree * BlockSizeInBytes);

		if (dataLength > 0) 
			memmove(&_buffer[left], ptrData, dataLength);
	
		_bufferLength = size_t(left) + UInt32(dataLength);
	}

	virtual IHashResult TransformFinal()
	{
		Int32 i;
		UInt64 left;
		
		HashLibMatrixByteArray _hash = HashLibMatrixByteArray(ParallelismDegree);
		
		for (i = 0; i < _hash.size(); i++)
		{
			_hash[i].resize(OutSizeInBytes);
		}

		for (i = 0; i < ParallelismDegree; i++)
		{
			if (_bufferLength > ((size_t)i * BlockSizeInBytes))
			{
				left = _bufferLength - UInt64((size_t)i * BlockSizeInBytes);
				if (left > BlockSizeInBytes) 
					left = BlockSizeInBytes;

				_leafHashes[i].TransformBytes(_buffer, i * BlockSizeInBytes, Int32(left));
			}

			_hash[i] = _leafHashes[i].TransformFinal()->GetBytes();
		}

		for (i = 0; i < ParallelismDegree; i++)
			_rootHash.TransformBytes(_hash[i], 0, OutSizeInBytes);

		IHashResult result = _rootHash.TransformFinal();

		Initialize();
		
		return result;
	}

	virtual string GetName() const
	{
		return Utils::string_format("Blake2SP_%u", GetHashSize() * 8);
	}

private:
	Blake2SP(const Int32 a_HashSize)
		: Hash(a_HashSize, BlockSizeInBytes)
	{}

	/// <summary>
	/// <br />Blake2S defaults to setting the expected output length <br />
	/// from the <c>HashSize</c> in the <c>Blake2SConfig</c> class. <br />In
	/// some cases, however, we do not want this, as the output length <br />
	/// of these instances is given by <c>Blake2STreeConfig.InnerSize</c>
	/// instead. <br />
	/// </summary>
	Blake2S Blake2SPCreateLeafParam(const IBlake2SConfig a_Blake2SConfig, const IBlake2STreeConfig a_Blake2STreeConfig) const
	{
		return Blake2S(a_Blake2SConfig, a_Blake2STreeConfig);
	}

	Blake2S Blake2SPCreateLeaf(const UInt64 a_Offset) const
	{
		IBlake2SConfig blake2SConfig = make_shared<Blake2SConfig>(GetHashSize());
		blake2SConfig->SetKey(_key);

		IBlake2STreeConfig blake2STreeConfig = make_shared<Blake2STreeConfig>();
		blake2STreeConfig->SetFanOut(ParallelismDegree);
		blake2STreeConfig->SetMaxDepth(2);
		blake2STreeConfig->SetNodeDepth(0);
		blake2STreeConfig->SetLeafSize(0);
		blake2STreeConfig->SetNodeOffset(a_Offset);
		blake2STreeConfig->SetInnerHashSize(OutSizeInBytes);

		if (a_Offset == (ParallelismDegree - 1))
			blake2STreeConfig->SetIsLastNode(true);

		return Blake2SPCreateLeafParam(blake2SConfig, blake2STreeConfig);
	}

	Blake2S Blake2SPCreateRoot() const
	{
		IBlake2SConfig blake2SConfig = make_shared<Blake2SConfig>(GetHashSize());
		blake2SConfig->SetKey(_key);

		IBlake2STreeConfig blake2STreeConfig = make_shared<Blake2STreeConfig>();
		blake2STreeConfig->SetFanOut(ParallelismDegree);
		blake2STreeConfig->SetMaxDepth(2);
		blake2STreeConfig->SetNodeDepth(1);
		blake2STreeConfig->SetLeafSize(0);
		blake2STreeConfig->SetNodeOffset(0);
		blake2STreeConfig->SetInnerHashSize(OutSizeInBytes);
		blake2STreeConfig->SetIsLastNode(true);

		return Blake2S(blake2SConfig, blake2STreeConfig, false);
	}

	void ParallelComputation(const Int32 Idx, const DataContainer &a_DataContainer)
	{
		HashLibByteArray temp = HashLibByteArray(BlockSizeInBytes);

		byte* ptrData = a_DataContainer.PtrData;
		UInt64 counter = a_DataContainer.Counter;

		ptrData += ((size_t)Idx * BlockSizeInBytes);

		while (counter >= (ParallelismDegree * BlockSizeInBytes))
		{
			memmove(&temp[0], ptrData, BlockSizeInBytes);

			_leafHashes[Idx].TransformBytes(temp, 0, BlockSizeInBytes);
			
			ptrData += (UInt64(ParallelismDegree * BlockSizeInBytes));
			counter = counter - UInt64(ParallelismDegree * BlockSizeInBytes);
		}
	}

	void DoParallelComputation(const DataContainer &a_DataContainer)
	{
		for (Int32 i = 0; i < ParallelismDegree; i++)
			ParallelComputation(i, a_DataContainer);
	}

	void Clear()
	{
		ArrayUtils::zeroFill(_key);
	}

private:
	// had to use the classes directly for performance purposes
	Blake2S _rootHash;
	HashLibGenericArray<Blake2S> _leafHashes;
	HashLibByteArray _buffer, _key;
	UInt64 _bufferLength = 0;

	static const Int32 BlockSizeInBytes = Int32(64);
	static const Int32 OutSizeInBytes = Int32(32);
	static const Int32 ParallelismDegree = Int32(8);

}; // end class Blake2SP
