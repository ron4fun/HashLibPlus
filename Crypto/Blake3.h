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

#include "../Params/Blake2BParams.h"
#include "../Params/Blake2XBParams.h"
#include "../Interfaces/IHashInfo.h"
#include "../Enum/HashSize.h"
#include "../Base/Hash.h"
#include "../Base/HashBuffer.h"
#include "../Base/HashResult.h"
#include "../Utils/Converters.h"
#include "../Utils/BitConverter.h"
#include "../Utils/HashLibTypes.h"
#include "../Utils/Utils.h"
#include "../Utils/ArrayUtils.h"

class Blake3 : public Hash, public virtual IICryptoNotBuildIn, public virtual IITransformBlock
{
protected:
	// A Blake3Node represents a chunk or parent in the BLAKE3 Merkle tree. In BLAKE3
	// terminology, the elements of the bottom layer (aka "leaves") of the tree are
	// called chunk nodes, and the elements of upper layers (aka "interior nodes")
	// are called parent nodes.
	//
	// Computing a BLAKE3 hash involves splitting the input into chunk nodes, then
	// repeatedly merging these nodes into parent nodes, until only a single "root"
	// node remains. The root node can then be used to generate up to 2^64 - 1 bytes
	// of pseudorandom output.
	class Blake3Node
	{
	public:
		// the chaining value from the previous state
		HashLibUInt32Array CV;

		// the current state
		HashLibUInt32Array Block;
		UInt64 Counter;
		UInt32 BlockLen, Flags;

	public:
		Blake3Node()
		{
			CV.resize(8);
			Block.resize(16);
			Counter = 0;
			BlockLen = 0;
			Flags = 0;
		}

		Blake3Node(const Blake3Node& a_value)
		{
			CV = a_value.CV;
			Block = a_value.Block;
			Counter = a_value.Counter;
			BlockLen = a_value.BlockLen;
			Flags = a_value.Flags;
		}
		
		// ChainingValue returns the first 8 words of the compressed node. This is used
		// in two places. First, when a chunk node is being constructed, its cv is
		// overwritten with this value after each block of input is processed. Second,
		// when two nodes are merged into a parent, each of their chaining values
		// supplies half of the new node's block.
		inline void ChainingValue(HashLibUInt32Array& result)
		{
			HashLibUInt32Array full = HashLibUInt32Array(16);
			Compress(full);
			memmove(&result[0], &full[0], 8 * sizeof(UInt32));
		}

		// compress is the core hash function, generating 16 pseudorandom words from a
		// node.
		// NOTE: we unroll all of the rounds, as well as the permutations that occur
		// between rounds.
		void Compress(HashLibUInt32Array& state)
		{
			// initializes state here
			state[0] = CV[0];
			state[1] = CV[1];
			state[2] = CV[2];
			state[3] = CV[3];
			state[4] = CV[4];
			state[5] = CV[5];
			state[6] = CV[6];
			state[7] = CV[7];
			state[8] = IV[0];
			state[9] = IV[1];
			state[10] = IV[2];
			state[11] = IV[3];
			state[12] = (UInt32)Counter;
			state[13] = (UInt32)(Counter >> 32);
			state[14] = BlockLen;
			state[15] = Flags;

			// NOTE: we unroll all of the rounds, as well as the permutations that occur
			// between rounds.
			// Round 0
			// Mix the columns.
			G(state, 0, 4, 8, 12, Block[0], Block[1]);
			G(state, 1, 5, 9, 13, Block[2], Block[3]);
			G(state, 2, 6, 10, 14, Block[4], Block[5]);
			G(state, 3, 7, 11, 15, Block[6], Block[7]);

			// Mix the rows.
			G(state, 0, 5, 10, 15, Block[8], Block[9]);
			G(state, 1, 6, 11, 12, Block[10], Block[11]);
			G(state, 2, 7, 8, 13, Block[12], Block[13]);
			G(state, 3, 4, 9, 14, Block[14], Block[15]);

			// Round 1
			// Mix the columns.
			G(state, 0, 4, 8, 12, Block[2], Block[6]);
			G(state, 1, 5, 9, 13, Block[3], Block[10]);
			G(state, 2, 6, 10, 14, Block[7], Block[0]);
			G(state, 3, 7, 11, 15, Block[4], Block[13]);

			// Mix the rows.
			G(state, 0, 5, 10, 15, Block[1], Block[11]);
			G(state, 1, 6, 11, 12, Block[12], Block[5]);
			G(state, 2, 7, 8, 13, Block[9], Block[14]);
			G(state, 3, 4, 9, 14, Block[15], Block[8]);

			// Round 2
			// Mix the columns.
			G(state, 0, 4, 8, 12, Block[3], Block[4]);
			G(state, 1, 5, 9, 13, Block[10], Block[12]);
			G(state, 2, 6, 10, 14, Block[13], Block[2]);
			G(state, 3, 7, 11, 15, Block[7], Block[14]);

			// Mix the rows.
			G(state, 0, 5, 10, 15, Block[6], Block[5]);
			G(state, 1, 6, 11, 12, Block[9], Block[0]);
			G(state, 2, 7, 8, 13, Block[11], Block[15]);
			G(state, 3, 4, 9, 14, Block[8], Block[1]);

			// Round 3
			// Mix the columns.
			G(state, 0, 4, 8, 12, Block[10], Block[7]);
			G(state, 1, 5, 9, 13, Block[12], Block[9]);
			G(state, 2, 6, 10, 14, Block[14], Block[3]);
			G(state, 3, 7, 11, 15, Block[13], Block[15]);

			// Mix the rows.
			G(state, 0, 5, 10, 15, Block[4], Block[0]);
			G(state, 1, 6, 11, 12, Block[11], Block[2]);
			G(state, 2, 7, 8, 13, Block[5], Block[8]);
			G(state, 3, 4, 9, 14, Block[1], Block[6]);

			// Round 4
			// Mix the columns.
			G(state, 0, 4, 8, 12, Block[12], Block[13]);
			G(state, 1, 5, 9, 13, Block[9], Block[11]);
			G(state, 2, 6, 10, 14, Block[15], Block[10]);
			G(state, 3, 7, 11, 15, Block[14], Block[8]);

			// Mix the rows.
			G(state, 0, 5, 10, 15, Block[7], Block[2]);
			G(state, 1, 6, 11, 12, Block[5], Block[3]);
			G(state, 2, 7, 8, 13, Block[0], Block[1]);
			G(state, 3, 4, 9, 14, Block[6], Block[4]);

			// Round 5
			// Mix the columns.
			G(state, 0, 4, 8, 12, Block[9], Block[14]);
			G(state, 1, 5, 9, 13, Block[11], Block[5]);
			G(state, 2, 6, 10, 14, Block[8], Block[12]);
			G(state, 3, 7, 11, 15, Block[15], Block[1]);

			// Mix the rows.
			G(state, 0, 5, 10, 15, Block[13], Block[3]);
			G(state, 1, 6, 11, 12, Block[0], Block[10]);
			G(state, 2, 7, 8, 13, Block[2], Block[6]);
			G(state, 3, 4, 9, 14, Block[4], Block[7]);

			// Round 6
			// Mix the columns.
			G(state, 0, 4, 8, 12, Block[11], Block[15]);
			G(state, 1, 5, 9, 13, Block[5], Block[0]);
			G(state, 2, 6, 10, 14, Block[1], Block[9]);
			G(state, 3, 7, 11, 15, Block[8], Block[6]);

			// Mix the rows.
			G(state, 0, 5, 10, 15, Block[14], Block[10]);
			G(state, 1, 6, 11, 12, Block[2], Block[12]);
			G(state, 2, 7, 8, 13, Block[3], Block[4]);
			G(state, 3, 4, 9, 14, Block[7], Block[13]);

			// compression finalization

			state[0] = state[0] ^ state[8];
			state[1] = state[1] ^ state[9];
			state[2] = state[2] ^ state[10];
			state[3] = state[3] ^ state[11];
			state[4] = state[4] ^ state[12];
			state[5] = state[5] ^ state[13];
			state[6] = state[6] ^ state[14];
			state[7] = state[7] ^ state[15];
			state[8] = state[8] ^ CV[0];
			state[9] = state[9] ^ CV[1];
			state[10] = state[10] ^ CV[2];
			state[11] = state[11] ^ CV[3];
			state[12] = state[12] ^ CV[4];
			state[13] = state[13] ^ CV[5];
			state[14] = state[14] ^ CV[6];
			state[15] = state[15] ^ CV[7];
		}

		private:
			inline static void G(HashLibUInt32Array& state, const UInt32 a, const UInt32 b,
				const UInt32 c, const UInt32 d, const UInt32 x, const UInt32 y)
			{
				UInt32 aa = state[a];
				UInt32 bb = state[b];
				UInt32 cc = state[c];
				UInt32 dd = state[d];

				aa = aa + bb + x;
				dd = Bits::RotateRight32(dd ^ aa, 16);
				cc += dd;
				bb = Bits::RotateRight32(bb ^ cc, 12);
				aa = aa + bb + y;
				dd = Bits::RotateRight32(dd ^ aa, 8);
				cc += dd;
				bb = Bits::RotateRight32(bb ^ cc, 7);

				state[a] = aa;
				state[b] = bb;
				state[c] = cc;
				state[d] = dd;
			}

			inline static Blake3Node CreateBlake3Node(const HashLibUInt32Array& cv, 
				const HashLibUInt32Array& block, const UInt64 counter, const UInt32 blockLen, 
				const UInt32 flags)
			{
				Blake3Node result = Blake3Node();	
				result.CV = cv;
				result.Block = block;
				result.Counter = counter;
				result.BlockLen = blockLen;
				result.Flags = flags;
				return result;
			}

		public:
			inline static Blake3Node ParentNode(const HashLibUInt32Array& left,
				const HashLibUInt32Array& right, const HashLibUInt32Array& key, const UInt32 flags)
			{
				return CreateBlake3Node(key, Utils::concat(left, right), 0, BlockSizeInBytes, flags | flagParent);
			} //

			static Blake3Node DefaultBlake3Node()
			{
				return Blake3Node();
			} //
	};

	// Blake3ChunkState manages the state involved in hashing a single chunk of input.
	class Blake3ChunkState
	{
	private:
		Blake3Node _n;
		HashLibByteArray _block;
		Int32 _blockLen;

	public:
		Int32 BytesConsumed;

	public:
		Blake3ChunkState()
		{
			_n = Blake3Node::DefaultBlake3Node();
			_block.resize(BlockSizeInBytes);
			_blockLen = 0;
			BytesConsumed = 0;
		}
		
		Blake3ChunkState(const Blake3ChunkState& a_value)
		{
			_n = a_value._n;
			_block = a_value._block;
			_blockLen = a_value._blockLen;
			BytesConsumed = a_value.BytesConsumed;
		} //

		// ChunkCounter is the index of this chunk, i.e. the number of chunks that have
		// been processed prior to this one.
		inline UInt64 ChunkCounter() const
		{
			return _n.Counter;
		} //

		inline bool Complete() const
		{
			return BytesConsumed == ChunkSize;
		} //

		// node returns a node containing the chunkState's current state, with the
		// ChunkEnd flag set.
		Blake3Node Node()
		{
			Blake3Node result = _n;

			// pad the remaining space in the block with zeros
			memset(&_block[0] + _blockLen, 0, _block.size() - _blockLen);
			Converters::le32_copy(&_block[0], 0, &result.Block[0], 0, BlockSizeInBytes);

			result.BlockLen = (UInt32)_blockLen;
			result.Flags |= flagChunkEnd;

			return result;
		}

		// update incorporates input into the chunkState.
		void Update(const byte* dataPtr, Int32 dataLength)
		{
			Int32 index = 0;

			while (dataLength > 0)
			{
				// If the block buffer is full, compress it and clear it. More
				// input is coming, so this compression is not flagChunkEnd.
				if (_blockLen == BlockSizeInBytes)
				{
					// copy the chunk block (bytes) into the node block and chain it.
					Converters::le32_copy(&_block[0], 0, &_n.Block[0], 0,
						BlockSizeInBytes);
					_n.ChainingValue(_n.CV);
					// clear the start flag for all but the first block
					_n.Flags &= _n.Flags ^ flagChunkStart;
					_blockLen = 0;
				}

				// Copy input bytes into the chunk block.
				Int32 count = min(BlockSizeInBytes - _blockLen, dataLength);
				memmove(&_block[0] + _blockLen, dataPtr + index, count);

				_blockLen += count;
				BytesConsumed += count;
				index += count;
				dataLength -= count;
			}

		}

		inline static Blake3ChunkState CreateBlake3ChunkState(const HashLibUInt32Array& iv,
			const UInt64 chunkCounter, const UInt32 flags)
		{
			Blake3ChunkState result = Blake3ChunkState();
			result._n.CV = iv;
			//
			result._n.Counter = chunkCounter;
			result._n.BlockLen = BlockSizeInBytes;
			// compress the first block with the start flag set
			result._n.Flags = flags | flagChunkStart;

			return result;
		} //

	}; //

	class Blake3OutputReader
	{
	private:
		HashLibByteArray _block;
	
	public:
		Blake3Node N;
		UInt64 Offset;

	public:
		Blake3OutputReader()
		{
			N = Blake3Node::DefaultBlake3Node();
			_block.resize(BlockSizeInBytes);
			Offset = 0;
		}

		Blake3OutputReader(const Blake3OutputReader& a_value)
		{
			N = a_value.N;
			_block = a_value._block;
			Offset = a_value.Offset;
		} //

		void Read(HashLibByteArray& dest, UInt64 destOffset, UInt64 outputLength)
		{
			HashLibUInt32Array words = HashLibUInt32Array(16);

			if (Offset == MaxDigestLengthInBytes)
				throw ArgumentOutOfRangeHashLibException(MaximumOutputLengthExceeded);

			UInt64 remainder = MaxDigestLengthInBytes - Offset;
			UInt64 OutputLength = min(outputLength, remainder);

			while (outputLength > 0)
			{
				if ((Offset & (BlockSizeInBytes - 1)) == 0)
				{
					N.Counter = Offset / BlockSizeInBytes;
					N.Compress(words);
					Converters::le32_copy(&words[0], 0, &_block[0], 0, BlockSizeInBytes);
				}

				UInt64 blockOffset = Offset & (BlockSizeInBytes - 1);

				UInt64 diff = (UInt64)_block.size() - blockOffset;

				Int32 count = (Int32)min(outputLength, diff);

				memmove(&dest[0] + destOffset, &_block[0] + blockOffset, count);

				outputLength -= (UInt64)count;
				destOffset += (UInt64)count;
				Offset += (UInt64)count;
			}
		}

		static Blake3OutputReader DefaultBlake3OutputReader()
		{
			return Blake3OutputReader();
		} //
	};

private:
	Blake3Node RootNode()
	{
		Blake3Node result = ChunkState.Node();
		HashLibUInt32Array temp = HashLibUInt32Array(8);

		Int32 trailingZeros64 = TrailingZeros64(Used);
		Int32 len64 = Len64(Used);

		
		Int32 idx;
		for (idx = trailingZeros64; idx < len64; idx++)
		{
			if (!HasSubTreeAtHeight(idx)) continue;
			result.ChainingValue(temp);
			result = Blake3Node::ParentNode(Stack[idx], temp, Key, Flags);
		}
		
		result.Flags |= flagRoot;

		return result;
	}

	static HashLibUInt32Array InternalSetup(const HashLibByteArray& key)
	{
		if (key.empty()) return IV;

		Int32 keyLength = (Int32)key.size();
		HashLibUInt32Array result = HashLibUInt32Array(8);

		if (keyLength != KeyLengthInBytes)
			throw ArgumentOutOfRangeHashLibException(
				Utils::string_format(InvalidKeyLength, KeyLengthInBytes, keyLength));


		Converters::le32_copy(&key[0], 0, &result[0], 0, keyLength);

		return result;
	}

	inline bool HasSubTreeAtHeight(const UInt32 idx)
	{
		return (Used & ((size_t)1 << idx)) != 0;
	} //

	// AddChunkChainingValue appends a chunk to the right edge of the Merkle tree.
	void AddChunkChainingValue(HashLibUInt32Array& cv)
	{
		// seek to first open stack slot, merging subtrees as we go
		Int32 idx = 0;
		
		while (HasSubTreeAtHeight(idx))
		{
			Blake3Node::ParentNode(Stack[idx], cv, Key, Flags).ChainingValue(cv);
			idx++;
		}		

		Stack[idx] = cv;
		Used++;
	}

	inline static byte Len8(byte value)
	{
		byte result = 0;
		while (value != 0)
		{
			value = (byte)(value >> 1);
			result++;
		}

		return result;
	}

	// Len64 returns the minimum number of bits required to represent x; the result is 0 for x == 0.
	inline static Int32 Len64(UInt64 value)
	{
		Int32 result = 0;
		if (value >= 1)
		{
			value >>= 32;
			result = 32;
		}

		if (value >= 1 << 16)
		{
			value >>= 16;
			result += 16;
		}

		if (value < 1 << 8) return result + Len8((byte)value);
		value >>= 8;
		result += 8;

		return result + Len8((byte)value);
	}

	inline static Int32 TrailingZeros64(UInt64 value)
	{
		if (value == 0) return 64;

		Int32 result = 0;
		while ((value & 1) == 0)
		{
			value >>= 1;
			result++;
		}

		return result;
	}

protected:
	inline void InternalDoOutput(HashLibByteArray& dest, const UInt64 destOffset, const UInt64 outputLength)
	{
		OutputReader.Read(dest, destOffset, outputLength);
	}

	inline void Finish()
	{
		OutputReader.N = RootNode();
	} //

public:
	Blake3() {}

	Blake3(const Int32 hashSize, const HashLibByteArray& key) 
		: Blake3(hashSize, InternalSetup(key), key.empty() ? 0 : flagKeyedHash)
	{} // cctr

	Blake3(const Int32 hashSize, const HashLibUInt32Array& keyWords, const UInt32 flags)
		: Hash(hashSize, BlockSizeInBytes)
	{
		_name = __func__;

		Key = keyWords;
		Flags = flags;

		Stack.resize(54);
		for (UInt32 idx = 0; idx < (UInt32)Stack.size(); idx++)
			Stack[idx].resize(8);
	} // cctr

	Blake3(const HashSize& hashSize, const HashLibByteArray& key)
		: Blake3((Int32)hashSize, key)
	{} // cctr

	Blake3(const Blake3& a_hash)
	{
		_name = a_hash.GetName();

		// Blake3 Cloning
		ChunkState = a_hash.ChunkState;
		OutputReader = a_hash.OutputReader;
		Stack = a_hash.Stack;
		Used = a_hash.Used;
		Flags = a_hash.Flags;
		Key = a_hash.Key;

		_block_size = a_hash._block_size;
		_hash_size = a_hash._hash_size;
		_buffer_size = a_hash._buffer_size;
	}

	virtual void Initialize()
	{
		ChunkState = Blake3ChunkState::CreateBlake3ChunkState(Key, 0, Flags);
		OutputReader = Blake3OutputReader::DefaultBlake3OutputReader();
		
		for (UInt32 idx = 0; idx < (UInt32)Stack.size(); idx++)
			ArrayUtils::zeroFill(Stack[idx]);

		Used = 0;
	}

	virtual void TransformBytes(const HashLibByteArray& a_data, const Int32 a_index, const Int32 a_data_length)
	{
		HashLibUInt32Array chainingValue = HashLibUInt32Array(8);
		Int32 length = a_data_length;

		if (a_data.empty()) return;

		const byte* dataPtr2 = &a_data[0] + a_index;

		while (length > 0)
		{
			// If the current chunk is complete, finalize it and add it to the tree,
			// then reset the chunk state (but keep incrementing the counter across
			// chunks).
			if (ChunkState.Complete())
			{
				ChunkState.Node().ChainingValue(chainingValue);
				AddChunkChainingValue(chainingValue);
				ChunkState =
					Blake3ChunkState::CreateBlake3ChunkState(Key, ChunkState.ChunkCounter() + 1, Flags);
			}

			// Compress input bytes into the current chunk state.
			Int32 count = min(ChunkSize - ChunkState.BytesConsumed, length);
			ChunkState.Update(dataPtr2, count);

			dataPtr2 += count;
			length -= count;
		}
	}

	virtual IHashResult TransformFinal()
	{
		HashLibByteArray tempRes;

		Finish();

		tempRes.resize(GetHashSize());

		InternalDoOutput(tempRes, 0, (UInt64)tempRes.size());

		IHashResult result = make_shared<HashResult>(tempRes);

		Initialize();

		return result;
	}

	virtual string GetName() const
	{
		return Utils::string_format("%s_%u", _name.c_str(), GetHashSize() * 8);
	}

	virtual IHash Clone() const
	{
		Blake3 result = Blake3(GetHashSize(), Key, Flags);
		result.ChunkState = ChunkState;
		result.OutputReader = OutputReader;
		result.Stack =Stack;
		result.Used = Used;
		result.SetBufferSize(GetBufferSize());

		return make_shared<Blake3>(result);
	}

	// maximum size in bytes this digest output reader can produce
	static const UInt64 MaxDigestLengthInBytes = UINT32_MAX;

	static const Int32 KeyLengthInBytes = 32;

	static const HashLibUInt32Array IV;

private:
	static const char* MaximumOutputLengthExceeded;
	static const char* InvalidKeyLength;

	static const Int32 ChunkSize = 1024;
	static const Int32 BlockSizeInBytes = 64;

	static const UInt32 flagChunkStart = 1 << 0;
	static const UInt32 flagChunkEnd = 1 << 1;
	static const UInt32 flagParent = 1 << 2;
	static const UInt32 flagRoot = 1 << 3;
	static const UInt32 flagKeyedHash = 1 << 4;

protected:
	Blake3ChunkState ChunkState;
	Blake3OutputReader OutputReader;
	HashLibUInt32Array Key;
	UInt32 Flags;

	// log(n) set of Merkle subtree roots, at most one per height.
	// stack [54][8]uint32
	HashLibMatrixUInt32Array Stack; // 2^54 * chunkSize = 2^64

	// bit vector indicating which stack elems are valid; also number of chunks added
	UInt64 Used;

}; // end class Blake3

const char* Blake3::MaximumOutputLengthExceeded = "Maximum output length is 2^64 bytes";
const char* Blake3::InvalidKeyLength = "Key length must not be greater than {%u}, '{%u}'";

const HashLibUInt32Array Blake3::IV =
{
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

class Blake3XOF : public Blake3, public virtual IIXOF
{
private:
	static const char* InvalidXofSize;
	static const char* InvalidOutputLength;
	static const char* OutputBufferTooShort;
	static const char* WriteToXofAfterReadError;

	bool _finalized;
	UInt64 _xofSizeInBits;

public:
	virtual UInt64 GetXOFSizeInBits() const
	{
		return _xofSizeInBits;
	}

	virtual void SetXOFSizeInBits(const UInt64 value)
	{
		SetXOFSizeInBitsInternal(value);
	}
	
	Blake3XOF(const Int32 hashSize, const HashLibByteArray& key)
		: Blake3(hashSize, key)
	{
		_name = __func__;
	}

	Blake3XOF(const Int32 hashSize, const HashLibUInt32Array& keyWords, const UInt32 flags)
		: Blake3(hashSize, keyWords, flags)
	{
		_name = __func__;
	}

	Blake3XOF(const Blake3XOF& a_hash)
	{		
		_name = a_hash.GetName();
		
		// Blake3 Cloning
		ChunkState = a_hash.ChunkState;
		OutputReader = a_hash.OutputReader;
		Stack = a_hash.Stack;
		Used = a_hash.Used;
		Flags = a_hash.Flags;
		Key = a_hash.Key;

		_block_size = a_hash._block_size;
		_hash_size = a_hash._hash_size;
		_buffer_size = a_hash._buffer_size;
	
		// Blake3XOF Cloning
		_finalized = a_hash._finalized;
		_xofSizeInBits = a_hash._xofSizeInBits;
	}

	virtual string GetName() const
	{
		return _name;
	}

	virtual void Initialize()
	{
		_finalized = false;
		Blake3::Initialize();
	} //
	Blake3XOF Copy() const
	{
		Blake3XOF result = Blake3XOF(GetHashSize(), {});
		// Blake3 Cloning
		result.ChunkState = ChunkState;
		result.OutputReader = OutputReader;
		result.Stack = Stack;
		result.Used = Used;
		result.Flags = Flags;
		result.Key = Key;

		result.SetBufferSize(GetBufferSize());

		// Blake3XOF Cloning
		result._finalized = _finalized;
		// Xof Cloning
		result._xofSizeInBits = _xofSizeInBits;

		return result;
	} //

	virtual IHash Clone() const
	{		
		return make_shared<Blake3XOF>(*this);
	}

	virtual IXOF CloneXOF() const
	{
		return make_shared<Blake3XOF>(*this);
	}
	
	virtual void TransformBytes(const HashLibByteArray& a_data, const Int32 a_index, const Int32 a_length)
	{
		if (_finalized)
			throw InvalidOperationHashLibException(
				Utils::string_format(WriteToXofAfterReadError, GetName().c_str()));

		Blake3::TransformBytes(a_data, a_index, a_length);
	} //

	virtual IHashResult TransformFinal()
	{
		HashLibByteArray buffer = GetResult();

		Initialize();

		IHashResult result = make_shared<HashResult>(buffer);

		return result;
	}

	virtual void DoOutput(HashLibByteArray& a_destination, const UInt64 a_destinationOffset,
		const UInt64 a_outputLength)
	{
		if ((UInt64)a_destination.size() - a_destinationOffset < a_outputLength)
			throw ArgumentOutOfRangeHashLibException(OutputBufferTooShort);

		if (OutputReader.Offset + a_outputLength > GetXOFSizeInBits() >> 3)
			throw ArgumentOutOfRangeHashLibException(InvalidOutputLength);

		if (!_finalized)
		{
			Finish();
			_finalized = true;
		}

		InternalDoOutput(a_destination, a_destinationOffset, a_outputLength);
	} //

private:
	void SetXOFSizeInBitsInternal(const UInt64 xofSizeInBits)
	{
		UInt64 xofSizeInBytes = xofSizeInBits >> 3;

		if ((xofSizeInBits & 0x7) != 0 || xofSizeInBytes < 1)
			throw ArgumentOutOfRangeHashLibException(InvalidXofSize);

		_xofSizeInBits = xofSizeInBits;
	} //

	HashLibByteArray GetResult()
	{
		UInt64 xofSizeInBytes = GetXOFSizeInBits() >> 3;

		HashLibByteArray result = HashLibByteArray(xofSizeInBytes);

		DoOutput(result, 0, xofSizeInBytes);

		return result;
	} //

}; //

const char* Blake3XOF::InvalidXofSize = "XOFSizeInBits must be multiples of 8 and be greater than zero bytes";
const char* Blake3XOF::InvalidOutputLength = "Output length is above the digest length";
const char* Blake3XOF::OutputBufferTooShort = "Output buffer too short";
const char* Blake3XOF::WriteToXofAfterReadError = "\"{%s}\" write to Xof after read not allowed";
