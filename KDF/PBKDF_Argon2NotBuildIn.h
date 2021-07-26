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

#include "KDFNotBuildIn.h"
#include "../Utils/ArrayUtils.h"
#include "../Utils/Utils.h"
#include "../Interfaces/IHashInfo.h"
#include "../Crypto/Blake2B.h"
#include "../Params/Argon2Parameters.h"

/// <summary>
/// Argon2 PBKDF - Based on the results of https://octets-hashing.net/
/// and https://www.ietf.org/archive/id/draft-irtf-cfrg-argon2-03.txt
/// </summary>
class PBKDF_Argon2NotBuildInAdapter : public KDFNotBuildInAdapter,
	public virtual IIPBKDF_Argon2NotBuildIn
{
private:
	static const char * LanesTooSmall;
	static const char * LanesTooBig;
	static const char * MemoryTooSmall;
	static const char * IterationsTooSmall;
	static const char * InvalidOutputByteCount;

	static const Int32 ARGON2_BLOCK_SIZE = 1024;
	static const Int32 ARGON2_QWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 8;

	static const Int32 ARGON2_ADDRESSES_IN_BLOCK = 128;

	static const Int32 ARGON2_PREHASH_DIGEST_LENGTH = 64;
	static const Int32 ARGON2_PREHASH_SEED_LENGTH = 72;

	static const Int32 ARGON2_SYNC_POINTS = 4;

	// Minimum and maximum number of lanes (degree of parallelism)
	static const Int32 MIN_PARALLELISM = 1;

	static const Int32 MAX_PARALLELISM = 16777216;

	// Minimum digest size in bytes
	static const Int32 MIN_OUTLEN = 4;

	// Minimum and maximum number of passes
	static const Int32 MIN_ITERATIONS = 1;

	struct Position
	{
	public:
		Int32 Pass;
		Int32 Lane;
		Int32 Slice;
		Int32 Index;

		void Update(const Int32 pass, const Int32 lane, const Int32 slice, const Int32 index)
		{
			Pass = pass;
			Lane = lane;
			Slice = slice;
			Index = index;
		} //

		static Position DefaultPosition() { return Position(); }

		static Position CreatePosition(const Int32 pass, const Int32 lane, const Int32 slice, const Int32 index)
		{
			Position result = Position();
			result.Pass = pass;
			result.Lane = lane;
			result.Slice = slice;
			result.Index = index;

			return result;
		}
	};

	class Block
	{
	private:
		static const char * InvalidInputLength;

		static const Int32 SIZE = ARGON2_QWORDS_IN_BLOCK;
		
	public:
		// 128 * 8 Byte QWords
		HashLibUInt64Array V;

		Block()
		{
			V.resize(SIZE);
		} // 

		Block(const Block& other)
		{
			V = other.V;
		} //

		void Xor(const Block& b1, const Block& b2)
		{
			for (Int32 idx = 0; idx < SIZE; idx++)
				V[idx] = b1.V[idx] ^ b2.V[idx];
		}

		void Xor(const Block& b1, const Block& b2, const Block& b3)
		{
			for (Int32 idx = 0; idx < SIZE; idx++)
				V[idx] = b1.V[idx] ^ b2.V[idx] ^ b3.V[idx];
		} //

		void XorWith(const Block& other)
		{
			for (size_t idx = 0; idx < V.size(); idx++)
				V[idx] = V[idx] ^ other.V[idx];
		} //

		void Clear()
		{
			ArrayUtils::zeroFill(V);
		} //

		Block Clone() const
		{
			Block result = Block();
			result.V = V;
			return result;
		} //

		void FromBytes(const HashLibByteArray& input)
		{
			if (input.size() != ARGON2_BLOCK_SIZE)
				throw ArgumentOutOfRangeHashLibException(
					Utils::string_format(InvalidInputLength, input.size(), ARGON2_BLOCK_SIZE));

			for (Int32 idx = 0; idx < SIZE; idx++)
				V[idx] = Converters::ReadBytesAsUInt64LE(&input[0], idx * 8);
		} //

		HashLibByteArray ToBytes() const 
		{
			HashLibByteArray result = HashLibByteArray(ARGON2_BLOCK_SIZE);
			for (Int32 idx = 0; idx < SIZE; idx++)
				Converters::ReadUInt64AsBytesLE(V[idx], result, idx * 8);

			return result;
		} 

		string ToString() const 
		{
			string result = "";
			for (Int32 idx = 0; idx < SIZE; idx++)
				result += Converters::ConvertBytesToHexString(
					Converters::ReadUInt64AsBytesLE(V[idx]));

			return result;
		} //

		static Block DefaultBlock() { return Block(); };
	}; //

	class BlockFiller
	{
	public:
		Block R;
		Block Z;
		Block AddressBlock;
		Block ZeroBlock;
		Block InputBlock;

		BlockFiller()
		{
			R = Block::DefaultBlock();
			Z = Block::DefaultBlock();
			AddressBlock = Block::DefaultBlock();
			ZeroBlock = Block::DefaultBlock();
			InputBlock = Block::DefaultBlock();
		} //

		inline void FillBlock(const Block& x, const Block& y, Block& currentBlock)
		{
			if (x.V == ZeroBlock.V)
			{
				R = y;
			}
			else
			{
				R.Xor(x, y);
			}

			Z = R;
			ApplyBlake();
			currentBlock.Xor(R, Z);
		}

		inline void FillBlockWithXor(const Block& x, const Block& y, Block& currentBlock)
		{
			R.Xor(x, y);
			Z = R;
			ApplyBlake();
			currentBlock.Xor(R, Z, currentBlock);
		}

		static BlockFiller DefaultBlockFiller() { return BlockFiller(); }

	private:
		void ApplyBlake()
		{
			Int32 i;

			/* Apply Blake2 on columns of 64-bit words: (0,1,...,15) ,
			 * then (16,17,..31)... finally (112,113,...127) */

			for (i = 0; i < 8; i++)
			{
				Int32 i16 = 16 * i;
				RoundFunction(Z, i16, i16 + 1, i16 + 2, i16 + 3, i16 + 4, i16 + 5,
					i16 + 6, i16 + 7, i16 + 8, i16 + 9, i16 + 10, i16 + 11, i16 + 12,
					i16 + 13, i16 + 14, i16 + 15);
			}

			/* Apply Blake2 on rows of 64-bit words: (0,1,16,17,...112,113),
			then (2,3,18,19,...,114,115).. finally (14,15,30,31,...,126,127) */

			for (i = 0; i < 8; i++)
			{
				Int32 i2 = 2 * i;
				RoundFunction(Z, i2, i2 + 1, i2 + 16, i2 + 17, i2 + 32, i2 + 33,
					i2 + 48, i2 + 49, i2 + 64, i2 + 65, i2 + 80, i2 + 81, i2 + 96,
					i2 + 97, i2 + 112, i2 + 113);
			}
		} //

		static void RoundFunction(Block& block, const Int32 v0, const Int32 v1, const Int32 v2, const Int32 v3,
			const Int32 v4, const Int32 v5, const Int32 v6, const Int32 v7, const Int32 v8, const Int32 v9, const Int32 v10,
			const Int32 v11, const Int32 v12, const Int32 v13, const Int32 v14, const Int32 v15)
		{
			F(block, v0, v4, v8, v12);
			F(block, v1, v5, v9, v13);
			F(block, v2, v6, v10, v14);
			F(block, v3, v7, v11, v15);

			F(block, v0, v5, v10, v15);
			F(block, v1, v6, v11, v12);
			F(block, v2, v7, v8, v13);
			F(block, v3, v4, v9, v14);
		} //

		inline static void F(Block& block, const Int32 a, const Int32 b, const Int32 c, const Int32 d)
		{
			BlaMka(block, a, b);
			RotateRight64(block, d, a, 32);

			BlaMka(block, c, d);
			RotateRight64(block, b, c, 24);

			BlaMka(block, a, b);
			RotateRight64(block, d, a, 16);

			BlaMka(block, c, d);
			RotateRight64(block, b, c, 63);
		} //

		inline static void RotateRight64(Block& block, const Int32 a, const Int32 b, const Int32 c)
		{
			block.V[a] = Bits::RotateRight64(block.V[a] ^ block.V[b], c);
		} //

		inline static void BlaMka(Block& block, const Int32 x, const Int32 y)
		{
			const UInt32 m = 0xFFFFFFFF;
			UInt64 xy = (block.V[x] & m) * (block.V[y] & m);

			block.V[x] = block.V[x] + block.V[y] + 2 * xy;
		} //
				
	}; //

	//
	HashLibByteArray _digest, _password;
	vector<Block> _memory;
	IArgon2Parameters _parameters;
	Int32 _segmentLength, _laneLength;

public:
	PBKDF_Argon2NotBuildInAdapter()
	{} //

	/// <summary>
	/// Initialise the <see cref="PBKDF_Argon2NotBuildIn" />
	/// from the octets and parameter object.
	/// </summary>
	/// <param name="password">
	/// the octets to use.
	/// </param>
	/// <param name="parameters">
	/// Argon2 configuration.
	/// </param>
	PBKDF_Argon2NotBuildInAdapter(const HashLibByteArray& password, const IArgon2Parameters parameters)
	{
		_password = password;
		_parameters = parameters->Clone();

		if (_parameters->GetLanes() < MIN_PARALLELISM)
			throw ArgumentOutOfRangeHashLibException(Utils::string_format(LanesTooSmall, MIN_PARALLELISM));

		if (_parameters->GetLanes() > MAX_PARALLELISM)
			throw ArgumentOutOfRangeHashLibException(Utils::string_format(LanesTooBig, MAX_PARALLELISM));

		if (_parameters->GetMemory() < 8 * _parameters->GetLanes())
			throw ArgumentOutOfRangeHashLibException(Utils::string_format(MemoryTooSmall, _parameters->GetMemory(),
				8 * _parameters->GetLanes()));

		if (_parameters->GetIterations() < MIN_ITERATIONS)
			throw ArgumentOutOfRangeHashLibException(Utils::string_format(IterationsTooSmall, MIN_ITERATIONS));

		DoInit(parameters);
	} //

	virtual void Clear()
	{
		ArrayUtils::zeroFill(_password);
	} //

	virtual HashLibByteArray GetBytes(const Int32 bc)
	{
		if (bc <= MIN_OUTLEN)
			throw ArgumentOutOfRangeHashLibException(
				Utils::string_format(InvalidOutputByteCount, MIN_OUTLEN));

		Initialize(_password, bc);
		DoFillMemoryBlocks();

		Digest(bc);

		HashLibByteArray result = HashLibByteArray(bc);

		memmove(&result[0], &_digest[0], bc * sizeof(byte));
		
		Reset();

		return result;
	} //

	virtual string GetName() const
	{
		return "PBKDF_Argon2NotBuildIn";
	} //

	virtual IKDFNotBuildIn Clone() const
	{
		PBKDF_Argon2NotBuildInAdapter result = PBKDF_Argon2NotBuildInAdapter();	
		result._digest = _digest;
		result._password = _password;
		result._memory = DeepCopyBlockArray(_memory);
		result._parameters = _parameters->Clone();
		result._segmentLength = _segmentLength;
		result._laneLength = _laneLength;

		return make_shared<PBKDF_Argon2NotBuildInAdapter>(result);
	} //

private:
	static vector<Block> DeepCopyBlockArray(const vector<Block>& blocks)
	{
		vector<Block> result = vector<Block>(blocks.size());

		for (size_t idx = 0; idx < result.size(); idx++)
		{
			result[idx] = blocks[idx];
		}

		return result;
	} //

	inline void DoInit(const IArgon2Parameters parameters)
	{
		// 2. Align memory size
		// Minimum memoryBlocks = 8L blocks, where L is the number of lanes */
		Int32 memoryBlocks = parameters->GetMemory();

		memoryBlocks = max(memoryBlocks, 2 * ARGON2_SYNC_POINTS * parameters->GetLanes());

		_segmentLength = memoryBlocks / (_parameters->GetLanes() * ARGON2_SYNC_POINTS);
		_laneLength = _segmentLength * ARGON2_SYNC_POINTS;

		// Ensure that all segments have equal length
		memoryBlocks = _segmentLength * parameters->GetLanes() * ARGON2_SYNC_POINTS;

		InitializeMemory(memoryBlocks);
	} //

	void InitializeMemory(const Int32 memoryBlocks)
	{
		_memory = vector<Block>(memoryBlocks);
		for (size_t idx = 0; idx < _memory.size(); idx++)
			_memory[idx] = Block::DefaultBlock();
	}

	void Reset()
	{
		// Reset memory.
		for (size_t idx = 0; idx < _memory.size(); idx++)
		{
			_memory[idx].Clear();
			_memory[idx] = Block::DefaultBlock();
		} //

		ArrayUtils::zeroFill(_digest);
	} //

	static HashLibByteArray InitialHash(const IArgon2Parameters parameters, const Int32 outputLength,
		const HashLibByteArray& password)
	{
		Blake2B blake2B = MakeBlake2BInstanceAndInitialize(ARGON2_PREHASH_DIGEST_LENGTH);

		AddIntToLittleEndian(blake2B, parameters->GetLanes());
		AddIntToLittleEndian(blake2B, outputLength);
		AddIntToLittleEndian(blake2B, parameters->GetMemory());
		AddIntToLittleEndian(blake2B, parameters->GetIterations());
		AddIntToLittleEndian(blake2B, (Int32)parameters->GetVersion());
		AddIntToLittleEndian(blake2B, (Int32)parameters->GetType());

		AddByteString(blake2B, password);
		AddByteString(blake2B, parameters->GetSalt());
		AddByteString(blake2B, parameters->GetSecret());
		AddByteString(blake2B, parameters->GetAdditional());

		return blake2B.TransformFinal()->GetBytes();
	} //

	inline static void AddByteString(Blake2B& hashInstance, const HashLibByteArray& octets)
	{
		if (!octets.empty())
		{
			AddIntToLittleEndian(hashInstance, (Int32)octets.size());
			hashInstance.TransformBytes(octets, 0, (Int32)octets.size());
		}
		else
		{
			AddIntToLittleEndian(hashInstance, 0);
		}
	}

	inline static void AddIntToLittleEndian(Blake2B& hashInstance, const Int32 lanes)
	{
		HashLibByteArray temp = Converters::ReadUInt32AsBytesLE((UInt32)lanes);
		hashInstance.TransformBytes(temp, 0, (Int32)temp.size());
	} //

	inline static Blake2B MakeBlake2BInstanceAndInitialize(const Int32 hashSize)
	{
		Blake2B hashInstance = Blake2B(Blake2BConfig::CreateBlake2BConfig(hashSize));
		hashInstance.Initialize();
		return hashInstance;
	} //

	inline static HashLibByteArray GetInitialHashLong(const HashLibByteArray& initialHash, const HashLibByteArray& appendix)
	{
		HashLibByteArray result = HashLibByteArray(ARGON2_PREHASH_SEED_LENGTH);

		memmove(&result[0], &initialHash[0], ARGON2_PREHASH_DIGEST_LENGTH * sizeof(byte));
		memmove(&result[ARGON2_PREHASH_DIGEST_LENGTH], &appendix[0], 4 * sizeof(byte));
	
		return result;
	}

	static HashLibByteArray Hash(const HashLibByteArray& input, const Int32 outputLength)
	{
		Blake2B blake2B;

		const Int32 blake2BLength = 64;

		HashLibByteArray result = HashLibByteArray(outputLength);
		HashLibByteArray outputLengthBytes = Converters::ReadUInt32AsBytesLE((UInt32)outputLength);

		if (outputLength <= blake2BLength)
		{
			blake2B = MakeBlake2BInstanceAndInitialize(outputLength);

			blake2B.TransformBytes(outputLengthBytes, 0, (Int32)outputLengthBytes.size());
			blake2B.TransformBytes(input, 0, (Int32)input.size());
			result = blake2B.TransformFinal()->GetBytes();
		}
		else
		{
			blake2B = MakeBlake2BInstanceAndInitialize(blake2BLength);

			blake2B.TransformBytes(outputLengthBytes, 0, (Int32)outputLengthBytes.size());
			blake2B.TransformBytes(input, 0, (Int32)input.size());
			HashLibByteArray buffer = blake2B.TransformFinal()->GetBytes();

			memmove(&result[0], &buffer[0], (blake2BLength / 2) * sizeof(byte));
			
			Int32 count = ((outputLength + 31) / 32) - 2;

			Int32 position = blake2BLength / 2;

			Int32 idx = 2;

			while (idx <= count)
			{
				blake2B.TransformBytes(buffer, 0, (Int32)buffer.size());
				buffer = blake2B.TransformFinal()->GetBytes();

				memmove(&result[position], &buffer[0], (blake2BLength / 2) * sizeof(byte));
				
				idx++;
				position += (blake2BLength / 2);
			}

			Int32 lastLength = outputLength - (32 * count);

			blake2B = MakeBlake2BInstanceAndInitialize(lastLength);

			blake2B.TransformBytes(buffer, 0, (Int32)buffer.size());
			buffer = blake2B.TransformFinal()->GetBytes();

			memmove(&result[position], &buffer[0], lastLength * sizeof(byte));
		}

		return result;
	} //

	void Digest(const Int32 outputLength)
	{
		Block finalBlock = _memory[(size_t)_laneLength - 1];

		// XOR the last blocks
		for (Int32 idx = 1; idx < _parameters->GetLanes(); idx++)
		{
			Int32 lastBlockInLane = (idx * _laneLength) + (_laneLength - 1);
			finalBlock.XorWith(_memory[lastBlockInLane]);
		}

		HashLibByteArray finalBlockBytes = finalBlock.ToBytes();

		_digest = Hash(finalBlockBytes, outputLength);
	} //

	void FillFirstBlocks(const HashLibByteArray& initialHash)
	{
		HashLibByteArray zeroBytes = { 0, 0, 0, 0 };
		HashLibByteArray oneBytes = { 1, 0, 0, 0 };

		HashLibByteArray initialHashWithZeros = GetInitialHashLong(initialHash, zeroBytes);
		HashLibByteArray initialHashWithOnes = GetInitialHashLong(initialHash, oneBytes);

		for (Int32 idx = 0; idx < _parameters->GetLanes(); idx++)
		{
			Converters::ReadUInt32AsBytesLE((UInt32)idx, initialHashWithZeros, ARGON2_PREHASH_DIGEST_LENGTH + 4);
			Converters::ReadUInt32AsBytesLE((UInt32)idx, initialHashWithOnes, ARGON2_PREHASH_DIGEST_LENGTH + 4);

			HashLibByteArray blockHashBytes = Hash(initialHashWithZeros, ARGON2_BLOCK_SIZE);
			_memory[(size_t)idx * _laneLength].FromBytes(blockHashBytes);

			blockHashBytes = Hash(initialHashWithOnes, ARGON2_BLOCK_SIZE);
			_memory[(size_t)idx * _laneLength + 1].FromBytes(blockHashBytes);
		}
	} //

	inline bool IsDataIndependentAddressing(const Position& position)
	{
		return
			(_parameters->GetType() == Argon2Type::DataIndependentAddressing) ||
			((_parameters->GetType() == Argon2Type::HybridAddressing) && (position.Pass == 0)
			&& (position.Slice < ARGON2_SYNC_POINTS / 2));
	} //

	inline void Initialize(const HashLibByteArray& password, const Int32 outputLength)
	{
		HashLibByteArray initialHash = InitialHash(_parameters, outputLength, password);
		FillFirstBlocks(initialHash);
	} //

	void FillSegment(BlockFiller blockFiller, Position position)
	{
		bool dataIndependentAddressing = IsDataIndependentAddressing(position);
		Int32 startingIndex = GetStartingIndex(position);
		Int32 currentOffset = (position.Lane * _laneLength) +
			(position.Slice * _segmentLength) + startingIndex;
		Int32 prevOffset = GetPrevOffset(currentOffset);

		Block addressBlock = Block::DefaultBlock();
		Block inputBlock = Block::DefaultBlock();
		Block zeroBlock = Block::DefaultBlock();

		if (dataIndependentAddressing)
		{
			blockFiller.AddressBlock.Clear();
			blockFiller.ZeroBlock.Clear();
			blockFiller.InputBlock.Clear();

			InitAddressBlocks(blockFiller, position, zeroBlock, inputBlock, addressBlock);
		}

		position.Index = startingIndex;

		while (position.Index < _segmentLength)
		{
			prevOffset = RotatePrevOffset(currentOffset, prevOffset);

			UInt64 pseudoRandom = GetPseudoRandom(blockFiller, position, addressBlock,
				inputBlock, zeroBlock, prevOffset, dataIndependentAddressing);
			Int32 refLane = GetRefLane(position, pseudoRandom);
			Int32 refColumn = GetRefColumn(position, pseudoRandom, refLane == position.Lane);

			// 2 Creating a new block
			Block prevBlock = _memory[prevOffset];
			Block refBlock = _memory[((size_t)_laneLength * refLane) + refColumn];
			//Block currentBlock = _memory[currentOffset];

			if (IsWithXor(position))
			{
				blockFiller.FillBlockWithXor(prevBlock, refBlock, _memory[currentOffset]);
			}
			else
			{
				blockFiller.FillBlock(prevBlock, refBlock, _memory[currentOffset]);
			}

			position.Index++;
			currentOffset++;
			prevOffset++;
		}
	}

	inline void FillMemoryBlocks(BlockFiller& blockFiller, Position& position)
	{
		FillSegment(blockFiller, position);
	} //

	void DoFillMemoryBlocks()
	{
		 // single threaded version
		BlockFiller filler = BlockFiller::DefaultBlockFiller();
		Position position = Position::DefaultPosition();

		Int32 iterations = _parameters->GetIterations();
		Int32 lanes = _parameters->GetLanes();

		for (Int32 idx = 0; idx < iterations; idx++)
		{
			for (Int32 jdx = 0; jdx < ARGON2_SYNC_POINTS; jdx++)
			{
				for (Int32 kdx = 0; kdx < lanes; kdx++)
				{
					position.Update(idx, kdx, jdx, 0);
					FillMemoryBlocks(filler, position);
				}
			}
		}

	}

	inline bool IsWithXor(const Position& position)
	{
		return !(position.Pass == 0 || _parameters->GetVersion() == Argon2Version::Sixteen);
	} //

	Int32 GetRefColumn(const Position& position, const UInt64 pseudoRandom, const bool sameLane)
	{
		Int32 referenceAreaSize, startPosition, temp;

		if (position.Pass == 0)
		{
			startPosition = 0;

			if (sameLane)
			{
				// The same lane => add current segment
				referenceAreaSize = (position.Slice * _segmentLength) +
					position.Index - 1;
			}
			else
			{
				temp = position.Index == 0 ? -1 : 0;

				referenceAreaSize = (position.Slice * _segmentLength) + temp;
			}
		}
		else
		{
			startPosition = ((position.Slice + 1) * _segmentLength) % _laneLength;

			if (sameLane)
			{
				referenceAreaSize = _laneLength - _segmentLength + position.Index - 1;
			}
			else
			{
				temp = position.Index == 0 ? -1 : 0;

				referenceAreaSize = _laneLength - _segmentLength + temp;
			}
		}

		UInt64 relativePosition = pseudoRandom & (UInt32)0xFFFFFFFF;
		relativePosition = (relativePosition * relativePosition) >> 32;
		relativePosition = (UInt64)referenceAreaSize - 1 -
			(((UInt64)referenceAreaSize * relativePosition) >> 32);

		return (Int32)(((UInt64)startPosition + relativePosition) % (UInt64)_laneLength);
	}

	inline Int32 GetRefLane(const Position& position, const UInt64 pseudoRandom)
	{
		Int32 refLane = (Int32)((pseudoRandom >> 32) % (UInt64)_parameters->GetLanes());

		if (position.Pass == 0 && position.Slice == 0)
			// Can not reference other lanes yet
			refLane = position.Lane;

		return refLane;
	}

	inline UInt64 GetPseudoRandom(BlockFiller& blockFiller, const Position& position,
		Block& addressBlock, Block& inputBlock, const Block& zeroBlock, const Int32 prevOffset,
		const bool dataIndependentAddressing)
	{
		if (!dataIndependentAddressing) return _memory[prevOffset].V[0];
		if (position.Index % ARGON2_ADDRESSES_IN_BLOCK == 0)
			NextAddresses(blockFiller, zeroBlock, inputBlock, addressBlock);

		return addressBlock.V[position.Index % ARGON2_ADDRESSES_IN_BLOCK];
	}

	inline Int32 RotatePrevOffset(const Int32 currentOffset, const Int32 prevOffset)
	{
		return currentOffset % _laneLength == 1 ? currentOffset - 1 : prevOffset;
	} //

	void InitAddressBlocks(BlockFiller& blockFiller, const Position& position,
		const Block& zeroBlock, Block& inputBlock, Block& addressBlock)
	{
		inputBlock.V[0] = IntToUInt64(position.Pass);
		inputBlock.V[1] = IntToUInt64(position.Lane);
		inputBlock.V[2] = IntToUInt64(position.Slice);
		inputBlock.V[3] = IntToUInt64((Int32)_memory.size());
		inputBlock.V[4] = IntToUInt64(_parameters->GetIterations());
		inputBlock.V[5] = IntToUInt64((Int32)_parameters->GetType());

		// Don't forget to generate the first block of addresses: */
		if (position.Pass == 0 && position.Slice == 0)
			NextAddresses(blockFiller, zeroBlock, inputBlock, addressBlock);
	} //

	inline static void NextAddresses(BlockFiller& blockFiller, const Block& zeroBlock, Block& inputBlock,
		Block& addressBlock)
	{
		inputBlock.V[6]++;
		blockFiller.FillBlock(zeroBlock, inputBlock, addressBlock);
		blockFiller.FillBlock(zeroBlock, addressBlock, addressBlock);
	}

	inline static UInt64 IntToUInt64(const Int32 x) { return (UInt64)(x & (UInt32)0xFFFFFFFF); }

	inline Int32 GetPrevOffset(const Int32 currentOffset)
	{
		return currentOffset % _laneLength == 0 ? currentOffset + _laneLength - 1 : currentOffset - 1;
	} //

	inline static Int32 GetStartingIndex(const Position& position)
	{
		return position.Pass == 0 && position.Slice == 0 ? 2 : 0;
	} //
	
}; //

const char* PBKDF_Argon2NotBuildInAdapter::Block::InvalidInputLength = "Input length '%u' is not equal to blockSize '%u'";

const char* PBKDF_Argon2NotBuildInAdapter::LanesTooSmall = "Lanes must be greater than '%u'";
const char* PBKDF_Argon2NotBuildInAdapter::LanesTooBig = "Lanes must be less than '%u'";
const char* PBKDF_Argon2NotBuildInAdapter::MemoryTooSmall = "Memory is too small: '%u', expected at least '%u'";
const char* PBKDF_Argon2NotBuildInAdapter::IterationsTooSmall = "Iterations is less than: '%u'";
const char* PBKDF_Argon2NotBuildInAdapter::InvalidOutputByteCount = "byteCount less than '%u'";