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

#include "../Params/Blake2SParams.h"
#include "../Params/Blake2XSParams.h"
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

class Blake2S : public Hash, public virtual IICryptoNotBuildIn, public virtual IITransformBlock
{
public:
	Blake2S() {}

	Blake2S(const IBlake2SConfig a_Config, const IBlake2STreeConfig a_TreeConfig = nullptr,
		bool a_DoTransformKeyBlock = true) 
		: Hash(a_Config ? a_Config->GetHashSize() : throw ArgumentNullHashLibException("config"), BlockSizeInBytes)
	{
		_name = __func__;

		_config = a_Config->Clone();
		_treeConfig = a_TreeConfig ? a_TreeConfig->Clone() : nullptr;
		_doTransformKeyBlock = a_DoTransformKeyBlock;
		
		_state.resize(8);
		_m.resize(16);

		_buffer.resize(BlockSizeInBytes);
	}

	// Copy constructor
	Blake2S(const Blake2S& blake2)
	{
		_state = blake2._state;
		_m = blake2._m;
		_buffer = blake2._buffer;

		_filledBufferCount = blake2._filledBufferCount;
		_counter0 = blake2._counter0;
		_counter1 = blake2._counter1;
		_finalizationFlag0 = blake2._finalizationFlag0;
		_finalizationFlag1 = blake2._finalizationFlag1;
		
		_treeConfig = blake2._treeConfig ? blake2._treeConfig->Clone() : nullptr;
		_config = blake2._config->Clone();

		_doTransformKeyBlock = blake2._doTransformKeyBlock;

		SetHashSize(blake2.GetHashSize());
		SetBufferSize(blake2.GetBufferSize());
		SetBlockSize(blake2.GetBlockSize());
		_name = blake2.GetName();
	}

	Blake2S CloneInternal() const
	{
		IBlake2STreeConfig treeConfig = nullptr;
		
		if (_treeConfig)
			treeConfig = _treeConfig->Clone();
		
		Blake2S result= Blake2S(_config, treeConfig, _doTransformKeyBlock);
		result._m = _m;
		result._state = _state;
		result._buffer = _buffer;
		result._filledBufferCount = _filledBufferCount;
		result._counter0 = _counter0;
		result._counter1 = _counter1;
		result._finalizationFlag0 = _finalizationFlag0;
		result._finalizationFlag1 = _finalizationFlag1;
		result.SetBufferSize(GetBufferSize());

		return result;
	}

	virtual IHash Clone() const
	{
		return make_shared<Blake2S>(CloneInternal());
	}

	virtual void Initialize()
	{
		Int32 Idx;
		HashLibByteArray Block;
		HashLibUInt32Array RawConfig;
		
		RawConfig = Blake2SIvBuilder::ConfigS(_config, _treeConfig);
	
		if (_doTransformKeyBlock)
		{
			if (!_config->GetKey().empty())
			{
				Block = HashLibByteArray(BlockSizeInBytes);
				memmove(&Block[0], &_config->GetKey()[0], _config->GetKey().size() * sizeof(byte));
			}
		}
				
		if (RawConfig.size() != 8) 
			throw ArgumentHashLibException(Blake2S::InvalidConfigLength);

		_state[0] = IV0;
		_state[1] = IV1;
		_state[2] = IV2;
		_state[3] = IV3;
		_state[4] = IV4;
		_state[5] = IV5;
		_state[6] = IV6;
		_state[7] = IV7;

		_counter0 = 0;
		_counter1 = 0;
		_finalizationFlag0 = 0;
		_finalizationFlag1 = 0;

		_filledBufferCount = 0;

		ArrayUtils::zeroFill(_buffer);
		ArrayUtils::zeroFill(_m);

		for (Idx = 0; Idx < 8; Idx++)
			_state[Idx] = _state[Idx] ^ RawConfig[Idx];

		if (_doTransformKeyBlock)
		{
			if (!Block.empty())
			{
				TransformBytes(Block, 0, (Int32)Block.size());
				ArrayUtils::zeroFill(Block); // burn key from memory
			}
		}
	}

	virtual void TransformBytes(const HashLibByteArray& a_data, const Int32 a_index, const Int32 a_data_length)
	{
		Int32 offset, bufferRemaining;
		Int32 data_length = a_data_length;

		offset = a_index;
		bufferRemaining = BlockSizeInBytes - _filledBufferCount;

		if (_filledBufferCount > 0 && data_length > bufferRemaining)
		{
			if (bufferRemaining > 0)
				memmove(&_buffer[_filledBufferCount], &a_data[offset], bufferRemaining);
			
			Blake2SIncrementCounter(BlockSizeInBytes);
			
			Compress(&_buffer[0], 0);

			offset = offset + bufferRemaining;
			data_length = data_length - bufferRemaining;
			_filledBufferCount = 0;
		}
			
		while (data_length > BlockSizeInBytes)
		{
			Blake2SIncrementCounter(BlockSizeInBytes);
			Compress(&a_data[0], offset);
			offset = offset + BlockSizeInBytes;
			data_length = data_length - BlockSizeInBytes;
		}

		if (data_length > 0)
		{
			memmove(&_buffer[_filledBufferCount], &a_data[offset], data_length);
			_filledBufferCount = _filledBufferCount + data_length;
		}

	}

	virtual IHashResult TransformFinal()
	{
		HashLibByteArray tempRes;

		Finish();

		tempRes.resize(GetHashSize());

		Converters::le32_copy(&_state[0], 0, &tempRes[0], 0, (Int32)tempRes.size());

		IHashResult result = make_shared<HashResult>(tempRes);

		Initialize();

		return result;
	}

	virtual string GetName() const
	{
		return Utils::string_format("%s_%u", _name.c_str(), GetHashSize() * 8);
	}

	IBlake2SConfig GetConfig() const
	{
		return _config->Clone();
	}

	IBlake2STreeConfig GetTreeConfig() const
	{
		return _treeConfig ? _treeConfig->Clone() : nullptr;
	}

	IBlake2SConfig GetConfig()
	{
		return _config;
	}

	IBlake2STreeConfig GetTreeConfig()
	{
		return _treeConfig;
	}

private:
	void Compress(const byte* block, const Int32 start)
	{
		Converters::le32_copy(block, start, &_m[0], 0, GetBlockSize());

		MixScalar();
	}

	void MixScalar() 
	{
		UInt32 m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, v0, v1,
			v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15;

		m0 = _m[0];
		m1 = _m[1];
		m2 = _m[2];
		m3 = _m[3];
		m4 = _m[4];
		m5 = _m[5];
		m6 = _m[6];
		m7 = _m[7];
		m8 = _m[8];
		m9 = _m[9];
		m10 = _m[10];
		m11 = _m[11];
		m12 = _m[12];
		m13 = _m[13];
		m14 = _m[14];
		m15 = _m[15];

		v0 = _state[0];
		v1 = _state[1];
		v2 = _state[2];
		v3 = _state[3];
		v4 = _state[4];
		v5 = _state[5];
		v6 = _state[6];
		v7 = _state[7];

		v8 = IV0;
		v9 = IV1;
		v10 = IV2;
		v11 = IV3;
		v12 = IV4 ^ _counter0;
		v13 = IV5 ^ _counter1;
		v14 = IV6 ^ _finalizationFlag0;
		v15 = IV7 ^ _finalizationFlag1;

		// Rounds
		// *
		// Round 1.
		v0 = v0 + m0;
		v0 = v0 + v4;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight32(v12, 16);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight32(v4, 12);
		v1 = v1 + m2;
		v1 = v1 + v5;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight32(v13, 16);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight32(v5, 12);
		v2 = v2 + m4;
		v2 = v2 + v6;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight32(v14, 16);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight32(v6, 12);
		v3 = v3 + m6;
		v3 = v3 + v7;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight32(v15, 16);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight32(v7, 12);
		v2 = v2 + m5;
		v2 = v2 + v6;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight32(v14, 8);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight32(v6, 7);
		v3 = v3 + m7;
		v3 = v3 + v7;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight32(v15, 8);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight32(v7, 7);
		v1 = v1 + m3;
		v1 = v1 + v5;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight32(v13, 8);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight32(v5, 7);
		v0 = v0 + m1;
		v0 = v0 + v4;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight32(v12, 8);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight32(v4, 7);
		v0 = v0 + m8;
		v0 = v0 + v5;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight32(v15, 16);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight32(v5, 12);
		v1 = v1 + m10;
		v1 = v1 + v6;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight32(v12, 16);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight32(v6, 12);
		v2 = v2 + m12;
		v2 = v2 + v7;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight32(v13, 16);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight32(v7, 12);
		v3 = v3 + m14;
		v3 = v3 + v4;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight32(v14, 16);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight32(v4, 12);
		v2 = v2 + m13;
		v2 = v2 + v7;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight32(v13, 8);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight32(v7, 7);
		v3 = v3 + m15;
		v3 = v3 + v4;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight32(v14, 8);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight32(v4, 7);
		v1 = v1 + m11;
		v1 = v1 + v6;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight32(v12, 8);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight32(v6, 7);
		v0 = v0 + m9;
		v0 = v0 + v5;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight32(v15, 8);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight32(v5, 7);

		// Round 2.
		v0 = v0 + m14;
		v0 = v0 + v4;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight32(v12, 16);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight32(v4, 12);
		v1 = v1 + m4;
		v1 = v1 + v5;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight32(v13, 16);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight32(v5, 12);
		v2 = v2 + m9;
		v2 = v2 + v6;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight32(v14, 16);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight32(v6, 12);
		v3 = v3 + m13;
		v3 = v3 + v7;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight32(v15, 16);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight32(v7, 12);
		v2 = v2 + m15;
		v2 = v2 + v6;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight32(v14, 8);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight32(v6, 7);
		v3 = v3 + m6;
		v3 = v3 + v7;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight32(v15, 8);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight32(v7, 7);
		v1 = v1 + m8;
		v1 = v1 + v5;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight32(v13, 8);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight32(v5, 7);
		v0 = v0 + m10;
		v0 = v0 + v4;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight32(v12, 8);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight32(v4, 7);
		v0 = v0 + m1;
		v0 = v0 + v5;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight32(v15, 16);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight32(v5, 12);
		v1 = v1 + m0;
		v1 = v1 + v6;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight32(v12, 16);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight32(v6, 12);
		v2 = v2 + m11;
		v2 = v2 + v7;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight32(v13, 16);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight32(v7, 12);
		v3 = v3 + m5;
		v3 = v3 + v4;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight32(v14, 16);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight32(v4, 12);
		v2 = v2 + m7;
		v2 = v2 + v7;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight32(v13, 8);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight32(v7, 7);
		v3 = v3 + m3;
		v3 = v3 + v4;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight32(v14, 8);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight32(v4, 7);
		v1 = v1 + m2;
		v1 = v1 + v6;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight32(v12, 8);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight32(v6, 7);
		v0 = v0 + m12;
		v0 = v0 + v5;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight32(v15, 8);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight32(v5, 7);

		// Round 3.
		v0 = v0 + m11;
		v0 = v0 + v4;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight32(v12, 16);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight32(v4, 12);
		v1 = v1 + m12;
		v1 = v1 + v5;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight32(v13, 16);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight32(v5, 12);
		v2 = v2 + m5;
		v2 = v2 + v6;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight32(v14, 16);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight32(v6, 12);
		v3 = v3 + m15;
		v3 = v3 + v7;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight32(v15, 16);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight32(v7, 12);
		v2 = v2 + m2;
		v2 = v2 + v6;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight32(v14, 8);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight32(v6, 7);
		v3 = v3 + m13;
		v3 = v3 + v7;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight32(v15, 8);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight32(v7, 7);
		v1 = v1 + m0;
		v1 = v1 + v5;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight32(v13, 8);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight32(v5, 7);
		v0 = v0 + m8;
		v0 = v0 + v4;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight32(v12, 8);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight32(v4, 7);
		v0 = v0 + m10;
		v0 = v0 + v5;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight32(v15, 16);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight32(v5, 12);
		v1 = v1 + m3;
		v1 = v1 + v6;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight32(v12, 16);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight32(v6, 12);
		v2 = v2 + m7;
		v2 = v2 + v7;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight32(v13, 16);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight32(v7, 12);
		v3 = v3 + m9;
		v3 = v3 + v4;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight32(v14, 16);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight32(v4, 12);
		v2 = v2 + m1;
		v2 = v2 + v7;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight32(v13, 8);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight32(v7, 7);
		v3 = v3 + m4;
		v3 = v3 + v4;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight32(v14, 8);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight32(v4, 7);
		v1 = v1 + m6;
		v1 = v1 + v6;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight32(v12, 8);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight32(v6, 7);
		v0 = v0 + m14;
		v0 = v0 + v5;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight32(v15, 8);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight32(v5, 7);

		// Round 4.
		v0 = v0 + m7;
		v0 = v0 + v4;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight32(v12, 16);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight32(v4, 12);
		v1 = v1 + m3;
		v1 = v1 + v5;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight32(v13, 16);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight32(v5, 12);
		v2 = v2 + m13;
		v2 = v2 + v6;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight32(v14, 16);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight32(v6, 12);
		v3 = v3 + m11;
		v3 = v3 + v7;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight32(v15, 16);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight32(v7, 12);
		v2 = v2 + m12;
		v2 = v2 + v6;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight32(v14, 8);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight32(v6, 7);
		v3 = v3 + m14;
		v3 = v3 + v7;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight32(v15, 8);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight32(v7, 7);
		v1 = v1 + m1;
		v1 = v1 + v5;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight32(v13, 8);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight32(v5, 7);
		v0 = v0 + m9;
		v0 = v0 + v4;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight32(v12, 8);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight32(v4, 7);
		v0 = v0 + m2;
		v0 = v0 + v5;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight32(v15, 16);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight32(v5, 12);
		v1 = v1 + m5;
		v1 = v1 + v6;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight32(v12, 16);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight32(v6, 12);
		v2 = v2 + m4;
		v2 = v2 + v7;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight32(v13, 16);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight32(v7, 12);
		v3 = v3 + m15;
		v3 = v3 + v4;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight32(v14, 16);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight32(v4, 12);
		v2 = v2 + m0;
		v2 = v2 + v7;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight32(v13, 8);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight32(v7, 7);
		v3 = v3 + m8;
		v3 = v3 + v4;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight32(v14, 8);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight32(v4, 7);
		v1 = v1 + m10;
		v1 = v1 + v6;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight32(v12, 8);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight32(v6, 7);
		v0 = v0 + m6;
		v0 = v0 + v5;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight32(v15, 8);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight32(v5, 7);

		// Round 5.
		v0 = v0 + m9;
		v0 = v0 + v4;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight32(v12, 16);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight32(v4, 12);
		v1 = v1 + m5;
		v1 = v1 + v5;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight32(v13, 16);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight32(v5, 12);
		v2 = v2 + m2;
		v2 = v2 + v6;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight32(v14, 16);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight32(v6, 12);
		v3 = v3 + m10;
		v3 = v3 + v7;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight32(v15, 16);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight32(v7, 12);
		v2 = v2 + m4;
		v2 = v2 + v6;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight32(v14, 8);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight32(v6, 7);
		v3 = v3 + m15;
		v3 = v3 + v7;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight32(v15, 8);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight32(v7, 7);
		v1 = v1 + m7;
		v1 = v1 + v5;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight32(v13, 8);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight32(v5, 7);
		v0 = v0 + m0;
		v0 = v0 + v4;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight32(v12, 8);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight32(v4, 7);
		v0 = v0 + m14;
		v0 = v0 + v5;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight32(v15, 16);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight32(v5, 12);
		v1 = v1 + m11;
		v1 = v1 + v6;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight32(v12, 16);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight32(v6, 12);
		v2 = v2 + m6;
		v2 = v2 + v7;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight32(v13, 16);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight32(v7, 12);
		v3 = v3 + m3;
		v3 = v3 + v4;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight32(v14, 16);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight32(v4, 12);
		v2 = v2 + m8;
		v2 = v2 + v7;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight32(v13, 8);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight32(v7, 7);
		v3 = v3 + m13;
		v3 = v3 + v4;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight32(v14, 8);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight32(v4, 7);
		v1 = v1 + m12;
		v1 = v1 + v6;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight32(v12, 8);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight32(v6, 7);
		v0 = v0 + m1;
		v0 = v0 + v5;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight32(v15, 8);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight32(v5, 7);

		// Round 6.
		v0 = v0 + m2;
		v0 = v0 + v4;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight32(v12, 16);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight32(v4, 12);
		v1 = v1 + m6;
		v1 = v1 + v5;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight32(v13, 16);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight32(v5, 12);
		v2 = v2 + m0;
		v2 = v2 + v6;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight32(v14, 16);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight32(v6, 12);
		v3 = v3 + m8;
		v3 = v3 + v7;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight32(v15, 16);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight32(v7, 12);
		v2 = v2 + m11;
		v2 = v2 + v6;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight32(v14, 8);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight32(v6, 7);
		v3 = v3 + m3;
		v3 = v3 + v7;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight32(v15, 8);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight32(v7, 7);
		v1 = v1 + m10;
		v1 = v1 + v5;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight32(v13, 8);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight32(v5, 7);
		v0 = v0 + m12;
		v0 = v0 + v4;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight32(v12, 8);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight32(v4, 7);
		v0 = v0 + m4;
		v0 = v0 + v5;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight32(v15, 16);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight32(v5, 12);
		v1 = v1 + m7;
		v1 = v1 + v6;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight32(v12, 16);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight32(v6, 12);
		v2 = v2 + m15;
		v2 = v2 + v7;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight32(v13, 16);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight32(v7, 12);
		v3 = v3 + m1;
		v3 = v3 + v4;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight32(v14, 16);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight32(v4, 12);
		v2 = v2 + m14;
		v2 = v2 + v7;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight32(v13, 8);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight32(v7, 7);
		v3 = v3 + m9;
		v3 = v3 + v4;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight32(v14, 8);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight32(v4, 7);
		v1 = v1 + m5;
		v1 = v1 + v6;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight32(v12, 8);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight32(v6, 7);
		v0 = v0 + m13;
		v0 = v0 + v5;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight32(v15, 8);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight32(v5, 7);

		// Round 7.
		v0 = v0 + m12;
		v0 = v0 + v4;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight32(v12, 16);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight32(v4, 12);
		v1 = v1 + m1;
		v1 = v1 + v5;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight32(v13, 16);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight32(v5, 12);
		v2 = v2 + m14;
		v2 = v2 + v6;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight32(v14, 16);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight32(v6, 12);
		v3 = v3 + m4;
		v3 = v3 + v7;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight32(v15, 16);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight32(v7, 12);
		v2 = v2 + m13;
		v2 = v2 + v6;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight32(v14, 8);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight32(v6, 7);
		v3 = v3 + m10;
		v3 = v3 + v7;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight32(v15, 8);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight32(v7, 7);
		v1 = v1 + m15;
		v1 = v1 + v5;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight32(v13, 8);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight32(v5, 7);
		v0 = v0 + m5;
		v0 = v0 + v4;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight32(v12, 8);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight32(v4, 7);
		v0 = v0 + m0;
		v0 = v0 + v5;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight32(v15, 16);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight32(v5, 12);
		v1 = v1 + m6;
		v1 = v1 + v6;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight32(v12, 16);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight32(v6, 12);
		v2 = v2 + m9;
		v2 = v2 + v7;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight32(v13, 16);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight32(v7, 12);
		v3 = v3 + m8;
		v3 = v3 + v4;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight32(v14, 16);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight32(v4, 12);
		v2 = v2 + m2;
		v2 = v2 + v7;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight32(v13, 8);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight32(v7, 7);
		v3 = v3 + m11;
		v3 = v3 + v4;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight32(v14, 8);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight32(v4, 7);
		v1 = v1 + m3;
		v1 = v1 + v6;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight32(v12, 8);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight32(v6, 7);
		v0 = v0 + m7;
		v0 = v0 + v5;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight32(v15, 8);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight32(v5, 7);

		// Round 8.
		v0 = v0 + m13;
		v0 = v0 + v4;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight32(v12, 16);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight32(v4, 12);
		v1 = v1 + m7;
		v1 = v1 + v5;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight32(v13, 16);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight32(v5, 12);
		v2 = v2 + m12;
		v2 = v2 + v6;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight32(v14, 16);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight32(v6, 12);
		v3 = v3 + m3;
		v3 = v3 + v7;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight32(v15, 16);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight32(v7, 12);
		v2 = v2 + m1;
		v2 = v2 + v6;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight32(v14, 8);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight32(v6, 7);
		v3 = v3 + m9;
		v3 = v3 + v7;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight32(v15, 8);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight32(v7, 7);
		v1 = v1 + m14;
		v1 = v1 + v5;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight32(v13, 8);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight32(v5, 7);
		v0 = v0 + m11;
		v0 = v0 + v4;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight32(v12, 8);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight32(v4, 7);
		v0 = v0 + m5;
		v0 = v0 + v5;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight32(v15, 16);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight32(v5, 12);
		v1 = v1 + m15;
		v1 = v1 + v6;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight32(v12, 16);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight32(v6, 12);
		v2 = v2 + m8;
		v2 = v2 + v7;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight32(v13, 16);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight32(v7, 12);
		v3 = v3 + m2;
		v3 = v3 + v4;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight32(v14, 16);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight32(v4, 12);
		v2 = v2 + m6;
		v2 = v2 + v7;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight32(v13, 8);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight32(v7, 7);
		v3 = v3 + m10;
		v3 = v3 + v4;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight32(v14, 8);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight32(v4, 7);
		v1 = v1 + m4;
		v1 = v1 + v6;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight32(v12, 8);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight32(v6, 7);
		v0 = v0 + m0;
		v0 = v0 + v5;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight32(v15, 8);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight32(v5, 7);

		// Round 9.
		v0 = v0 + m6;
		v0 = v0 + v4;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight32(v12, 16);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight32(v4, 12);
		v1 = v1 + m14;
		v1 = v1 + v5;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight32(v13, 16);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight32(v5, 12);
		v2 = v2 + m11;
		v2 = v2 + v6;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight32(v14, 16);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight32(v6, 12);
		v3 = v3 + m0;
		v3 = v3 + v7;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight32(v15, 16);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight32(v7, 12);
		v2 = v2 + m3;
		v2 = v2 + v6;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight32(v14, 8);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight32(v6, 7);
		v3 = v3 + m8;
		v3 = v3 + v7;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight32(v15, 8);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight32(v7, 7);
		v1 = v1 + m9;
		v1 = v1 + v5;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight32(v13, 8);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight32(v5, 7);
		v0 = v0 + m15;
		v0 = v0 + v4;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight32(v12, 8);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight32(v4, 7);
		v0 = v0 + m12;
		v0 = v0 + v5;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight32(v15, 16);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight32(v5, 12);
		v1 = v1 + m13;
		v1 = v1 + v6;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight32(v12, 16);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight32(v6, 12);
		v2 = v2 + m1;
		v2 = v2 + v7;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight32(v13, 16);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight32(v7, 12);
		v3 = v3 + m10;
		v3 = v3 + v4;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight32(v14, 16);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight32(v4, 12);
		v2 = v2 + m4;
		v2 = v2 + v7;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight32(v13, 8);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight32(v7, 7);
		v3 = v3 + m5;
		v3 = v3 + v4;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight32(v14, 8);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight32(v4, 7);
		v1 = v1 + m7;
		v1 = v1 + v6;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight32(v12, 8);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight32(v6, 7);
		v0 = v0 + m2;
		v0 = v0 + v5;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight32(v15, 8);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight32(v5, 7);

		// Round 10.
		v0 = v0 + m10;
		v0 = v0 + v4;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight32(v12, 16);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight32(v4, 12);
		v1 = v1 + m8;
		v1 = v1 + v5;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight32(v13, 16);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight32(v5, 12);
		v2 = v2 + m7;
		v2 = v2 + v6;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight32(v14, 16);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight32(v6, 12);
		v3 = v3 + m1;
		v3 = v3 + v7;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight32(v15, 16);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight32(v7, 12);
		v2 = v2 + m6;
		v2 = v2 + v6;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight32(v14, 8);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight32(v6, 7);
		v3 = v3 + m5;
		v3 = v3 + v7;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight32(v15, 8);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight32(v7, 7);
		v1 = v1 + m4;
		v1 = v1 + v5;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight32(v13, 8);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight32(v5, 7);
		v0 = v0 + m2;
		v0 = v0 + v4;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight32(v12, 8);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight32(v4, 7);
		v0 = v0 + m15;
		v0 = v0 + v5;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight32(v15, 16);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight32(v5, 12);
		v1 = v1 + m9;
		v1 = v1 + v6;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight32(v12, 16);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight32(v6, 12);
		v2 = v2 + m3;
		v2 = v2 + v7;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight32(v13, 16);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight32(v7, 12);
		v3 = v3 + m13;
		v3 = v3 + v4;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight32(v14, 16);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight32(v4, 12);
		v2 = v2 + m12;
		v2 = v2 + v7;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight32(v13, 8);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight32(v7, 7);
		v3 = v3 + m0;
		v3 = v3 + v4;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight32(v14, 8);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight32(v4, 7);
		v1 = v1 + m14;
		v1 = v1 + v6;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight32(v12, 8);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight32(v6, 7);
		v0 = v0 + m11;
		v0 = v0 + v5;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight32(v15, 8);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight32(v5, 7);
		// */
		// Finalization

		_state[0] = _state[0] ^ (v0 ^ v8);
		_state[1] = _state[1] ^ (v1 ^ v9);
		_state[2] = _state[2] ^ (v2 ^ v10);
		_state[3] = _state[3] ^ (v3 ^ v11);
		_state[4] = _state[4] ^ (v4 ^ v12);
		_state[5] = _state[5] ^ (v5 ^ v13);
		_state[6] = _state[6] ^ (v6 ^ v14);
		_state[7] = _state[7] ^ (v7 ^ v15);

	}

	void Blake2SIncrementCounter(const UInt32 incrementCount)
	{
		_counter0 += incrementCount;
		_counter1 += UInt32(_counter0 < incrementCount);
	}

protected:
	inline void Finish()
	{
		Int32 count;

		// Last compression
		Blake2SIncrementCounter((UInt32)_filledBufferCount);

		_finalizationFlag0 = UINT32_MAX;

		if (_treeConfig != nullptr && _treeConfig->GetIsLastNode())
			_finalizationFlag1 = UINT32_MAX;

		count = (Int32)_buffer.size() - _filledBufferCount;

		if (count > 0)
			ArrayUtils::fill(_buffer, _filledBufferCount, count + _filledBufferCount, byte(0));

		Compress(&_buffer[0], 0);
	}


	HashLibUInt32Array _state, _m;
	HashLibByteArray _buffer;

	Int32 _filledBufferCount = 0;
	UInt32 _counter0 = 0, _counter1 = 0, _finalizationFlag0 = 0, _finalizationFlag1 = 0;

	IBlake2STreeConfig _treeConfig = nullptr;
	IBlake2SConfig _config = nullptr;

private:
	bool _doTransformKeyBlock = false;

	static const Int32 BlockSizeInBytes = Int32(64);

	static const UInt32 IV0 = UInt32(0x6A09E667);
	static const UInt32 IV1 = UInt32(0xBB67AE85);
	static const UInt32 IV2 = UInt32(0x3C6EF372);
	static const UInt32 IV3 = UInt32(0xA54FF53A);
	static const UInt32 IV4 = UInt32(0x510E527F);
	static const UInt32 IV5 = UInt32(0x9B05688C);
	static const UInt32 IV6 = UInt32(0x1F83D9AB);
	static const UInt32 IV7 = UInt32(0x5BE0CD19);

protected:
	static const char* InvalidConfigLength;
	
}; // end class Blake2S

class Blake2XS : public Blake2S, public virtual IIXOF
{
protected:
	static const char* InvalidXofSize;
	static const char* InvalidOutputLength;
	static const char* OutputBufferTooShort;
	static const char* MaximumOutputLengthExceeded;
	static const char* WritetoXofAfterReadError;

private:
	void SetXOFSizeInBitsInternal(const UInt64 a_XofSizeInBits)
	{
		UInt64 xofSizeInBytes;
		
		xofSizeInBytes = a_XofSizeInBits >> 3;
		if ((a_XofSizeInBits & 0x7) != 0 || xofSizeInBytes < 1 ||
			xofSizeInBytes > UInt64(UnknownDigestLengthInBytes))
			throw ArgumentOutOfRangeHashLibException(
				Utils::string_format(InvalidXofSize, 1, UInt64(UnknownDigestLengthInBytes)));
	
		_xofSizeInBits = a_XofSizeInBits;
	}

	inline UInt64 NodeOffsetWithXOFDigestLength(const UInt64 a_XOFSizeInBytes)
	{
		return UInt64(a_XOFSizeInBytes) << 32;
	}

	inline Int32 ComputeStepLength()
	{
		UInt64 xofSizeInBytes, diff;
		
		xofSizeInBytes = _xofSizeInBits >> 3;
		diff = xofSizeInBytes - _digestPosition;

		if (xofSizeInBytes == UInt64(UnknownDigestLengthInBytes))
			return Blake2SHashSize;

		return (Int32)min((UInt64)Blake2SHashSize, diff);
	}

	HashLibByteArray GetResult()
	{
		UInt64 xofSizeInBytes = _xofSizeInBits >> 3;
		
		HashLibByteArray result = HashLibByteArray((Int32)xofSizeInBytes);
		
		DoOutput(result, 0, xofSizeInBytes);

		return result;
	}
	
public:
	virtual string GetName() const
	{
		return Utils::string_format("%s_%s_%u", _name.c_str(), "XOFSizeInBytes",
			dynamic_cast<const IIXOF*>(&(*this))->GetXOFSizeInBits() >> 3);
	}

	virtual UInt64 GetXOFSizeInBits() const
	{
		return _xofSizeInBits;
	}

	virtual void SetXOFSizeInBits(const UInt64 value)
	{
		SetXOFSizeInBitsInternal(value);
	}

	virtual void DoOutput(HashLibByteArray& a_destination, const UInt64 a_destinationOffset, const UInt64 a_outputLength)
	{
		UInt64 destinationOffset, outputLength;
		
		if ((UInt64(a_destination.size()) - a_destinationOffset) < a_outputLength)
				throw ArgumentOutOfRangeHashLibException(OutputBufferTooShort);
		
		if ((_xofSizeInBits >> 3) != UnknownDigestLengthInBytes)
		{
			if ((_digestPosition + a_outputLength) > (_xofSizeInBits >> 3))
				throw ArgumentOutOfRangeHashLibException(InvalidOutputLength);
		}
		else if (_digestPosition == UnknownMaxDigestLengthInBytes)
			throw ArgumentOutOfRangeHashLibException(MaximumOutputLengthExceeded);
		
		if (!_finalized)
		{
			Finish();
			_finalized = true;
		}
		
		destinationOffset = a_destinationOffset;
		outputLength = a_outputLength;

		if (_rootHashDigest.empty())
		{
			// Get root digest
			_rootHashDigest.resize(Blake2SHashSize);
			Converters::le32_copy(&_state[0], 0, &_rootHashDigest[0], 0, (Int32)_rootHashDigest.size());
		}	
		
		while (outputLength > 0)
		{
			if ((_digestPosition & Blake2SHashSize - 1) == 0)
			{
				_outputConfig->GetConfig()->SetHashSize(ComputeStepLength());
				_outputConfig->GetTreeConfig()->SetInnerHashSize(Blake2SHashSize);

				_xofBuffer = (Blake2S(_outputConfig->GetConfig(),
					_outputConfig->GetTreeConfig())).ComputeBytes(_rootHashDigest)
					->GetBytes();
				_outputConfig->GetTreeConfig()->SetNodeOffset(
					_outputConfig->GetTreeConfig()->GetNodeOffset() + 1);
			}

			UInt64 blockOffset = _digestPosition & (Blake2SHashSize - 1);

			UInt64 diff = _xofBuffer.size() - blockOffset;

			UInt64 count = min(outputLength, diff);

			memmove(&a_destination[destinationOffset], &_xofBuffer[blockOffset], (size_t)count);

			outputLength -= count;
			destinationOffset += count;
			_digestPosition += count;
		}

	}

	Blake2XS(const IBlake2XSConfig config)
		: Blake2S(CreateConfig(config), CreateTreeConfig(config))
	{
		_name = __func__;

		_xofBuffer.resize(Blake2SHashSize);

		// Create initial config for output hashes.
		IBlake2SConfig tempC = ::move(config->GetConfig());

		if (tempC == nullptr)
			tempC = make_shared<Blake2SConfig>();

		IBlake2SConfig temp = make_shared<Blake2SConfig>();
		temp->SetSalt(tempC->GetSalt());
		temp->SetPersonalization(tempC->GetPersonalization());

		_outputConfig = Blake2XSConfig::CreateBlake2XSConfig(temp, Blake2STreeConfig::GetDefaultTreeConfig());
	}

	virtual void Initialize()
	{
		UInt64 xofSizeInBytes;
		
		xofSizeInBytes = _xofSizeInBits >> 3;

		_treeConfig->SetNodeOffset(
			NodeOffsetWithXOFDigestLength(xofSizeInBytes));

		_outputConfig->GetTreeConfig()->SetNodeOffset(
			NodeOffsetWithXOFDigestLength(xofSizeInBytes));

		_rootHashDigest.clear();
		_digestPosition = 0;
		_finalized = false;
		ArrayUtils::zeroFill(_xofBuffer);

		Blake2S::Initialize();
	}

	Blake2XS Copy() const
	{
		// Xof Cloning
		Blake2XS HashInstance = Blake2XS(make_shared<Blake2XSConfig>(_config, _treeConfig));
		HashInstance.SetXOFSizeInBits(GetXOFSizeInBits());

		// Blake2XS Cloning
		HashInstance._digestPosition = _digestPosition;
		HashInstance._outputConfig = _outputConfig->Clone();
		HashInstance._rootHashDigest = _rootHashDigest;
		HashInstance._xofBuffer = _xofBuffer;
		HashInstance._finalized = _finalized;

		// Internal Blake2S Cloning
		HashInstance._m = _m;
		HashInstance._state = _state;
		HashInstance._buffer = _buffer;

		HashInstance._filledBufferCount = _filledBufferCount;
		HashInstance._counter0 = _counter0;
		HashInstance._counter1 = _counter1;
		HashInstance._finalizationFlag0 = _finalizationFlag0;
		HashInstance._finalizationFlag1 = _finalizationFlag1;

		HashInstance.SetBufferSize(GetBufferSize());

		return HashInstance;
	} //

	virtual IHash Clone() const
	{	
		return make_shared<Blake2XS>(Copy());
	}

	virtual IXOF CloneXOF() const
	{
		return make_shared<Blake2XS>(Copy());
	}

	virtual void TransformBytes(const HashLibByteArray& a_data, const Int32 a_index, const Int32 a_length)
	{
		if (_finalized)
			throw InvalidOperationHashLibException(Utils::string_format(WritetoXofAfterReadError, GetName().c_str()));
		
		Blake2S::TransformBytes(a_data, a_index, a_length);
	}
	
	virtual IHashResult TransformFinal()
	{
		HashLibByteArray buffer = GetResult();
		
		Initialize();

		return make_shared<HashResult>(buffer);
	}

private:
	static IBlake2SConfig CreateConfig(const IBlake2XSConfig config) {
		return config->GetConfig() ? config->GetConfig() : Blake2SConfig::GetDefaultConfig();
	}

	static IBlake2STreeConfig CreateTreeConfig(const IBlake2XSConfig config) {
		return config->GetTreeConfig() ? config->GetTreeConfig() : Blake2STreeConfig::GetSequentialTreeConfig();
	}
	
private:
	UInt64 _digestPosition, _xofSizeInBits;
	IBlake2XSConfig _outputConfig = nullptr;
	HashLibByteArray _rootHashDigest, _xofBuffer;
	bool _finalized;

	static const Int32 Blake2SHashSize = Int32(32);

	// Magic number to indicate an unknown length of digest
	static const UInt16 UnknownDigestLengthInBytes = UInt16((UInt32(1) << 16) - 1); // 65535 bytes
	static const UInt64 MaxNumberBlocks = UInt64(1) << 32;

	// 2^32 blocks of 32 bytes (128GiB)
	// the maximum size in bytes the digest can produce when the length is unknown
	static const UInt64 UnknownMaxDigestLengthInBytes = UInt64(MaxNumberBlocks * UInt64(Blake2SHashSize));

}; // end class Blake2XS
