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

class Blake2B : public Hash, public virtual IICryptoNotBuildIn, public virtual IITransformBlock
{
protected:
	Blake2B CloneInternal() const
	{
		Blake2B result = Blake2B(_config, _treeConfig, _doTransformKeyBlock);
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

public:
	Blake2B() {}

	Blake2B(const IBlake2BConfig a_Config, const IBlake2BTreeConfig a_TreeConfig = nullptr,
		bool a_DoTransformKeyBlock = true)
		: Hash(!a_Config ? throw ArgumentNullHashLibException("config") : a_Config->GetHashSize(), BlockSizeInBytes)
	{
		_name = __func__;

		_config = ::move(a_Config);
		_treeConfig = ::move(a_TreeConfig);
		_doTransformKeyBlock = a_DoTransformKeyBlock;

		_state.resize(8);
		_m.resize(16);
		_buffer.resize(BlockSizeInBytes);
	}

	// Copy constructor
	Blake2B(const Blake2B& blake2)
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

	virtual IHash Clone() const
	{
		return make_shared<Blake2B>(CloneInternal());
	}

	virtual void Initialize()
	{
		Int32 Idx;
		HashLibByteArray Block;
		HashLibUInt64Array RawConfig;

		RawConfig = Blake2BIvBuilder::ConfigB(_config, _treeConfig);

		if (_doTransformKeyBlock)
		{
			if (!_config->GetKey().empty())
			{
				Block.resize(BlockSizeInBytes);
				memmove(&Block[0], &_config->GetKey()[0], _config->GetKey().size() * sizeof(byte));
			}
		}

		if (RawConfig.size() != 8)
			throw ArgumentOutOfRangeHashLibException(Blake2B::InvalidConfigLength);

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

			Blake2BIncrementCounter(BlockSizeInBytes);

			Compress(&_buffer[0], 0);

			offset = offset + bufferRemaining;
			data_length = data_length - bufferRemaining;
			_filledBufferCount = 0;
		}

		while (data_length > BlockSizeInBytes)
		{
			Blake2BIncrementCounter(BlockSizeInBytes);

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

		Converters::le64_copy(&_state[0], 0, &tempRes[0], 0, (Int32)tempRes.size());

		IHashResult result = make_shared<HashResult>(tempRes);

		Initialize();

		return result;
	}

	virtual string GetName() const
	{
		return Utils::string_format("%s_%u", _name.c_str(), GetHashSize() * 8);
	}

	IBlake2BConfig GetConfig() const
	{
		return _config->Clone();
	}

	IBlake2BTreeConfig GetTreeConfig() const
	{
		return _treeConfig ? _treeConfig->Clone() : nullptr;
	}

	IBlake2BConfig GetConfig()
	{
		return _config;
	}

	IBlake2BTreeConfig GetTreeConfig()
	{
		return _treeConfig;
	}

private:
	void Compress(const byte* block, const Int32 start)
	{
		Converters::le64_copy(block, start, &_m[0], 0, GetBlockSize());

		MixScalar();
	} // end function Compress

	void MixScalar()
	{
		UInt64 m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, v0, v1,
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

		// ##### Round(0)
		// G(0, 0, v0, v4, v8, v12)
		v0 = v0 + v4 + m0;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight64(v12, 32);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight64(v4, 24);
		v0 = v0 + v4 + m1;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight64(v12, 16);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight64(v4, 63);

		// G(0, 1, v1, v5, v9, v13)
		v1 = v1 + v5 + m2;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight64(v13, 32);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight64(v5, 24);
		v1 = v1 + v5 + m3;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight64(v13, 16);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight64(v5, 63);

		// G(0, 2, v2, v6, v10, v14)
		v2 = v2 + v6 + m4;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight64(v14, 32);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight64(v6, 24);
		v2 = v2 + v6 + m5;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight64(v14, 16);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight64(v6, 63);

		// G(0, 3, v3, v7, v11, v15)
		v3 = v3 + v7 + m6;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight64(v15, 32);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight64(v7, 24);
		v3 = v3 + v7 + m7;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight64(v15, 16);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight64(v7, 63);

		// G(0, 4, v0, v5, v10, v15)
		v0 = v0 + v5 + m8;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight64(v15, 32);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight64(v5, 24);
		v0 = v0 + v5 + m9;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight64(v15, 16);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight64(v5, 63);

		// G(0, 5, v1, v6, v11, v12)
		v1 = v1 + v6 + m10;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight64(v12, 32);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight64(v6, 24);
		v1 = v1 + v6 + m11;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight64(v12, 16);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight64(v6, 63);

		// G(0, 6, v2, v7, v8, v13)
		v2 = v2 + v7 + m12;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight64(v13, 32);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight64(v7, 24);
		v2 = v2 + v7 + m13;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight64(v13, 16);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight64(v7, 63);

		// G(0, 7, v3, v4, v9, v14)
		v3 = v3 + v4 + m14;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight64(v14, 32);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight64(v4, 24);
		v3 = v3 + v4 + m15;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight64(v14, 16);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight64(v4, 63);

		// ##### Round(1)
		// G(1, 0, v0, v4, v8, v12)
		v0 = v0 + v4 + m14;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight64(v12, 32);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight64(v4, 24);
		v0 = v0 + v4 + m10;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight64(v12, 16);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight64(v4, 63);

		// G(1, 1, v1, v5, v9, v13)
		v1 = v1 + v5 + m4;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight64(v13, 32);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight64(v5, 24);
		v1 = v1 + v5 + m8;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight64(v13, 16);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight64(v5, 63);

		// G(1, 2, v2, v6, v10, v14)
		v2 = v2 + v6 + m9;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight64(v14, 32);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight64(v6, 24);
		v2 = v2 + v6 + m15;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight64(v14, 16);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight64(v6, 63);

		// G(1, 3, v3, v7, v11, v15)
		v3 = v3 + v7 + m13;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight64(v15, 32);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight64(v7, 24);
		v3 = v3 + v7 + m6;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight64(v15, 16);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight64(v7, 63);

		// G(1, 4, v0, v5, v10, v15)
		v0 = v0 + v5 + m1;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight64(v15, 32);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight64(v5, 24);
		v0 = v0 + v5 + m12;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight64(v15, 16);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight64(v5, 63);

		// G(1, 5, v1, v6, v11, v12)
		v1 = v1 + v6 + m0;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight64(v12, 32);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight64(v6, 24);
		v1 = v1 + v6 + m2;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight64(v12, 16);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight64(v6, 63);

		// G(1, 6, v2, v7, v8, v13)
		v2 = v2 + v7 + m11;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight64(v13, 32);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight64(v7, 24);
		v2 = v2 + v7 + m7;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight64(v13, 16);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight64(v7, 63);

		// G(1, 7, v3, v4, v9, v14)
		v3 = v3 + v4 + m5;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight64(v14, 32);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight64(v4, 24);
		v3 = v3 + v4 + m3;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight64(v14, 16);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight64(v4, 63);

		// ##### Round(2)
		// G(2, 0, v0, v4, v8, v12)
		v0 = v0 + v4 + m11;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight64(v12, 32);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight64(v4, 24);
		v0 = v0 + v4 + m8;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight64(v12, 16);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight64(v4, 63);

		// G(2, 1, v1, v5, v9, v13)
		v1 = v1 + v5 + m12;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight64(v13, 32);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight64(v5, 24);
		v1 = v1 + v5 + m0;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight64(v13, 16);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight64(v5, 63);

		// G(2, 2, v2, v6, v10, v14)
		v2 = v2 + v6 + m5;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight64(v14, 32);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight64(v6, 24);
		v2 = v2 + v6 + m2;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight64(v14, 16);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight64(v6, 63);

		// G(2, 3, v3, v7, v11, v15)
		v3 = v3 + v7 + m15;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight64(v15, 32);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight64(v7, 24);
		v3 = v3 + v7 + m13;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight64(v15, 16);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight64(v7, 63);

		// G(2, 4, v0, v5, v10, v15)
		v0 = v0 + v5 + m10;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight64(v15, 32);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight64(v5, 24);
		v0 = v0 + v5 + m14;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight64(v15, 16);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight64(v5, 63);

		// G(2, 5, v1, v6, v11, v12)
		v1 = v1 + v6 + m3;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight64(v12, 32);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight64(v6, 24);
		v1 = v1 + v6 + m6;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight64(v12, 16);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight64(v6, 63);

		// G(2, 6, v2, v7, v8, v13)
		v2 = v2 + v7 + m7;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight64(v13, 32);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight64(v7, 24);
		v2 = v2 + v7 + m1;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight64(v13, 16);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight64(v7, 63);

		// G(2, 7, v3, v4, v9, v14)
		v3 = v3 + v4 + m9;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight64(v14, 32);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight64(v4, 24);
		v3 = v3 + v4 + m4;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight64(v14, 16);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight64(v4, 63);

		// ##### Round(3)
		// G(3, 0, v0, v4, v8, v12)
		v0 = v0 + v4 + m7;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight64(v12, 32);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight64(v4, 24);
		v0 = v0 + v4 + m9;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight64(v12, 16);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight64(v4, 63);

		// G(3, 1, v1, v5, v9, v13)
		v1 = v1 + v5 + m3;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight64(v13, 32);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight64(v5, 24);
		v1 = v1 + v5 + m1;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight64(v13, 16);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight64(v5, 63);

		// G(3, 2, v2, v6, v10, v14)
		v2 = v2 + v6 + m13;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight64(v14, 32);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight64(v6, 24);
		v2 = v2 + v6 + m12;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight64(v14, 16);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight64(v6, 63);

		// G(3, 3, v3, v7, v11, v15)
		v3 = v3 + v7 + m11;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight64(v15, 32);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight64(v7, 24);
		v3 = v3 + v7 + m14;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight64(v15, 16);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight64(v7, 63);

		// G(3, 4, v0, v5, v10, v15)
		v0 = v0 + v5 + m2;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight64(v15, 32);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight64(v5, 24);
		v0 = v0 + v5 + m6;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight64(v15, 16);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight64(v5, 63);

		// G(3, 5, v1, v6, v11, v12)
		v1 = v1 + v6 + m5;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight64(v12, 32);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight64(v6, 24);
		v1 = v1 + v6 + m10;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight64(v12, 16);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight64(v6, 63);

		// G(3, 6, v2, v7, v8, v13)
		v2 = v2 + v7 + m4;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight64(v13, 32);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight64(v7, 24);
		v2 = v2 + v7 + m0;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight64(v13, 16);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight64(v7, 63);

		// G(3, 7, v3, v4, v9, v14)
		v3 = v3 + v4 + m15;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight64(v14, 32);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight64(v4, 24);
		v3 = v3 + v4 + m8;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight64(v14, 16);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight64(v4, 63);

		// ##### Round(4)
		// G(4, 0, v0, v4, v8, v12)
		v0 = v0 + v4 + m9;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight64(v12, 32);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight64(v4, 24);
		v0 = v0 + v4 + m0;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight64(v12, 16);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight64(v4, 63);

		// G(4, 1, v1, v5, v9, v13)
		v1 = v1 + v5 + m5;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight64(v13, 32);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight64(v5, 24);
		v1 = v1 + v5 + m7;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight64(v13, 16);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight64(v5, 63);

		// G(4, 2, v2, v6, v10, v14)
		v2 = v2 + v6 + m2;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight64(v14, 32);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight64(v6, 24);
		v2 = v2 + v6 + m4;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight64(v14, 16);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight64(v6, 63);

		// G(4, 3, v3, v7, v11, v15)
		v3 = v3 + v7 + m10;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight64(v15, 32);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight64(v7, 24);
		v3 = v3 + v7 + m15;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight64(v15, 16);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight64(v7, 63);

		// G(4, 4, v0, v5, v10, v15)
		v0 = v0 + v5 + m14;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight64(v15, 32);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight64(v5, 24);
		v0 = v0 + v5 + m1;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight64(v15, 16);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight64(v5, 63);

		// G(4, 5, v1, v6, v11, v12)
		v1 = v1 + v6 + m11;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight64(v12, 32);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight64(v6, 24);
		v1 = v1 + v6 + m12;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight64(v12, 16);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight64(v6, 63);

		// G(4, 6, v2, v7, v8, v13)
		v2 = v2 + v7 + m6;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight64(v13, 32);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight64(v7, 24);
		v2 = v2 + v7 + m8;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight64(v13, 16);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight64(v7, 63);

		// G(4, 7, v3, v4, v9, v14)
		v3 = v3 + v4 + m3;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight64(v14, 32);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight64(v4, 24);
		v3 = v3 + v4 + m13;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight64(v14, 16);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight64(v4, 63);

		// ##### Round(5)
		// G(5, 0, v0, v4, v8, v12)
		v0 = v0 + v4 + m2;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight64(v12, 32);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight64(v4, 24);
		v0 = v0 + v4 + m12;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight64(v12, 16);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight64(v4, 63);

		// G(5, 1, v1, v5, v9, v13)
		v1 = v1 + v5 + m6;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight64(v13, 32);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight64(v5, 24);
		v1 = v1 + v5 + m10;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight64(v13, 16);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight64(v5, 63);

		// G(5, 2, v2, v6, v10, v14)
		v2 = v2 + v6 + m0;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight64(v14, 32);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight64(v6, 24);
		v2 = v2 + v6 + m11;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight64(v14, 16);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight64(v6, 63);

		// G(5, 3, v3, v7, v11, v15)
		v3 = v3 + v7 + m8;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight64(v15, 32);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight64(v7, 24);
		v3 = v3 + v7 + m3;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight64(v15, 16);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight64(v7, 63);

		// G(5, 4, v0, v5, v10, v15)
		v0 = v0 + v5 + m4;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight64(v15, 32);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight64(v5, 24);
		v0 = v0 + v5 + m13;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight64(v15, 16);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight64(v5, 63);

		// G(5, 5, v1, v6, v11, v12)
		v1 = v1 + v6 + m7;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight64(v12, 32);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight64(v6, 24);
		v1 = v1 + v6 + m5;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight64(v12, 16);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight64(v6, 63);

		// G(5, 6, v2, v7, v8, v13)
		v2 = v2 + v7 + m15;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight64(v13, 32);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight64(v7, 24);
		v2 = v2 + v7 + m14;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight64(v13, 16);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight64(v7, 63);

		// G(5, 7, v3, v4, v9, v14)
		v3 = v3 + v4 + m1;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight64(v14, 32);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight64(v4, 24);
		v3 = v3 + v4 + m9;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight64(v14, 16);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight64(v4, 63);

		// ##### Round(6)
		// G(6, 0, v0, v4, v8, v12)
		v0 = v0 + v4 + m12;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight64(v12, 32);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight64(v4, 24);
		v0 = v0 + v4 + m5;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight64(v12, 16);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight64(v4, 63);

		// G(6, 1, v1, v5, v9, v13)
		v1 = v1 + v5 + m1;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight64(v13, 32);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight64(v5, 24);
		v1 = v1 + v5 + m15;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight64(v13, 16);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight64(v5, 63);

		// G(6, 2, v2, v6, v10, v14)
		v2 = v2 + v6 + m14;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight64(v14, 32);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight64(v6, 24);
		v2 = v2 + v6 + m13;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight64(v14, 16);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight64(v6, 63);

		// G(6, 3, v3, v7, v11, v15)
		v3 = v3 + v7 + m4;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight64(v15, 32);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight64(v7, 24);
		v3 = v3 + v7 + m10;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight64(v15, 16);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight64(v7, 63);

		// G(6, 4, v0, v5, v10, v15)
		v0 = v0 + v5 + m0;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight64(v15, 32);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight64(v5, 24);
		v0 = v0 + v5 + m7;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight64(v15, 16);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight64(v5, 63);

		// G(6, 5, v1, v6, v11, v12)
		v1 = v1 + v6 + m6;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight64(v12, 32);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight64(v6, 24);
		v1 = v1 + v6 + m3;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight64(v12, 16);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight64(v6, 63);

		// G(6, 6, v2, v7, v8, v13)
		v2 = v2 + v7 + m9;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight64(v13, 32);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight64(v7, 24);
		v2 = v2 + v7 + m2;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight64(v13, 16);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight64(v7, 63);

		// G(6, 7, v3, v4, v9, v14)
		v3 = v3 + v4 + m8;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight64(v14, 32);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight64(v4, 24);
		v3 = v3 + v4 + m11;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight64(v14, 16);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight64(v4, 63);

		// ##### Round(7)
		// G(7, 0, v0, v4, v8, v12)
		v0 = v0 + v4 + m13;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight64(v12, 32);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight64(v4, 24);
		v0 = v0 + v4 + m11;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight64(v12, 16);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight64(v4, 63);

		// G(7, 1, v1, v5, v9, v13)
		v1 = v1 + v5 + m7;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight64(v13, 32);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight64(v5, 24);
		v1 = v1 + v5 + m14;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight64(v13, 16);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight64(v5, 63);

		// G(7, 2, v2, v6, v10, v14)
		v2 = v2 + v6 + m12;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight64(v14, 32);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight64(v6, 24);
		v2 = v2 + v6 + m1;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight64(v14, 16);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight64(v6, 63);

		// G(7, 3, v3, v7, v11, v15)
		v3 = v3 + v7 + m3;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight64(v15, 32);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight64(v7, 24);
		v3 = v3 + v7 + m9;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight64(v15, 16);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight64(v7, 63);

		// G(7, 4, v0, v5, v10, v15)
		v0 = v0 + v5 + m5;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight64(v15, 32);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight64(v5, 24);
		v0 = v0 + v5 + m0;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight64(v15, 16);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight64(v5, 63);

		// G(7, 5, v1, v6, v11, v12)
		v1 = v1 + v6 + m15;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight64(v12, 32);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight64(v6, 24);
		v1 = v1 + v6 + m4;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight64(v12, 16);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight64(v6, 63);

		// G(7, 6, v2, v7, v8, v13)
		v2 = v2 + v7 + m8;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight64(v13, 32);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight64(v7, 24);
		v2 = v2 + v7 + m6;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight64(v13, 16);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight64(v7, 63);

		// G(7, 7, v3, v4, v9, v14)
		v3 = v3 + v4 + m2;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight64(v14, 32);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight64(v4, 24);
		v3 = v3 + v4 + m10;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight64(v14, 16);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight64(v4, 63);

		// ##### Round(8)
		// G(8, 0, v0, v4, v8, v12)
		v0 = v0 + v4 + m6;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight64(v12, 32);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight64(v4, 24);
		v0 = v0 + v4 + m15;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight64(v12, 16);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight64(v4, 63);

		// G(8, 1, v1, v5, v9, v13)
		v1 = v1 + v5 + m14;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight64(v13, 32);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight64(v5, 24);
		v1 = v1 + v5 + m9;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight64(v13, 16);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight64(v5, 63);

		// G(8, 2, v2, v6, v10, v14)
		v2 = v2 + v6 + m11;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight64(v14, 32);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight64(v6, 24);
		v2 = v2 + v6 + m3;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight64(v14, 16);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight64(v6, 63);

		// G(8, 3, v3, v7, v11, v15)
		v3 = v3 + v7 + m0;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight64(v15, 32);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight64(v7, 24);
		v3 = v3 + v7 + m8;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight64(v15, 16);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight64(v7, 63);

		// G(8, 4, v0, v5, v10, v15)
		v0 = v0 + v5 + m12;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight64(v15, 32);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight64(v5, 24);
		v0 = v0 + v5 + m2;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight64(v15, 16);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight64(v5, 63);

		// G(8, 5, v1, v6, v11, v12)
		v1 = v1 + v6 + m13;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight64(v12, 32);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight64(v6, 24);
		v1 = v1 + v6 + m7;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight64(v12, 16);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight64(v6, 63);

		// G(8, 6, v2, v7, v8, v13)
		v2 = v2 + v7 + m1;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight64(v13, 32);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight64(v7, 24);
		v2 = v2 + v7 + m4;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight64(v13, 16);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight64(v7, 63);

		// G(8, 7, v3, v4, v9, v14)
		v3 = v3 + v4 + m10;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight64(v14, 32);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight64(v4, 24);
		v3 = v3 + v4 + m5;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight64(v14, 16);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight64(v4, 63);

		// ##### Round(9)
		// G(9, 0, v0, v4, v8, v12)
		v0 = v0 + v4 + m10;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight64(v12, 32);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight64(v4, 24);
		v0 = v0 + v4 + m2;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight64(v12, 16);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight64(v4, 63);

		// G(9, 1, v1, v5, v9, v13)
		v1 = v1 + v5 + m8;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight64(v13, 32);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight64(v5, 24);
		v1 = v1 + v5 + m4;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight64(v13, 16);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight64(v5, 63);

		// G(9, 2, v2, v6, v10, v14)
		v2 = v2 + v6 + m7;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight64(v14, 32);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight64(v6, 24);
		v2 = v2 + v6 + m6;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight64(v14, 16);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight64(v6, 63);

		// G(9, 3, v3, v7, v11, v15)
		v3 = v3 + v7 + m1;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight64(v15, 32);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight64(v7, 24);
		v3 = v3 + v7 + m5;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight64(v15, 16);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight64(v7, 63);

		// G(9, 4, v0, v5, v10, v15)
		v0 = v0 + v5 + m15;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight64(v15, 32);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight64(v5, 24);
		v0 = v0 + v5 + m11;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight64(v15, 16);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight64(v5, 63);

		// G(9, 5, v1, v6, v11, v12)
		v1 = v1 + v6 + m9;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight64(v12, 32);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight64(v6, 24);
		v1 = v1 + v6 + m14;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight64(v12, 16);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight64(v6, 63);

		// G(9, 6, v2, v7, v8, v13)
		v2 = v2 + v7 + m3;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight64(v13, 32);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight64(v7, 24);
		v2 = v2 + v7 + m12;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight64(v13, 16);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight64(v7, 63);

		// G(9, 7, v3, v4, v9, v14)
		v3 = v3 + v4 + m13;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight64(v14, 32);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight64(v4, 24);
		v3 = v3 + v4 + m0;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight64(v14, 16);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight64(v4, 63);

		// ##### Round(10)
		// G(10, 0, v0, v4, v8, v12)
		v0 = v0 + v4 + m0;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight64(v12, 32);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight64(v4, 24);
		v0 = v0 + v4 + m1;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight64(v12, 16);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight64(v4, 63);

		// G(10, 1, v1, v5, v9, v13)
		v1 = v1 + v5 + m2;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight64(v13, 32);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight64(v5, 24);
		v1 = v1 + v5 + m3;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight64(v13, 16);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight64(v5, 63);

		// G(10, 2, v2, v6, v10, v14)
		v2 = v2 + v6 + m4;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight64(v14, 32);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight64(v6, 24);
		v2 = v2 + v6 + m5;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight64(v14, 16);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight64(v6, 63);

		// G(10, 3, v3, v7, v11, v15)
		v3 = v3 + v7 + m6;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight64(v15, 32);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight64(v7, 24);
		v3 = v3 + v7 + m7;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight64(v15, 16);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight64(v7, 63);

		// G(10, 4, v0, v5, v10, v15)
		v0 = v0 + v5 + m8;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight64(v15, 32);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight64(v5, 24);
		v0 = v0 + v5 + m9;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight64(v15, 16);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight64(v5, 63);

		// G(10, 5, v1, v6, v11, v12)
		v1 = v1 + v6 + m10;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight64(v12, 32);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight64(v6, 24);
		v1 = v1 + v6 + m11;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight64(v12, 16);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight64(v6, 63);

		// G(10, 6, v2, v7, v8, v13)
		v2 = v2 + v7 + m12;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight64(v13, 32);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight64(v7, 24);
		v2 = v2 + v7 + m13;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight64(v13, 16);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight64(v7, 63);

		// G(10, 7, v3, v4, v9, v14)
		v3 = v3 + v4 + m14;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight64(v14, 32);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight64(v4, 24);
		v3 = v3 + v4 + m15;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight64(v14, 16);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight64(v4, 63);

		// ##### Round(11)
		// G(11, 0, v0, v4, v8, v12)
		v0 = v0 + v4 + m14;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight64(v12, 32);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight64(v4, 24);
		v0 = v0 + v4 + m10;
		v12 = v12 ^ v0;
		v12 = Bits::RotateRight64(v12, 16);
		v8 = v8 + v12;
		v4 = v4 ^ v8;
		v4 = Bits::RotateRight64(v4, 63);

		// G(11, 1, v1, v5, v9, v13)
		v1 = v1 + v5 + m4;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight64(v13, 32);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight64(v5, 24);
		v1 = v1 + v5 + m8;
		v13 = v13 ^ v1;
		v13 = Bits::RotateRight64(v13, 16);
		v9 = v9 + v13;
		v5 = v5 ^ v9;
		v5 = Bits::RotateRight64(v5, 63);

		// G(11, 2, v2, v6, v10, v14)
		v2 = v2 + v6 + m9;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight64(v14, 32);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight64(v6, 24);
		v2 = v2 + v6 + m15;
		v14 = v14 ^ v2;
		v14 = Bits::RotateRight64(v14, 16);
		v10 = v10 + v14;
		v6 = v6 ^ v10;
		v6 = Bits::RotateRight64(v6, 63);

		// G(11, 3, v3, v7, v11, v15)
		v3 = v3 + v7 + m13;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight64(v15, 32);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight64(v7, 24);
		v3 = v3 + v7 + m6;
		v15 = v15 ^ v3;
		v15 = Bits::RotateRight64(v15, 16);
		v11 = v11 + v15;
		v7 = v7 ^ v11;
		v7 = Bits::RotateRight64(v7, 63);

		// G(11, 4, v0, v5, v10, v15)
		v0 = v0 + v5 + m1;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight64(v15, 32);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight64(v5, 24);
		v0 = v0 + v5 + m12;
		v15 = v15 ^ v0;
		v15 = Bits::RotateRight64(v15, 16);
		v10 = v10 + v15;
		v5 = v5 ^ v10;
		v5 = Bits::RotateRight64(v5, 63);

		// G(11, 5, v1, v6, v11, v12)
		v1 = v1 + v6 + m0;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight64(v12, 32);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight64(v6, 24);
		v1 = v1 + v6 + m2;
		v12 = v12 ^ v1;
		v12 = Bits::RotateRight64(v12, 16);
		v11 = v11 + v12;
		v6 = v6 ^ v11;
		v6 = Bits::RotateRight64(v6, 63);

		// G(11, 6, v2, v7, v8, v13)
		v2 = v2 + v7 + m11;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight64(v13, 32);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight64(v7, 24);
		v2 = v2 + v7 + m7;
		v13 = v13 ^ v2;
		v13 = Bits::RotateRight64(v13, 16);
		v8 = v8 + v13;
		v7 = v7 ^ v8;
		v7 = Bits::RotateRight64(v7, 63);

		// G(11, 7, v3, v4, v9, v14)
		v3 = v3 + v4 + m5;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight64(v14, 32);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight64(v4, 24);
		v3 = v3 + v4 + m3;
		v14 = v14 ^ v3;
		v14 = Bits::RotateRight64(v14, 16);
		v9 = v9 + v14;
		v4 = v4 ^ v9;
		v4 = Bits::RotateRight64(v4, 63);

		// Finalization
		_state[0] = _state[0] ^ v0 ^ v8;
		_state[1] = _state[1] ^ v1 ^ v9;
		_state[2] = _state[2] ^ v2 ^ v10;
		_state[3] = _state[3] ^ v3 ^ v11;
		_state[4] = _state[4] ^ v4 ^ v12;
		_state[5] = _state[5] ^ v5 ^ v13;
		_state[6] = _state[6] ^ v6 ^ v14;
		_state[7] = _state[7] ^ v7 ^ v15;
	}

	void Blake2BIncrementCounter(const UInt64 incrementCount)
	{
		_counter0 += incrementCount;
		_counter1 += UInt64(_counter0 < incrementCount);
	}

protected:
	inline void Finish()
	{
		Int32 count;

		// Last compression
		Blake2BIncrementCounter(UInt64(_filledBufferCount));

		_finalizationFlag0 = UINT64_MAX;

		if (_treeConfig != nullptr && _treeConfig->GetIsLastNode())
			_finalizationFlag1 = UINT64_MAX;

		count = (Int32)_buffer.size() - _filledBufferCount;

		if (count > 0)
			ArrayUtils::fill(_buffer, _filledBufferCount, count + _filledBufferCount, byte(0));

		Compress(&_buffer[0], 0);
	}


	HashLibUInt64Array _state, _m;
	HashLibByteArray _buffer;

	Int32 _filledBufferCount = 0;
	UInt64 _counter0 = 0, _counter1 = 0, _finalizationFlag0 = 0, _finalizationFlag1 = 0;

	IBlake2BConfig _config = nullptr;
	IBlake2BTreeConfig _treeConfig = nullptr;

private:
	bool _doTransformKeyBlock = false;

	static const Int32 BlockSizeInBytes = Int32(128);

	static const UInt64 IV0 = UInt64(0x6A09E667F3BCC908);
	static const UInt64 IV1 = UInt64(0xBB67AE8584CAA73B);
	static const UInt64 IV2 = UInt64(0x3C6EF372FE94F82B);
	static const UInt64 IV3 = UInt64(0xA54FF53A5F1D36F1);
	static const UInt64 IV4 = UInt64(0x510E527FADE682D1);
	static const UInt64 IV5 = UInt64(0x9B05688C2B3E6C1F);
	static const UInt64 IV6 = UInt64(0x1F83D9ABFB41BD6B);
	static const UInt64 IV7 = UInt64(0x5BE0CD19137E2179);

protected:
	static const char* InvalidConfigLength;

}; // end class Blake2B

class Blake2XB : public Blake2B, public virtual IIXOF
{
private:
	void SetXOFSizeInBitsInternal(const UInt64 a_XofSizeInBits)
	{
		UInt64 xofSizeInBytes;

		xofSizeInBytes = a_XofSizeInBits >> 3;
		if ((a_XofSizeInBits & 0x7) != 0 || xofSizeInBytes < 1 ||
			xofSizeInBytes > UInt64(UnknownDigestLengthInBytes))
			throw ArgumentOutOfRangeHashLibException(
				Utils::string_format(Blake2XB::InvalidXofSize, 1, UInt64(UnknownDigestLengthInBytes)));

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
			return Blake2BHashSize;
		
		return (Int32)min((UInt64)Blake2BHashSize, diff);
	}

	HashLibByteArray GetResult()
	{
		UInt64 xofSizeInBytes = _xofSizeInBits >> 3;

		HashLibByteArray result = HashLibByteArray((Int32)xofSizeInBytes);

		DoOutput(result, 0, xofSizeInBytes);

		return result;
	}

public:
	Blake2XB(const IBlake2XBConfig& config)
		: Blake2B(CreateConfig(config), CreateTreeConfig(config))
	{
		_name = __func__;
		
		_xofBuffer.resize(Blake2BHashSize);

		// Create initial config for output hashes.
		IBlake2BConfig tempC = ::move(config->GetConfig());

		if (tempC == nullptr)
			tempC = make_shared<Blake2BConfig>();

		IBlake2BConfig temp = make_shared<Blake2BConfig>();
		temp->SetSalt(tempC->GetSalt());
		temp->SetPersonalization(tempC->GetPersonalization());

		_outputConfig = Blake2XBConfig::CreateBlake2XBConfig(temp, Blake2BTreeConfig::GetDefaultTreeConfig());
	}

	virtual string GetName() const
	{
		return Utils::string_format("%s_%s_%u", _name.c_str(), "XOFSizeInBytes",
			dynamic_cast<const IIXOF*>(&(*this))->GetXOFSizeInBits() >> 3);
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

		Blake2B::Initialize();
	}

	Blake2XB Copy() const
	{
		// Xof Cloning
		Blake2XB HashInstance = Blake2XB(make_shared<Blake2XBConfig>(_config, _treeConfig));
		HashInstance.SetXOFSizeInBits(GetXOFSizeInBits());

		// Blake2XB Cloning
		HashInstance._digestPosition = _digestPosition;
		HashInstance._outputConfig = _outputConfig->Clone();
		HashInstance._rootHashDigest = _rootHashDigest;
		HashInstance._xofBuffer = _xofBuffer;
		HashInstance._finalized = _finalized;

		// Internal Blake2B Cloning
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
		return make_shared<Blake2XB>(Copy());
	}

	virtual IXOF CloneXOF() const
	{
		return make_shared<Blake2XB>(Copy());
	}

	virtual void TransformBytes(const HashLibByteArray& a_data, const Int32 a_index, const Int32 a_length)
	{
		if (_finalized)
			throw InvalidOperationHashLibException(Utils::string_format(Blake2XB::WritetoXofAfterReadError, GetName().c_str()));

		Blake2B::TransformBytes(a_data, a_index, a_length);
	}

	virtual IHashResult TransformFinal()
	{
		HashLibByteArray buffer = GetResult();

		Initialize();

		return make_shared<HashResult>(buffer);
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

		if (UInt64(a_destination.size()) - a_destinationOffset < a_outputLength)
			throw ArgumentOutOfRangeHashLibException(Blake2XB::OutputBufferTooShort);

		if (_xofSizeInBits >> 3 != UnknownDigestLengthInBytes)
		{
			if (_digestPosition + a_outputLength > _xofSizeInBits >> 3)
				throw ArgumentOutOfRangeHashLibException(Blake2XB::InvalidOutputLength);
		}
		else if (_digestPosition << 5 == UnknownMaxDigestLengthInBytes)
			throw ArgumentOutOfRangeHashLibException(Blake2XB::MaximumOutputLengthExceeded);

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
			_rootHashDigest.resize(Blake2BHashSize);
			Converters::le64_copy(&_state[0], 0, &_rootHashDigest[0], 0, (Int32)_rootHashDigest.size());
		}

		while (outputLength > 0)
		{
			if ((_digestPosition & UInt64(Blake2BHashSize - 1)) == 0)
			{
				_outputConfig->GetConfig()->SetHashSize(ComputeStepLength());
				_outputConfig->GetTreeConfig()->SetInnerHashSize(Blake2BHashSize);

				_xofBuffer = (Blake2B(_outputConfig->GetConfig(),
					_outputConfig->GetTreeConfig())).ComputeBytes(_rootHashDigest)
					->GetBytes();
				_outputConfig->GetTreeConfig()->SetNodeOffset(
					_outputConfig->GetTreeConfig()->GetNodeOffset() + 1);
			}

			UInt64 blockOffset = _digestPosition & (Blake2BHashSize - 1);

			UInt64 diff = _xofBuffer.size() - blockOffset;

			UInt64 count = min(outputLength, diff);

			memmove(&a_destination[destinationOffset], &_xofBuffer[blockOffset], (size_t)count);
			
			outputLength -= count;
			destinationOffset += count;
			_digestPosition += count;
		}

	}

private:
	static IBlake2BConfig CreateConfig(const IBlake2XBConfig &config) {
		return config->GetConfig() ? config->GetConfig() : Blake2BConfig::GetDefaultConfig();
	}

	static IBlake2BTreeConfig CreateTreeConfig(const IBlake2XBConfig &config) {
		return config->GetTreeConfig() ? config->GetTreeConfig() : Blake2BTreeConfig::GetSequentialTreeConfig();
	}

protected:	
	static const char* InvalidXofSize;
	static const char* InvalidOutputLength;
	static const char* OutputBufferTooShort;
	static const char* MaximumOutputLengthExceeded;
	static const char* WritetoXofAfterReadError;

private:
	UInt64 _xofSizeInBits, _digestPosition;
	IBlake2XBConfig _outputConfig = nullptr;
	HashLibByteArray _rootHashDigest, _xofBuffer;
	bool _finalized;

	static const Int32 Blake2BHashSize = Int32(64);

	// Magic number to indicate an unknown length of digest
	static const UInt32 UnknownDigestLengthInBytes = UInt32((UInt64(1) << 32) - 1); // 65535 bytes
	static const UInt64 MaxNumberBlocks = UInt64(1) << 32;

	// 2^32 blocks of 32 bytes (128GiB)
	// the maximum size in bytes the digest can produce when the length is unknown
	static const UInt64 UnknownMaxDigestLengthInBytes = MaxNumberBlocks * UInt64(Blake2BHashSize);

}; // end class Blake2XB
