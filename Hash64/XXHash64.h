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

#include "../Base/Hash.h"
#include "../Nullable/Nullable.h"
#include "../Interfaces/IHashInfo.h"

class XXHash64 : public Hash, public virtual IIBlockHash, public virtual IIHash64, 
	public virtual IIHashWithKey, public virtual IITransformBlock
{
public:
	XXHash64()
		: Hash(8, 32)
	{
		_name = __func__;

		_key = CKEY;
		_state.memory.resize(32);
	} // end constructor
	
	virtual IHash Clone() const
	{
		IHash _hash = make_shared<XXHash64>(Copy());
		_hash->SetBufferSize(GetBufferSize());
		return _hash;
	}

	virtual IHashWithKey CloneHashWithKey() const
	{
		IHashWithKey _hash = make_shared<XXHash64>(Copy());
		_hash->SetBufferSize(GetBufferSize());
		return _hash;
	}
	
	virtual void Initialize() override
	{
		_hash = 0;
		_state.v1 = _key + PRIME64_1 + PRIME64_2;
		_state.v2 = _key + PRIME64_2;
		_state.v3 = _key + 0;
		_state.v4 = _key - PRIME64_1;
		_state.total_len = 0;
		_state.memsize = 0;
	} // end function Initialize

	virtual void TransformBytes(const HashLibByteArray& a_data, const Int32 a_index, const Int32 a_length) override
	{
		UInt64 _v1, _v2, _v3, _v4;
		byte* ptrTemp, * ptrMemory;
		const byte* ptrAData;

		if (a_data.empty()) return;

		_state.total_len = _state.total_len + (UInt64)a_length;

		ptrMemory = &_state.memory[0];
		ptrAData = (const byte*)&a_data[0];

		const byte* ptrBuffer = ptrAData + a_index;

		if ((_state.memsize + (UInt32)a_length) < (UInt32)32)
		{
			ptrTemp = ptrMemory + _state.memsize;

			memmove(ptrTemp, ptrBuffer, a_length);

			_state.memsize = _state.memsize + (UInt32)a_length;

			return;
		} // end if

		const byte* ptrEnd = ptrBuffer + (UInt32)a_length;

		if (_state.memsize > 0)
		{
			ptrTemp = ptrMemory + _state.memsize;

			memmove(ptrTemp, ptrBuffer, (Int32)(32 - _state.memsize));

			_state.v1 = PRIME64_1 * Bits::RotateLeft64(_state.v1 + PRIME64_2 * Converters::ReadBytesAsUInt64LE(ptrMemory, 0), 31);
			_state.v2 = PRIME64_1 * Bits::RotateLeft64(_state.v2 + PRIME64_2 * Converters::ReadBytesAsUInt64LE(ptrMemory, 8), 31);
			_state.v3 = PRIME64_1 * Bits::RotateLeft64(_state.v3 + PRIME64_2 * Converters::ReadBytesAsUInt64LE(ptrMemory, 16), 31);
			_state.v4 = PRIME64_1 * Bits::RotateLeft64(_state.v4 + PRIME64_2 * Converters::ReadBytesAsUInt64LE(ptrMemory, 24), 31);

			ptrBuffer = ptrBuffer + (32 - _state.memsize);
			_state.memsize = 0;
		} // end if

		if (ptrBuffer <= (ptrEnd - 32))
		{
			_v1 = _state.v1;
			_v2 = _state.v2;
			_v3 = _state.v3;
			_v4 = _state.v4;

			const byte* ptrLimit = ptrEnd - 32;

			do
			{
				_v1 = PRIME64_1 * Bits::RotateLeft64(_v1 + PRIME64_2 * Converters::ReadBytesAsUInt64LE(ptrBuffer, 0), 31);
				_v2 = PRIME64_1 * Bits::RotateLeft64(_v2 + PRIME64_2 * Converters::ReadBytesAsUInt64LE(ptrBuffer, 8), 31);
				_v3 = PRIME64_1 * Bits::RotateLeft64(_v3 + PRIME64_2 * Converters::ReadBytesAsUInt64LE(ptrBuffer, 16), 31);
				_v4 = PRIME64_1 * Bits::RotateLeft64(_v4 + PRIME64_2 * Converters::ReadBytesAsUInt64LE(ptrBuffer, 24), 31);
				ptrBuffer += 32;
			} while (ptrBuffer <= ptrLimit);

			_state.v1 = _v1;
			_state.v2 = _v2;
			_state.v3 = _v3;
			_state.v4 = _v4;
		} // end if

		if (ptrBuffer < ptrEnd)
		{
			memmove(ptrMemory, ptrBuffer, (Int32)(ptrEnd - ptrBuffer));
			_state.memsize = (UInt32)(ptrEnd - ptrBuffer);
		} // end if
		
	} // end function TransformBytes

	virtual IHashResult TransformFinal() override
	{
		UInt64 _v1, _v2, _v3, _v4;
		byte* ptrEnd, *ptrBuffer, *bPtr;

		bPtr = &_state.memory[0];

		if (_state.total_len >= (UInt64)32)
		{
			_v1 = _state.v1;
			_v2 = _state.v2;
			_v3 = _state.v3;
			_v4 = _state.v4;

			_hash = Bits::RotateLeft64(_v1, 1) + Bits::RotateLeft64(_v2, 7) + Bits::RotateLeft64(_v3, 12) + Bits::RotateLeft64(_v4, 18);

			_v1 = Bits::RotateLeft64(_v1 * PRIME64_2, 31) * PRIME64_1;
			_hash = (_hash ^ _v1) * PRIME64_1 + PRIME64_4;

			_v2 = Bits::RotateLeft64(_v2 * PRIME64_2, 31) * PRIME64_1;
			_hash = (_hash ^ _v2) * PRIME64_1 + PRIME64_4;

			_v3 = Bits::RotateLeft64(_v3 * PRIME64_2, 31) * PRIME64_1;
			_hash = (_hash ^ _v3) * PRIME64_1 + PRIME64_4;

			_v4 = Bits::RotateLeft64(_v4 * PRIME64_2, 31) * PRIME64_1;
			_hash = (_hash ^ _v4) * PRIME64_1 + PRIME64_4;
		} // end if
		else
			_hash = _key + PRIME64_5;

		_hash += _state.total_len;

		ptrBuffer = bPtr;

		ptrEnd = ptrBuffer + _state.memsize;
		while ((ptrBuffer + 8) <= ptrEnd)
		{
			_hash = _hash ^ (PRIME64_1 * Bits::RotateLeft64(PRIME64_2 * Converters::ReadBytesAsUInt64LE(ptrBuffer, 0), 31));
			_hash = Bits::RotateLeft64(_hash, 27) * PRIME64_1 + PRIME64_4;
			ptrBuffer += 8;
		} // end while

		if ((ptrBuffer + 4) <= ptrEnd)
		{
			_hash = _hash ^ Converters::ReadBytesAsUInt32LE(ptrBuffer, 0) * PRIME64_1;
			_hash = Bits::RotateLeft64(_hash, 23) * PRIME64_2 + PRIME64_3;
			ptrBuffer += 4;
		} // end if

		while (ptrBuffer < ptrEnd)
		{
			_hash = _hash ^ (*ptrBuffer) * PRIME64_5;
			_hash = Bits::RotateLeft64(_hash, 11) * PRIME64_1;
			ptrBuffer++;
		} // end while

		_hash = _hash ^ (_hash >> 33);
		_hash = _hash * PRIME64_2;
		_hash = _hash ^ (_hash >> 29);
		_hash = _hash * PRIME64_3;
		_hash = _hash ^ (_hash >> 32);
		

		IHashResult result = make_shared<HashResult>(_hash);

		Initialize();

		return result;
	} // end function TransformFinal

	virtual NullableInteger GetKeyLength() const override
	{
		return 8;
	} // end function GetKeyLength

	virtual HashLibByteArray GetKey() const override
	{
		return Converters::ReadUInt64AsBytesLE(_key);
	} // end function GetKey

	virtual void SetKey(const HashLibByteArray& value) override
	{
		if (value.empty())
			_key = CKEY;
		else
		{
			if (value.size() != GetKeyLength().GetValue())
				throw ArgumentHashLibException(Utils::string_format(InvalidKeyLength, GetKeyLength().GetValue()));
			_key = Converters::ReadBytesAsUInt64LE(&value[0], 0);
		} // end else
	} // end function SetKey

private:
	XXHash64 Copy() const
	{
		XXHash64 HashInstance = XXHash64();
		HashInstance._key = _key;
		HashInstance._hash = _hash;
		HashInstance._state = _state.Clone();

		return HashInstance;
	}

private:
	UInt64 _key, _hash;

	static const UInt64 CKEY = UInt64(0x0);

	static const UInt64 PRIME64_1 = UInt64(11400714785074694791U);
	static const UInt64 PRIME64_2 = UInt64(14029467366897019727U);
	static const UInt64 PRIME64_3 = UInt64(1609587929392839161U);
	static const UInt64 PRIME64_4 = UInt64(9650029242287828579U);
	static const UInt64 PRIME64_5 = UInt64(2870177450012600261U);

	struct XXH_State
	{
	public:
		UInt64 total_len, v1, v2, v3, v4;
		UInt32 memsize;
		HashLibByteArray memory;

		XXH_State Clone() const
		{
			XXH_State result = XXH_State();
			result.total_len = total_len;
			result.memsize = memsize;
			result.v1 = v1;
			result.v2 = v2;
			result.v3 = v3;
			result.v4 = v4;

			result.memory = memory;

			return result;
		} // end function Clone

	} _state; // end struct XXH_State

	static const char* InvalidKeyLength;

}; // end class XXHash64

const char* XXHash64::InvalidKeyLength = "KeyLength must be equal to %u";
