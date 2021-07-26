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
#include "../Interfaces/IHashInfo.h"
#include "../Nullable/Nullable.h"
#include "../Interfaces/IHashInfo.h"
#include "../Utils/Utils.h"


class XXHash32 : public Hash, public virtual IIBlockHash,
	public virtual IIHash32, public virtual IIHashWithKey, public virtual IITransformBlock
{
public:
	XXHash32()
		: Hash(4, 16)
	{
		_name = __func__;

		_key = CKEY;
		_memory.resize(16);
	} // end constructor

	virtual IHashWithKey CloneHashWithKey() const
	{
		IHashWithKey _hash = make_shared<XXHash32>(Copy());
		_hash->SetBufferSize(GetBufferSize());

		return _hash;
	}

	virtual IHash Clone() const
	{
		IHash _hash = make_shared<XXHash32>(Copy());
		_hash->SetBufferSize(GetBufferSize());

		return _hash;
	}

	virtual void Initialize()
	{
		_hash = 0;
		_v1 = _key + PRIME32_1 + PRIME32_2;
		_v2 = _key + PRIME32_2;
		_v3 = _key + 0;
		_v4 = _key - PRIME32_1;
		_total_len = 0;
		_memsize = 0;
	} // end function Initialize
	
	virtual void TransformBytes(const HashLibByteArray &a_data, const Int32 a_index, const Int32 a_length)
	{
		UInt32 v1, v2, v3, v4;

		if (a_data.empty()) return;

		const byte *ptrBuffer = &a_data[a_index];
		byte * ptrTemp, *ptrMemory = &_memory[0];
		_total_len = _total_len + UInt64(a_length);

		if ((_memsize + UInt32(a_length)) < UInt32(16))
		{
			ptrTemp = (byte *)&_memory[0] + _memsize;

			memmove(ptrTemp, ptrBuffer, a_length);

			_memsize = _memsize + UInt32(a_length);
			
			return;
		} // end if

		const byte * ptrEnd = ptrBuffer + UInt32(a_length);

		if (_memsize > 0)
		{
			ptrTemp = (byte *)&_memory[0] + _memsize;

			memmove(ptrTemp, ptrBuffer, 16 - _memsize);

			_v1 = PRIME32_1 * Bits::RotateLeft32(_v1 + PRIME32_2 * Converters::ReadBytesAsUInt32LE(ptrMemory, 0), 13);
			_v2 = PRIME32_1 * Bits::RotateLeft32(_v2 + PRIME32_2 * Converters::ReadBytesAsUInt32LE(ptrMemory, 4), 13);
			_v3 = PRIME32_1 * Bits::RotateLeft32(_v3 + PRIME32_2 * Converters::ReadBytesAsUInt32LE(ptrMemory, 8), 13);
			_v4 = PRIME32_1 * Bits::RotateLeft32(_v4 + PRIME32_2 * Converters::ReadBytesAsUInt32LE(ptrMemory, 12), 13);

			ptrBuffer = ptrBuffer + (16 - _memsize);
			_memsize = 0;
		} // end if

		if (ptrBuffer <= (ptrEnd - 16))
		{
			v1 = _v1;
			v2 = _v2;
			v3 = _v3;
			v4 = _v4;

			const byte *ptrLimit = ptrEnd - 16;
			
			do 
			{
				v1 = PRIME32_1 * Bits::RotateLeft32(v1 + PRIME32_2 * Converters::ReadBytesAsUInt32LE(ptrBuffer, 0), 13);
				v2 = PRIME32_1 * Bits::RotateLeft32(v2 + PRIME32_2 * Converters::ReadBytesAsUInt32LE(ptrBuffer, 4), 13);
				v3 = PRIME32_1 * Bits::RotateLeft32(v3 + PRIME32_2 * Converters::ReadBytesAsUInt32LE(ptrBuffer, 8), 13);
				v4 = PRIME32_1 * Bits::RotateLeft32(v4 + PRIME32_2 * Converters::ReadBytesAsUInt32LE(ptrBuffer, 12), 13);
				ptrBuffer += 16;
			}
			while (ptrBuffer <= ptrLimit);

			_v1 = v1;
			_v2 = v2;
			_v3 = v3;
			_v4 = v4;
		} // end if

		if (ptrBuffer < ptrEnd)
		{
			ptrTemp = &_memory[0];
			memmove(ptrTemp, ptrBuffer, ptrEnd - ptrBuffer);
			_memsize = ptrEnd - ptrBuffer;
		} // end if
	} // end function TransformBytes

	virtual IHashResult TransformFinal()
	{
		byte *ptrEnd, *ptrBuffer;
		
		if (_total_len >= UInt64(16))
			_hash = Bits::RotateLeft32(_v1, 1) + Bits::RotateLeft32(_v2, 7) + 
			Bits::RotateLeft32(_v3, 12) + Bits::RotateLeft32(_v4, 18);
		else
			_hash = _key + PRIME32_5;
		
		_hash += _total_len;

		ptrBuffer = &_memory[0];

		ptrEnd = ptrBuffer + _memsize;
		while ((ptrBuffer + 4) <= ptrEnd)
		{
			_hash = _hash + Converters::ReadBytesAsUInt32LE(ptrBuffer, 0) * PRIME32_3;
			_hash = Bits::RotateLeft32(_hash, 17) * PRIME32_4;
			ptrBuffer += 4;
		} // end while

		while (ptrBuffer < ptrEnd)
		{
			_hash = _hash + (*ptrBuffer) * PRIME32_5;
			_hash = Bits::RotateLeft32(_hash, 11) * PRIME32_1;
			ptrBuffer++;
		} // end while

		_hash = _hash ^ (_hash >> 15);
		_hash = _hash * PRIME32_2;
		_hash = _hash ^ (_hash >> 13);
		_hash = _hash * PRIME32_3;
		_hash = _hash ^ (_hash >> 16);

		IHashResult result = make_shared<HashResult>(_hash);
			
		Initialize();
		
		return result;
	} // end function TransformFinal

private:
	XXHash32 Copy() const
	{
		XXHash32 HashInstance = XXHash32();
		HashInstance._key = _key;
		HashInstance._hash = _hash;
		HashInstance._total_len = _total_len;
		HashInstance._memsize = _memsize;
		HashInstance._v1 = _v1;
		HashInstance._v2 = _v2;
		HashInstance._v3 = _v3;
		HashInstance._v4 = _v4;
		HashInstance._memory = _memory;

		return HashInstance;
	}

	virtual inline NullableInteger GetKeyLength() const
	{
		return 4;
	} // end function GetKeyLength

	virtual inline HashLibByteArray GetKey() const
	{
		return Converters::ReadUInt32AsBytesLE(_key);
	} // end function GetKey

	virtual inline void SetKey(const HashLibByteArray &value)
	{
		if (value.empty())
			_key = CKEY;
		else
		{
			if (value.size() != GetKeyLength().GetValue())
				throw ArgumentHashLibException(Utils::string_format(InvalidKeyLength, GetKeyLength().GetValue()));
			_key = Converters::ReadBytesAsUInt32LE(&value[0], 0);
		} // end else
	} // end function SetKey

private:
	UInt32 _key, _hash;

	static const UInt32 CKEY = UInt32(0x0);

	static const UInt32 PRIME32_1 = UInt32(2654435761);
	static const UInt32 PRIME32_2 = UInt32(2246822519);
	static const UInt32 PRIME32_3 = UInt32(3266489917);
	static const UInt32 PRIME32_4 = UInt32(668265263);
	static const UInt32 PRIME32_5 = UInt32(374761393);

	UInt64 _total_len;
	UInt32 _memsize, _v1, _v2, _v3, _v4;
	HashLibByteArray _memory;

	static const char *InvalidKeyLength;

}; // end class XXHash32

const char *XXHash32::InvalidKeyLength = "KeyLength must be equal to %d";
