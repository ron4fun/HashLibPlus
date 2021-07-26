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

class SipHash : public Hash, public virtual IIHash64, 
	public virtual IIHashWithKey, public virtual IITransformBlock
{
public:
	SipHash(const Int32 hash_size, const Int32 block_size)
		: Hash(hash_size, block_size)
	{
		_name = __func__;

		_key0 = KEY0;
		_key1 = KEY1;
		_buf.resize(8);
	} // end constructor

	virtual void Initialize()
	{
		_v0 = V0;
		_v1 = V1;
		_v2 = V2;
		_v3 = V3;
		_total_length = 0;
		_idx = 0;

		_v3 = _v3 ^ _key1;
		_v2 = _v2 ^ _key0;
		_v1 = _v1 ^ _key1;
		_v0 = _v0 ^ _key0;
	} // end function Initialize

	virtual NullableInteger GetKeyLength() const
	{
		return 16;
	} // end function GetKeyLength

	virtual HashLibByteArray GetKey() const
	{
		HashLibByteArray LKey = HashLibByteArray(GetKeyLength().GetValue());

		Converters::ReadUInt64AsBytesLE(_key0, LKey, 0);
		Converters::ReadUInt64AsBytesLE(_key1, LKey, 8);

		return LKey;
	} // end function GetKey

	virtual void SetKey(const HashLibByteArray& value)
	{
		if (value.empty())
		{
			_key0 = KEY0;
			_key1 = KEY1;
		} // end if
		else
		{
			if (value.size() != GetKeyLength().GetValue())
				throw ArgumentHashLibException(InvalidKeyLength + GetKeyLength().GetValue());
			_key0 = Converters::ReadBytesAsUInt64LE((byte*)& value[0], 0);
			_key1 = Converters::ReadBytesAsUInt64LE((byte*)& value[0], 8);
		} // end else
	} // end function SetKey

	virtual void TransformBytes(const HashLibByteArray& a_data, const Int32 a_index, const Int32 a_length)
	{
		Int32 i, length, iter, offset, index;

		if (a_data.empty()) return;

		length = a_length;
		index = a_index;
		i = a_index;

		_total_length += (UInt32)length;

		const byte* ptr_a_data = &a_data[0], * ptr_Fm_buf = &_buf[0];
				
		// consume last pending bytes
		if (_idx != 0 && length != 0)
		{
			while (_idx < 8 && length != 0)
			{
				_buf[_idx] = *(ptr_a_data + index);
				_idx++;
				index++;
				length--;
			} // end while

			if (_idx == 8)
			{
				_m = Converters::ReadBytesAsUInt64LE(ptr_Fm_buf, 0);
				ProcessBlock(_m);
				_idx = 0;
			} // end if
		} // end if
		else
		{
			i = 0;
		} // end else

		iter = length >> 3;

		// body
		while (i < iter)
		{
			_m = Converters::ReadBytesAsUInt64LE(ptr_a_data, index + (i * 8));
			ProcessBlock(_m);
			i++;
		} // end while

		// save pending end bytes
		offset = index + (i * 8);

		while (offset < (length + index))
		{
			ByteUpdate(a_data[offset]);
			offset++;
		} // end while
	
	} // end function TransformBytes

	virtual IHashResult TransformFinal()
	{
		UInt64 finalBlock = ProcessFinalBlock();
		_v3 ^= finalBlock;
		CompressTimes(_cr);
		_v0 ^= finalBlock;
		_v2 ^= GetMagicXor();
		CompressTimes(_fr);

		HashLibByteArray buffer = HashLibByteArray(GetHashSize());
		Converters::ReadUInt64AsBytesLE(_v0 ^ _v1 ^ _v2 ^ _v3, buffer, 0);
		IHashResult result = make_shared<HashResult>(buffer);
		Initialize();
		return result;
	} // end function TransformFinal

protected:
	virtual byte GetMagicXor() const = 0;

	inline void Compress()
	{
		_v0 = _v0 + _v1;
		_v2 = _v2 + _v3;
		_v1 = Bits::RotateLeft64(_v1, 13);
		_v3 = Bits::RotateLeft64(_v3, 16);
		_v1 = _v1 ^ _v0;
		_v3 = _v3 ^ _v2;
		_v0 = Bits::RotateLeft64(_v0, 32);
		_v2 = _v2 + _v1;
		_v0 = _v0 + _v3;
		_v1 = Bits::RotateLeft64(_v1, 17);
		_v3 = Bits::RotateLeft64(_v3, 21);
		_v1 = _v1 ^ _v2;
		_v3 = _v3 ^ _v0;
		_v2 = Bits::RotateLeft64(_v2, 32);
	} // end function Compress

	inline void CompressTimes(const Int32 a_times)
	{
		Int32 i = 0;

		while (i < a_times)
		{
			Compress();
			i++;
		} // end while
	} // end function CompressTimes

	inline void ProcessBlock(const UInt64 a_m)
	{
		_v3 = _v3 ^ a_m;
		CompressTimes(_cr);
		_v0 = _v0 ^ a_m;
	} // end function ProcessBlock

	inline UInt64 ProcessFinalBlock()
	{
		UInt64 result = (_total_length & 0xFF) << 56;

		if (_idx == 0) return result;
		switch (_idx)
		{
		case 7:
			result |= (UInt64)_buf[6] << 48;
			result |= (UInt64)_buf[5] << 40;
			result |= (UInt64)_buf[4] << 32;
			result |= (UInt64)_buf[3] << 24;
			result |= (UInt64)_buf[2] << 16;
			result |= (UInt64)_buf[1] << 8;
			result |= _buf[0];
			break;

		case 6:
			result |= (UInt64)_buf[5] << 40;
			result |= (UInt64)_buf[4] << 32;
			result |= (UInt64)_buf[3] << 24;
			result |= (UInt64)_buf[2] << 16;
			result |= (UInt64)_buf[1] << 8;
			result |= _buf[0];
			break;

		case 5:
			result |= (UInt64)_buf[4] << 32;
			result |= (UInt64)_buf[3] << 24;
			result |= (UInt64)_buf[2] << 16;
			result |= (UInt64)_buf[1] << 8;
			result |= _buf[0];
			break;

		case 4:
			result |= (UInt64)_buf[3] << 24;
			result |= (UInt64)_buf[2] << 16;
			result |= (UInt64)_buf[1] << 8;
			result |= _buf[0];
			break;

		case 3:
			result |= (UInt64)_buf[2] << 16;
			result |= (UInt64)_buf[1] << 8;
			result |= _buf[0];
			break;

		case 2:
			result |= (UInt64)_buf[1] << 8;
			result |= _buf[0];
			break;

		case 1:
			result |= _buf[0];
			break;
		}

		return result;
	}

	inline void ByteUpdate(const byte a_b)
	{
		_buf[_idx] = a_b;
		_idx++;
		if (_idx >= 8)
		{
			byte* ptr_Fm_buf = &_buf[0];
			UInt64 m = Converters::ReadBytesAsUInt64LE(ptr_Fm_buf, 0);
			ProcessBlock(m);
			_idx = 0;
		} // end if
	} // end function ByteUpdate

	void Finish()
	{
		UInt64 b = UInt64(_total_length & 0xFF) << 56;

		if (_idx != 0)
		{
			switch (_idx)
			{
			case 7:
				b = b | (UInt64(_buf[6]) << 48);
				b = b | (UInt64(_buf[5]) << 40);
				b = b | (UInt64(_buf[4]) << 32);
				b = b | (UInt64(_buf[3]) << 24);
				b = b | (UInt64(_buf[2]) << 16);
				b = b | (UInt64(_buf[1]) << 8);
				b = b | (UInt64(_buf[0]));
				break;

			case 6:
				b = b | (UInt64(_buf[5]) << 40);
				b = b | (UInt64(_buf[4]) << 32);
				b = b | (UInt64(_buf[3]) << 24);
				b = b | (UInt64(_buf[2]) << 16);
				b = b | (UInt64(_buf[1]) << 8);
				b = b | (UInt64(_buf[0]));
				break;

			case 5:
				b = b | (UInt64(_buf[4]) << 32);
				b = b | (UInt64(_buf[3]) << 24);
				b = b | (UInt64(_buf[2]) << 16);
				b = b | (UInt64(_buf[1]) << 8);
				b = b | (UInt64(_buf[0]));
				break;

			case 4:
				b = b | (UInt64(_buf[3]) << 24);
				b = b | (UInt64(_buf[2]) << 16);
				b = b | (UInt64(_buf[1]) << 8);
				b = b | (UInt64(_buf[0]));
				break;

			case 3:
				b = b | (UInt64(_buf[2]) << 16);
				b = b | (UInt64(_buf[1]) << 8);
				b = b | (UInt64(_buf[0]));
				break;

			case 2:
				b = b | (UInt64(_buf[1]) << 8);
				b = b | (UInt64(_buf[0]));
				break;

			case 1:
				b = b | (UInt64(_buf[0]));
			} // end switch
		} // end if

		_v3 = _v3 ^ b;
		CompressTimes(_cr);
		_v0 = _v0 ^ b;
		_v2 = _v2 ^ 0xFF;
		CompressTimes(_fr);
	} // end function Finish

protected:
	UInt64 _v0, _v1, _v2, _v3, _key0, _key1, _total_length, _m;
	Int32 _cr, _fr, _idx;
	HashLibByteArray _buf;

	static const UInt64 V0 = UInt64(0x736F6D6570736575);
	static const UInt64 V1 = UInt64(0x646F72616E646F6D);
	static const UInt64 V2 = UInt64(0x6C7967656E657261);
	static const UInt64 V3 = UInt64(0x7465646279746573);
	static const UInt64 KEY0 = UInt64(0x0706050403020100);
	static const UInt64 KEY1 = UInt64(0x0F0E0D0C0B0A0908);

	static const char* InvalidKeyLength;

}; // end class SipHash

const char* SipHash::InvalidKeyLength = "KeyLength must be equal to %u";

class SipHash64 : public SipHash
{
public:
	virtual IHashResult TransformFinal()
	{
		UInt64 finalBlock = ProcessFinalBlock();
		_v3 ^= finalBlock;
		CompressTimes(_cr);
		_v0 ^= finalBlock;
		_v2 ^= GetMagicXor();
		CompressTimes(_fr);

		HashLibByteArray buffer = HashLibByteArray(GetHashSize());
		Converters::ReadUInt64AsBytesLE(_v0 ^ _v1 ^ _v2 ^ _v3, buffer, 0);
		IHashResult result = make_shared<HashResult>(buffer);
		Initialize();
		return result;
	} // end function TransformFinal

protected:
	SipHash64(const Int32 compressionRounds, const Int32 finalizationRounds)
		: SipHash(8, 8)
	{
		_cr = compressionRounds;
		_fr = finalizationRounds;
	}

	virtual byte GetMagicXor() const { return 0xFF; };

}; // end class SipHash64

/// <summary>
/// SipHash64 2 - 4 algorithm.
/// <summary>
class SipHash64_2_4 : public SipHash64
{
public:
	SipHash64_2_4()
		: SipHash64(2, 4)
	{
		_name = __func__;
	} // end constructor
	
	virtual IHash Clone() const
	{
		IHash _hash = make_shared<SipHash64_2_4>(Copy());
		_hash->SetBufferSize(GetBufferSize());
		return _hash;
	}

	virtual IHashWithKey CloneHashWithKey() const
	{
		IHashWithKey _hash = make_shared<SipHash64_2_4>(Copy());
		_hash->SetBufferSize(GetBufferSize());
		return _hash;
	}
	
private:
	SipHash64_2_4 Copy() const
	{
		SipHash64_2_4 HashInstance = SipHash64_2_4();
		HashInstance._v0 = _v0;
		HashInstance._v1 = _v1;
		HashInstance._v2 = _v2;
		HashInstance._v3 = _v3;
		HashInstance._key0 = _key0;
		HashInstance._key1 = _key1;
		HashInstance._total_length = _total_length;
		HashInstance._cr = _cr;
		HashInstance._fr = _fr;
		HashInstance._idx = _idx;
		HashInstance._buf = _buf;

		return HashInstance;
	}

}; // end class SipHash64_2_4
