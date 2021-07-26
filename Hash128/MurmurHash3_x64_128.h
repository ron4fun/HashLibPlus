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
#include "../Utils/Utils.h"

class MurmurHash3_x64_128 : public Hash, public virtual IIHash128, 
	public virtual IIHashWithKey, public virtual IITransformBlock
{
public:
	MurmurHash3_x64_128()
		: Hash(16, 16)
	{
		_name = __func__;

		_key = CKEY;
		_buf.resize(16);
	} // end constructor

	virtual IHash Clone() const
	{
		IHash _hash = make_shared<MurmurHash3_x64_128>(Copy());
		_hash->SetBufferSize(GetBufferSize());
		return _hash;
	}

	virtual IHashWithKey CloneHashWithKey() const
	{
		IHashWithKey _hash = make_shared<MurmurHash3_x64_128>(Copy());
		_hash->SetBufferSize(GetBufferSize());
		return _hash;
	}

	virtual void Initialize()
	{
		_h1 = _key;
		_h2 = _key;

		_total_length = 0;
		_idx = 0;
	} // end function Initialize

	virtual IHashResult TransformFinal()
	{
		Finish();

		HashLibUInt64Array tempBufUInt64 = HashLibUInt64Array({ _h1, _h2 });
		HashLibByteArray tempBufByte = HashLibByteArray(tempBufUInt64.size() * sizeof(UInt64));

		Converters::be64_copy(&tempBufUInt64[0], 0, &tempBufByte[0], 0, (Int32)tempBufByte.size());

		IHashResult result = make_shared<HashResult>(tempBufByte);

		Initialize();

		return result;
	} // end function TransformFinal

	virtual void TransformBytes(const HashLibByteArray& a_data, const Int32 a_index, const Int32 a_length)
	{
		Int32 len, nBlocks, i, offset, lIdx, index;
		UInt64 k1, k2;
		const byte* ptr_a_data = 0;

		if (a_data.empty()) return;

		len = a_length;
		i = a_index;
		index = a_index;
		lIdx = 0;
		_total_length += len;
		ptr_a_data = &a_data[0];

		//consume last pending bytes
		if (_idx && a_length)
		{
			while (_idx < 16 && len)
			{
				_buf[_idx++] = *(ptr_a_data + index);
				index++;
				len--;
			}

			if (_idx == 16)
				ProcessPendings();
		}
		else
			i = 0;

		nBlocks = len >> 4;

		// body
		while (i < nBlocks)
		{
			k1 = Converters::ReadBytesAsUInt64LE(ptr_a_data, a_index + lIdx);
			lIdx += 8;

			k2 = Converters::ReadBytesAsUInt64LE(ptr_a_data, a_index + lIdx);
			lIdx += 8;

			k1 = k1 * C1;
			k1 = Bits::RotateLeft64(k1, 31);
			k1 = k1 * C2;
			_h1 = _h1 ^ k1;

			_h1 = Bits::RotateLeft64(_h1, 27);
			_h1 = _h1 + _h2;
			_h1 = _h1 * 5 + C3;

			k2 = k2 * C2;
			k2 = Bits::RotateLeft64(k2, 33);
			k2 = k2 * C1;
			_h2 = _h2 ^ k2;

			_h2 = Bits::RotateLeft64(_h2, 31);
			_h2 = _h2 + _h1;
			_h2 = _h2 * 5 + C4;

			i++;
		} // end if

		offset = index + (i * 16);
		while (offset < (index + len))
		{
			ByteUpdate(a_data[offset]);
			offset++;
		} // end while
	} // end function TransformBytes

	virtual NullableInteger GetKeyLength() const
	{
		return 4;
	} // end function GetKeyLength

	virtual HashLibByteArray GetKey() const
	{
		return Converters::ReadUInt32AsBytesLE(_key);
	} // end function GetKey

	virtual void SetKey(const HashLibByteArray& value)
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
	MurmurHash3_x64_128 Copy() const
	{
		MurmurHash3_x64_128 HashInstance = MurmurHash3_x64_128();
		HashInstance._h1 = _h1;
		HashInstance._h2 = _h2;
		HashInstance._total_length = _total_length;
		HashInstance._key = _key;
		HashInstance._idx = _idx;
		HashInstance._buf = _buf;

		return HashInstance;
	}

	void ByteUpdate(const byte a_b)
	{
		_buf[_idx] = a_b;
		_idx++;
		ProcessPendings();
	}

	void ProcessPendings()
	{
		UInt64 k1, k2;
		byte* ptr_Fm_buf = 0;

		if (_idx >= 16)
		{
			ptr_Fm_buf = &_buf[0];
			k1 = Converters::ReadBytesAsUInt64LE(ptr_Fm_buf, 0);
			k2 = Converters::ReadBytesAsUInt64LE(ptr_Fm_buf, 8);

			k1 = k1 * C1;
			k1 = Bits::RotateLeft64(k1, 31);
			k1 = k1 * C2;
			_h1 = _h1 ^ k1;

			_h1 = Bits::RotateLeft64(_h1, 27);
			_h1 = _h1 + _h2;
			_h1 = _h1 * 5 + C3;

			k2 = k2 * C2;
			k2 = Bits::RotateLeft64(k2, 33);
			k2 = k2 * C1;
			_h2 = _h2 ^ k2;

			_h2 = Bits::RotateLeft64(_h2, 31);
			_h2 = _h2 + _h1;
			_h2 = _h2 * 5 + C4;

			_idx = 0;
		} // end if

	} // end function ByteUpdate

	void Finish()
	{
		UInt64 k1, k2;
		Int32 Length;

		// tail
		k1 = 0;
		k2 = 0;

		Length = _idx;
		if (Length != 0)
		{
			switch (Length)
			{
			case 15:
				k2 = k2 ^ (UInt64(_buf[14]) << 48);
				k2 = k2 ^ (UInt64(_buf[13]) << 40);
				k2 = k2 ^ (UInt64(_buf[12]) << 32);
				k2 = k2 ^ (UInt64(_buf[11]) << 24);
				k2 = k2 ^ (UInt64(_buf[10]) << 16);
				k2 = k2 ^ (UInt64(_buf[9]) << 8);
				k2 = k2 ^ (UInt64(_buf[8]) << 0);
				k2 = k2 * C2;
				k2 = Bits::RotateLeft64(k2, 33);
				k2 = k2 * C1;
				_h2 = _h2 ^ k2;
				break;

			case 14:
				k2 = k2 ^ (UInt64(_buf[13]) << 40);
				k2 = k2 ^ (UInt64(_buf[12]) << 32);
				k2 = k2 ^ (UInt64(_buf[11]) << 24);
				k2 = k2 ^ (UInt64(_buf[10]) << 16);
				k2 = k2 ^ (UInt64(_buf[9]) << 8);
				k2 = k2 ^ (UInt64(_buf[8]) << 0);
				k2 = k2 * C2;
				k2 = Bits::RotateLeft64(k2, 33);
				k2 = k2 * C1;
				_h2 = _h2 ^ k2;
				break;

			case 13:
				k2 = k2 ^ (UInt64(_buf[12]) << 32);
				k2 = k2 ^ (UInt64(_buf[11]) << 24);
				k2 = k2 ^ (UInt64(_buf[10]) << 16);
				k2 = k2 ^ (UInt64(_buf[9]) << 8);
				k2 = k2 ^ (UInt64(_buf[8]) << 0);
				k2 = k2 * C2;
				k2 = Bits::RotateLeft64(k2, 33);
				k2 = k2 * C1;
				_h2 = _h2 ^ k2;
				break;

			case 12:
				k2 = k2 ^ (UInt64(_buf[11]) << 24);
				k2 = k2 ^ (UInt64(_buf[10]) << 16);
				k2 = k2 ^ (UInt64(_buf[9]) << 8);
				k2 = k2 ^ (UInt64(_buf[8]) << 0);
				k2 = k2 * C2;
				k2 = Bits::RotateLeft64(k2, 33);
				k2 = k2 * C1;
				_h2 = _h2 ^ k2;
				break;

			case 11:
				k2 = k2 ^ (UInt64(_buf[10]) << 16);
				k2 = k2 ^ (UInt64(_buf[9]) << 8);
				k2 = k2 ^ (UInt64(_buf[8]) << 0);
				k2 = k2 * C2;
				k2 = Bits::RotateLeft64(k2, 33);
				k2 = k2 * C1;
				_h2 = _h2 ^ k2;
				break;

			case 10:
				k2 = k2 ^ (UInt64(_buf[9]) << 8);
				k2 = k2 ^ (UInt64(_buf[8]) << 0);
				k2 = k2 * C2;
				k2 = Bits::RotateLeft64(k2, 33);
				k2 = k2 * C1;
				_h2 = _h2 ^ k2;
				break;

			case 9:
				k2 = k2 ^ (UInt64(_buf[8]) << 0);
				k2 = k2 * C2;
				k2 = Bits::RotateLeft64(k2, 33);
				k2 = k2 * C1;
				_h2 = _h2 ^ k2;
				break;
			} // end switch

			if (Length > 8)
				Length = 8;

			switch (Length)
			{
			case 8:
				k1 = k1 ^ (UInt64(_buf[7]) << 56);
				k1 = k1 ^ (UInt64(_buf[6]) << 48);
				k1 = k1 ^ (UInt64(_buf[5]) << 40);
				k1 = k1 ^ (UInt64(_buf[4]) << 32);
				k1 = k1 ^ (UInt64(_buf[3]) << 24);
				k1 = k1 ^ (UInt64(_buf[2]) << 16);
				k1 = k1 ^ (UInt64(_buf[1]) << 8);
				k1 = k1 ^ (UInt64(_buf[0]) << 0);
				k1 = k1 * C1;
				k1 = Bits::RotateLeft64(k1, 31);
				k1 = k1 * C2;
				_h1 = _h1 ^ k1;
				break;

			case 7:
				k1 = k1 ^ (UInt64(_buf[6]) << 48);
				k1 = k1 ^ (UInt64(_buf[5]) << 40);
				k1 = k1 ^ (UInt64(_buf[4]) << 32);
				k1 = k1 ^ (UInt64(_buf[3]) << 24);
				k1 = k1 ^ (UInt64(_buf[2]) << 16);
				k1 = k1 ^ (UInt64(_buf[1]) << 8);
				k1 = k1 ^ (UInt64(_buf[0]) << 0);
				k1 = k1 * C1;
				k1 = Bits::RotateLeft64(k1, 31);
				k1 = k1 * C2;
				_h1 = _h1 ^ k1;
				break;

			case 6:
				k1 = k1 ^ (UInt64(_buf[5]) << 40);
				k1 = k1 ^ (UInt64(_buf[4]) << 32);
				k1 = k1 ^ (UInt64(_buf[3]) << 24);
				k1 = k1 ^ (UInt64(_buf[2]) << 16);
				k1 = k1 ^ (UInt64(_buf[1]) << 8);
				k1 = k1 ^ (UInt64(_buf[0]) << 0);
				k1 = k1 * C1;
				k1 = Bits::RotateLeft64(k1, 31);
				k1 = k1 * C2;
				_h1 = _h1 ^ k1;
				break;

			case 5:
				k1 = k1 ^ (UInt64(_buf[4]) << 32);
				k1 = k1 ^ (UInt64(_buf[3]) << 24);
				k1 = k1 ^ (UInt64(_buf[2]) << 16);
				k1 = k1 ^ (UInt64(_buf[1]) << 8);
				k1 = k1 ^ (UInt64(_buf[0]) << 0);
				k1 = k1 * C1;
				k1 = Bits::RotateLeft64(k1, 31);
				k1 = k1 * C2;
				_h1 = _h1 ^ k1;
				break;

			case 4:
				k1 = k1 ^ (UInt64(_buf[3]) << 24);
				k1 = k1 ^ (UInt64(_buf[2]) << 16);
				k1 = k1 ^ (UInt64(_buf[1]) << 8);
				k1 = k1 ^ (UInt64(_buf[0]) << 0);
				k1 = k1 * C1;
				k1 = Bits::RotateLeft64(k1, 31);
				k1 = k1 * C2;
				_h1 = _h1 ^ k1;
				break;

			case 3:
				k1 = k1 ^ (UInt64(_buf[2]) << 16);
				k1 = k1 ^ (UInt64(_buf[1]) << 8);
				k1 = k1 ^ (UInt64(_buf[0]) << 0);
				k1 = k1 * C1;
				k1 = Bits::RotateLeft64(k1, 31);
				k1 = k1 * C2;
				_h1 = _h1 ^ k1;
				break;

			case 2:
				k1 = k1 ^ (UInt64(_buf[1]) << 8);
				k1 = k1 ^ (UInt64(_buf[0]) << 0);
				k1 = k1 * C1;
				k1 = Bits::RotateLeft64(k1, 31);
				k1 = k1 * C2;
				_h1 = _h1 ^ k1;
				break;

			case 1:
				k1 = k1 ^ (UInt64(_buf[0]) << 0);
				k1 = k1 * C1;
				k1 = Bits::RotateLeft64(k1, 31);
				k1 = k1 * C2;
				_h1 = _h1 ^ k1;
				break;

			} // end switch

		} // end if

		// finalization

		_h1 = _h1 ^ _total_length;
		_h2 = _h2 ^ _total_length;

		_h1 = _h1 + _h2;
		_h2 = _h2 + _h1;

		_h1 = _h1 ^ (_h1 >> 33);
		_h1 = _h1 * C5;
		_h1 = _h1 ^ (_h1 >> 33);
		_h1 = _h1 * C6;
		_h1 = _h1 ^ (_h1 >> 33);

		_h2 = _h2 ^ (_h2 >> 33);
		_h2 = _h2 * C5;
		_h2 = _h2 ^ (_h2 >> 33);
		_h2 = _h2 * C6;
		_h2 = _h2 ^ (_h2 >> 33);

		_h1 = _h1 + _h2;
		_h2 = _h2 + _h1;
	} // end function Finish

private:
	UInt64 _h1, _h2, _total_length;
	UInt32 _key;
	Int32 _idx;
	HashLibByteArray _buf;

	static const UInt32 CKEY = UInt32(0x0);

	static const UInt64 C1 = UInt64(0x87C37B91114253D5);
	static const UInt64 C5 = UInt64(0xFF51AFD7ED558CCD);
	static const UInt64 C6 = UInt64(0xC4CEB9FE1A85EC53);

	static const UInt64 C2 = UInt64(0x4CF5AD432745937F);
	static const UInt32 C3 = UInt32(0x52DCE729);
	static const UInt32 C4 = UInt32(0x38495AB5);

	static const char* InvalidKeyLength;

}; // end class MurmurHash3_x64_128

const char* MurmurHash3_x64_128::InvalidKeyLength = "KeyLength must be equal to %u";
