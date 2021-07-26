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

#include "../Nullable/Nullable.h"
#include "../Base/MultipleTransformNonBlock.h"
#include "../Utils/Utils.h"

class Murmur2_64 : public MultipleTransformNonBlock, public virtual IIHash64, 
	public virtual IIHashWithKey, public virtual IITransformBlock
{
public:
	Murmur2_64()
		: MultipleTransformNonBlock(8, 8)
	{
		_name = __func__;

		_key = CKEY;
	} // end constructor
	
	Murmur2_64(const Murmur2_64& value)
	{
		_key = value._key;
		_working_key = value._working_key;
		_buffer = value._buffer;
	}
	
	virtual IHash Clone() const
	{
		IHash _hash = make_shared<Murmur2_64>(Copy());
		_hash->SetBufferSize(GetBufferSize());
		return _hash;
	}

	virtual IHashWithKey CloneHashWithKey() const
	{
		IHashWithKey _hash = make_shared<Murmur2_64>(Copy());
		_hash->SetBufferSize(GetBufferSize());
		return _hash;
	}
	
	virtual void Initialize()
	{
		_working_key = _key;
		MultipleTransformNonBlock::Initialize();
	} // end function Initialize

	virtual NullableInteger GetKeyLength() const
	{
		return 8;
	} // end function GetKeyLength

	virtual HashLibByteArray GetKey() const
	{
		return Converters::ReadUInt64AsBytesLE(_key);
	} // end function GetKey

	virtual void SetKey(const HashLibByteArray& value)
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

protected:
	virtual IHashResult ComputeAggregatedBytes(const HashLibByteArray& a_data)
	{
		Int32 Length, current_index;
		UInt64 k, h;
				
		if (a_data.empty())
			return make_shared<HashResult>(UInt64(0));

		Length = (Int32)a_data.size();

		const byte* ptr_a_data = &a_data[0];
		
		h = _working_key ^ ((UInt64)Length * _m);
		current_index = 0;

		while (Length >= 8)
		{
			k = Converters::ReadBytesAsUInt64LE(ptr_a_data, current_index);

			k = k * _m;
			k = k ^ (k >> R);
			k = k * _m;

			h = h ^ k;
			h = h * _m;

			current_index += 8;
			Length -= 8;
		} // end while

		switch (Length)
			{
			case 7:
				h = h ^ (((UInt64)(a_data[(size_t)current_index + 6]) << 48));

				h = h ^ ((UInt64)(a_data[(size_t)current_index + 5]) << 40);

				h = h ^ ((UInt64)(a_data[(size_t)current_index + 4]) << 32);

				h = h ^ ((UInt64)(a_data[(size_t)current_index + 3]) << 24);

				h = h ^ ((UInt64)(a_data[(size_t)current_index + 2]) << 16);

				h = h ^ ((UInt64)(a_data[(size_t)current_index + 1]) << 8);

				h = h ^ (UInt64)(a_data[current_index]);

				h = h * _m;
				break;

			case 6:
				h = h ^ ((UInt64)(a_data[(size_t)current_index + 5]) << 40);

				h = h ^ ((UInt64)(a_data[(size_t)current_index + 4]) << 32);

				h = h ^ ((UInt64)(a_data[(size_t)current_index + 3]) << 24);

				h = h ^ ((UInt64)(a_data[(size_t)current_index + 2]) << 16);

				h = h ^ ((UInt64)(a_data[(size_t)current_index + 1]) << 8);

				h = h ^ (UInt64)(a_data[current_index]);

				h = h * _m;
				break;

			case 5:
				h = h ^ ((UInt64)(a_data[(size_t)current_index + 4]) << 32);

				h = h ^ ((UInt64)(a_data[(size_t)current_index + 3]) << 24);

				h = h ^ ((UInt64)(a_data[(size_t)current_index + 2]) << 16);

				h = h ^ ((UInt64)(a_data[(size_t)current_index + 1]) << 8);

				h = h ^ (UInt64)(a_data[current_index]);

				h = h * _m;
				break;

			case 4:
				h = h ^ ((UInt64)(a_data[(size_t)current_index + 3]) << 24);

				h = h ^ ((UInt64)(a_data[(size_t)current_index + 2]) << 16);

				h = h ^ ((UInt64)(a_data[(size_t)current_index + 1]) << 8);

				h = h ^ (UInt64)(a_data[current_index]);

				h = h * _m;
				break;

			case 3:
				h = h ^ ((UInt64)(a_data[(size_t)current_index + 2]) << 16);

				h = h ^ ((UInt64)(a_data[(size_t)current_index + 1]) << 8);

				h = h ^ (UInt64)(a_data[current_index]);

				h = h * _m;
				break;

			case 2:
				h = h ^ ((UInt64)(a_data[(size_t)current_index + 1]) << 8);

				h = h ^ (UInt64)(a_data[current_index]);

				h = h * _m;
				break;

			case 1:
				h = h ^ (UInt64)(a_data[current_index]);

				h = h * _m;
				break;
			} // end switch

		h = h ^ (h >> R);
		h = h * _m;
		h = h ^ (h >> R);

		return make_shared<HashResult>(h);
	} // end function ComputeAggregatedBytes

private:
	Murmur2_64 Copy() const
	{
		Murmur2_64 HashInstance = Murmur2_64();
		HashInstance._key = _key;
		HashInstance._working_key = _working_key;

		HashInstance._buffer = _buffer;

		return HashInstance;
	}

	UInt64 _key, _working_key;

	static const UInt32 CKEY = UInt32(0x0);
	static const UInt64 _m = UInt64(0xC6A4A7935BD1E995);
	static const Int32 R = Int32(47);

	static const char* InvalidKeyLength;

}; // end class Murmur2_64

const char* Murmur2_64::InvalidKeyLength = "KeyLength must be equal to %u";
