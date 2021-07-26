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

class Murmur2_32 : public MultipleTransformNonBlock, public virtual IIHash32,
	public virtual IIHashWithKey, public virtual IITransformBlock
{
public:
	Murmur2_32()
		: MultipleTransformNonBlock(4, 4)
	{
		_name = __func__;

		_key = CKEY;
	} // end constructor
	
	virtual IHashWithKey CloneHashWithKey() const
	{
		IHashWithKey _hash = make_shared<Murmur2_32>(Copy());
		_hash->SetBufferSize(GetBufferSize());

		return _hash;
	}

	virtual IHash Clone() const
	{
		IHash _hash = make_shared<Murmur2_32>(Copy());
		_hash->SetBufferSize(GetBufferSize());

		return _hash;
	}

	virtual void Initialize()
	{
		_working_key = _key;
		MultipleTransformNonBlock::Initialize();
	} // end function Initialize

protected:
	virtual IHashResult ComputeAggregatedBytes(const HashLibByteArray &a_data)
	{
		return make_shared<HashResult>(InternalComputeBytes(a_data));
	} // end function ComputeAggregatedBytes

private:
	Murmur2_32 Copy() const
	{
		Murmur2_32 HashInstance = Murmur2_32();
		HashInstance._key = _key;
		HashInstance._working_key = _working_key;
		HashInstance._h = _h;
		HashInstance._buffer = _buffer;

		return HashInstance;
	}

	Int32 InternalComputeBytes(const HashLibByteArray &a_data)
	{
		Int32 Length, current_index;
		UInt32 k;

		if (a_data.empty()) return 0;

		Length = (Int32)a_data.size();
		const byte *ptr_a_data = &a_data[0];

		if (Length == 0)
			return 0;
		
		_h = _working_key ^ UInt32(Length);
		current_index = 0;

		while (Length >= 4)
		{
			k = Converters::ReadBytesAsUInt32LE(ptr_a_data, current_index);

			TransformUInt32Fast(k);
			current_index += 4;
			Length -= 4;
		} // end while

		switch (Length)
		{
		case 3:
			_h = _h ^ (a_data[(size_t)current_index + 2] << 16);
			_h = _h ^ (a_data[(size_t)current_index + 1] << 8);
			_h = _h ^ (a_data[current_index]);
			_h = _h * _m;
			break;

		case 2:
			_h = _h ^ (a_data[(size_t)current_index + 1] << 8);
			_h = _h ^ (a_data[current_index]);
			_h = _h * _m;
			break;

		case 1:
			_h = _h ^ (a_data[current_index]);
			_h = _h * _m;
		} // end switch

		_h = _h ^ (_h >> 13);

		_h = _h * _m;
		_h = _h ^ (_h >> 15);

		return Int32(_h);
	} // end function InternalComputeBytes

	inline void TransformUInt32Fast(UInt32 a_data)
	{
		a_data = a_data * _m;
		a_data = a_data ^ (a_data >> R);
		a_data = a_data * _m;

		_h = _h * _m;
		_h = _h ^ a_data;
	} // end function TransformUInt32Fast

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
	UInt32 _key, _working_key, _h;

	static const UInt32 CKEY = UInt32(0x0);
	static const UInt32 _m = UInt32(0x5BD1E995);
	static const Int32 R = Int32(24);

	static const char *InvalidKeyLength;

}; // end class Murmur2_32

const char *Murmur2_32::InvalidKeyLength = "KeyLength must be equal to %d";
