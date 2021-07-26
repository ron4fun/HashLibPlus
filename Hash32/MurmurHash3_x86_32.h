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

class MurmurHash3_x86_32 : public Hash, public virtual IIHash32,
	public virtual IIHashWithKey, public virtual IITransformBlock
{
public:
	MurmurHash3_x86_32()
		: Hash(4, 4)
	{
		_name = __func__;

		_key = CKEY;
		_buf.resize(4);
	} // end constructor

	virtual IHashWithKey CloneHashWithKey() const
	{
		IHashWithKey _hash = make_shared<MurmurHash3_x86_32>(Copy());
		_hash->SetBufferSize(GetBufferSize());

		return _hash;
	}

	virtual IHash Clone() const
	{
		IHash _hash = make_shared<MurmurHash3_x86_32>(Copy());
		_hash->SetBufferSize(GetBufferSize());

		return _hash;
	}

	virtual void Initialize()
	{
		_h = _key;
		_total_length = 0;
		_idx = 0;
	} // end function Initialize

	virtual void TransformBytes(const HashLibByteArray &a_data, const Int32 a_index, const Int32 a_length)
	{
		Int32 len, nBlocks, i, offset, index;
		UInt32 k;
		const byte *ptr_a_data;

		if (a_data.empty()) return;

		len = a_length;
		i = a_index;
		index = a_index;
		ptr_a_data = &a_data[0];
		_total_length += len;
        
        //consume last pending bytes
        if (_idx != 0 && a_length != 0)
        {
            while (_idx < 4 && len != 0)
            {
                _buf[_idx++] = *(ptr_a_data + index);
				index++;
                len--;
            }
            
            if (_idx == 4)
            {
                byte *ptr_Fm_buf = &_buf[0];
			    k = Converters::ReadBytesAsUInt32LE(ptr_Fm_buf, 0);
			    TransformUInt32Fast(k);
                _idx = 0;
            }
        } 
		else
		{
			i = 0;
		}

        nBlocks = (len) >> 2;
        offset = 0;

		// body
		while (i < nBlocks)
		{
			k = Converters::ReadBytesAsUInt32LE(ptr_a_data, index + (i * 4));
			TransformUInt32Fast(k);
			i++;
		} // end while

        //save pending end bytes
        offset = index + (i * 4);
		while (offset < (len + index))
		{
			ByteUpdate(a_data[offset]);
			offset++;
		} // end while

	} // end function TransformBytes

	virtual IHashResult TransformFinal()
	{
		Finish();

		IHashResult result = make_shared<HashResult>(_h);

		Initialize();

		return result;
	} // end function TransformFinal

private:

	MurmurHash3_x86_32 Copy() const
	{
		MurmurHash3_x86_32 HashInstance;

		HashInstance = MurmurHash3_x86_32();
		HashInstance._key = _key;
		HashInstance._h = _h;
		HashInstance._total_length = _total_length;
		HashInstance._idx = _idx;
		HashInstance._buf = _buf;

		return HashInstance;
	}

	inline void TransformUInt32Fast(const UInt32 a_data)
	{
		UInt32 k = a_data;
		
		k = k * C1;
		k = Bits::RotateLeft32(k, 15);
		k = k * C2;

		_h = _h ^ k;
		_h = Bits::RotateLeft32(_h, 13);
		_h = (_h * 5) + C3;
	} // end function TransformUInt32Fast

	inline void ByteUpdate(const byte a_b)
	{
		UInt32 k = 0;
		byte *ptr_Fm_buf = 0;
		
		_buf[_idx] = a_b;
		_idx++;
		if (_idx >= 4)
		{
			ptr_Fm_buf = &_buf[0];
			k = Converters::ReadBytesAsUInt32LE(ptr_Fm_buf, 0);
			TransformUInt32Fast(k);
			_idx = 0;
		} // end if
	} // end function ByteUpdate

	void Finish()
	{
		 UInt32 k = 0;

         // tail
		 if (_idx != 0)
		 {
			 switch (_idx)
			 {
			 case 3:
				 k = k ^ (_buf[2] << 16);
				 k = k ^ (_buf[1] << 8);
				 k = k ^ _buf[0];
				 k = k * C1;
				 k = Bits::RotateLeft32(k, 15);
				 k = k * C2;
				 _h = _h ^ k;
				 break;

			 case 2:
				 k = k ^ (_buf[1] << 8);
				 k = k ^ _buf[0];
				 k = k * C1;
				 k = Bits::RotateLeft32(k, 15);
				 k = k * C2;
				 _h = _h ^ k;
				 break;

			 case 1:
				 k = k ^ _buf[0];
				 k = k * C1;
				 k = Bits::RotateLeft32(k, 15);
				 k = k * C2;
				 _h = _h ^ k;
			 } // end switch
		 } // end if

		// finalization
		_h = _h ^ _total_length;
		_h = _h ^ (_h >> 16);
		_h = _h * C4;
		_h = _h ^ (_h >> 13);
		_h = _h * C5;
		_h = _h ^ (_h >> 16);
	} // end function Finish

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
	UInt32 _key, _h, _total_length;
	Int32 _idx;
	HashLibByteArray _buf;

	static const UInt32 CKEY = UInt32(0x0);

	static const UInt32 C1 = UInt32(0xCC9E2D51);
	static const UInt32 C2 = UInt32(0x1B873593);
	static const UInt32 C3 = UInt32(0xE6546B64);
	static const UInt32 C4 = UInt32(0x85EBCA6B);
	static const UInt32 C5 = UInt32(0xC2B2AE35);
	
	static const char *InvalidKeyLength;

}; // end class MurmurHash3_x86_32

const char *MurmurHash3_x86_32::InvalidKeyLength = "KeyLength must be equal to %d";
