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

#include <sstream>
#include "../Base/Hash.h"
#include "../Interfaces/IHashInfo.h"

class HMACNotBuildInAdapter : public Hash, public virtual IIHMACNotBuildIn,
	public virtual IIWithKey, public virtual IICryptoNotBuildIn
{
private:
	HMACNotBuildInAdapter(const IHash a_hash)
		: Hash(a_hash->GetHashSize(), a_hash->GetBlockSize())
	{
		_hash = ::move(a_hash);
	}

	HMACNotBuildInAdapter Copy() const
	{
		HMACNotBuildInAdapter hmac = HMACNotBuildInAdapter(_hash);
		hmac._opad = _opad;
		hmac._ipad = _ipad;
		hmac._key = _key;
		hmac._workingKey = _workingKey;

		hmac.SetBufferSize(GetBufferSize());

		return hmac;
	} //

public:
	HMACNotBuildInAdapter() {}

	HMACNotBuildInAdapter(const IHash a_hash, const HashLibByteArray& hmacKey)
		: Hash(a_hash->GetHashSize(), a_hash->GetBlockSize())
	{
		_hash = a_hash->Clone();
		SetKey(hmacKey);
		_ipad.resize(_hash->GetBlockSize());
		_opad.resize(_hash->GetBlockSize());
	} // end constructor

	~HMACNotBuildInAdapter()
	{
		Clear();
	} // end destructor

	static IHMACNotBuildIn CreateHMAC(const IHash a_hash, const HashLibByteArray& hmacKey)
	{
		if (!a_hash) throw ArgumentNullHashLibException("hash");
		return make_shared<HMACNotBuildInAdapter>(a_hash, hmacKey);
	} //

	virtual string GetName() const
	{
		return Utils::string_format("HMACNotBuildIn(%s)", _hash->GetName().c_str());
	}

	HMACNotBuildInAdapter(const HMACNotBuildInAdapter& a_hash)
	{
		_hash = a_hash._hash->Clone();

		_opad = a_hash._opad;
		_ipad = a_hash._ipad;
		_key = a_hash._key;
		_workingKey = a_hash._workingKey;

		SetBufferSize(a_hash.GetBufferSize());
		SetBlockSize(a_hash.GetBlockSize());
		SetHashSize(a_hash.GetHashSize());
	}

	virtual IHash Clone() const
	{
		return make_shared<HMACNotBuildInAdapter>(Copy());
	}

	virtual IHMACNotBuildIn CloneHMAC() const
	{
		return make_shared<HMACNotBuildInAdapter>(Copy());
	}

	virtual IMACNotBuildIn CloneMAC() const
	{
		return make_shared<HMACNotBuildInAdapter>(Copy());
	}

	virtual void Clear()
	{
		ArrayUtils::zeroFill(_key);
		ArrayUtils::zeroFill(_workingKey);
	} // end function Clear

	virtual void Initialize()
	{
		_hash->Initialize();
		UpdatePads();
		_hash->TransformBytes(_ipad);
	} // end function Initialize

	virtual IHashResult TransformFinal()
	{
		IHashResult result = _hash->TransformFinal();
		_hash->TransformBytes(_opad);
		_hash->TransformBytes(result->GetBytes());
		result = _hash->TransformFinal();
		Initialize();
		return result;
	} // end function TransformFinal

	virtual void TransformBytes(const HashLibByteArray& a_data, Int32 a_index, Int32 a_length)
	{
		_hash->TransformBytes(a_data, a_index, a_length);
	} // end function TransformBytes

	virtual HashLibByteArray GetWorkingKey() const
	{
		return _workingKey;
	} // end function GetWorkingKey

	virtual HashLibByteArray GetKey() const
	{
		return _key;
	} // end function GetKey

	virtual NullableInteger GetKeyLength() const
	{
		return NullableInteger();
	} // end function GetKeyLength

	virtual void SetKey(const HashLibByteArray& value)
	{
		_key = value;
		TransformKey();
	} // end function SetKey

	void UpdatePads()
	{
		Int32 idx = 0;

		Int32 blockSize = _hash->GetBlockSize();

		memset(&_ipad[0], 0x36, blockSize * sizeof(byte));
		memset(&_opad[0], 0x5C, blockSize * sizeof(byte));

		Int32 length = (Int32)_workingKey.size();
		while (idx < length && idx < _hash->GetBlockSize())
		{
			_ipad[idx] = (byte)(_ipad[idx] ^ _workingKey[idx]);
			_opad[idx] = (byte)(_opad[idx] ^ _workingKey[idx]);
			idx++;
		}
	} // end function UpdatePads

	/// <summary>
	/// Computes the actual key used for hashing. This will not be the same as the
	/// original key passed to TransformKey() if the original key exceeds the <br />
	/// _hash algorithm's block size. (See RFC 2104, section 2)
	/// </summary>
private:
	void TransformKey()
	{
		Int32 blockSize = _hash->GetBlockSize();
		// Perform RFC 2104, section 2 key adjustment.
		_workingKey = (Int32)_key.size() > blockSize ? _hash->ComputeBytes(_key)->GetBytes() : _key;
	}

private:
	IHash _hash = nullptr;
	HashLibByteArray _opad, _ipad, _key, _workingKey;

}; // end class HMACNotBuildInAdapter
