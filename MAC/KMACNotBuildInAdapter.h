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

#include "../Crypto/SHA3.h"
#include "../Utils/ArrayUtils.h"

#pragma region KMAC Family

class KMACNotBuildInAdapter : public Hash, public virtual IIKMACNotBuildIn, 
	public virtual IICryptoNotBuildIn
{
protected:
	IHash _hash = nullptr;
	HashLibByteArray _key, _customization;
	bool _finalized = false;

	static const HashLibByteArray KMAC_Bytes;
	
	KMACNotBuildInAdapter(Int32 a_hash_size)
		: Hash(a_hash_size, 200 - (a_hash_size * 2))
	{ } // end constructor

	~KMACNotBuildInAdapter()
	{
		Clear();
	} // end destructor

	virtual HashLibByteArray GetResult()
	{
		UInt64 XofSizeInBytes = dynamic_cast<IIXOF*>(&(*_hash))->GetXOFSizeInBits() >> 3;

		HashLibByteArray result = HashLibByteArray((Int32)XofSizeInBytes);

		DoOutput(result, 0, XofSizeInBytes);

		return result;
	} // end function GetResult

public:
	virtual void Initialize()
	{
		_finalized = false;
		_hash->Initialize();
		TransformBytes(CShake::BytePad(CShake::EncodeString(GetKey()), GetBlockSize()));
	} // end function Initialize

	virtual IHashResult TransformFinal()
	{
		HashLibByteArray temp = GetResult();

		Initialize();

		return make_shared<HashResult>(temp);
	} // end function TransformFinal

	virtual void TransformBytes(const HashLibByteArray& a_data, const Int32 a_index, const Int32 a_length)
	{
		_hash->TransformBytes(a_data, a_index, a_length);
	} // end function TransformBytes

	virtual void TransformBytes(const HashLibByteArray& a_data)
	{
		TransformBytes(a_data, 0, (Int32)a_data.size());
	} // end function TransformBytes

	virtual void Clear()
	{
		ArrayUtils::zeroFill(_key);
	} // end function Clear

	virtual HashLibByteArray GetKey() const
	{
		return _key;
	}

	virtual void SetKey(const HashLibByteArray& value)
	{
		_key = value;
	}

	virtual string GetName() const
	{
		if (dynamic_cast<const IXOF*>(this) != nullptr)
			return Utils::string_format("%s_%s_%u", _name.c_str(), "XOFSizeInBytes",
				dynamic_cast<IIXOF*>(&(*_hash))->GetXOFSizeInBits() >> 3);

		return _name;
	}

	virtual void DoOutput(HashLibByteArray& destination, const UInt64 destinationOffset, const UInt64 outputLength)
	{
		if (!_finalized)
		{
			TransformBytes(dynamic_cast<const IIXOF*>(this) != nullptr ?
				CShake::RightEncode(0) : CShake::RightEncode(
					dynamic_cast<IIXOF*>(&(*_hash))->GetXOFSizeInBits())
			);
			_finalized = true;
		}
		
		dynamic_cast<IIXOF*>(&(*_hash))->DoOutput(destination, destinationOffset, outputLength);
	} // end function DoOutput
	
}; // end class KMACNotBuildInAdapter

const HashLibByteArray KMACNotBuildInAdapter::KMAC_Bytes = HashLibByteArray({ 75, 77, 65, 67 });

class KMAC128 : public KMACNotBuildInAdapter
{
public:
	KMAC128(const HashLibByteArray& a_KMACKey, const HashLibByteArray& a_Customization,
		const UInt64 a_OutputLengthInBits)
		: KMAC128(make_shared<CShake_128>(KMAC_Bytes, a_Customization), a_KMACKey, a_OutputLengthInBits)
	{} // end constructor

	KMAC128(IHash a_hash, const HashLibByteArray& a_KMACKey, const UInt64 a_OutputLengthInBits)
		: KMACNotBuildInAdapter((Int32)HashSize128)
	{
		_name = __func__;

		_key = a_KMACKey;

		_hash = ::move(a_hash);
		dynamic_cast<IIXOF*>(&(*_hash))->SetXOFSizeInBits(a_OutputLengthInBits);
	} // end constructor

	virtual IHash Clone() const
	{
		// KMAC128 Cloning
		KMAC128 HashInstance = KMAC128(_hash->Clone(), _key, dynamic_cast<IIXOF*>(&(*_hash))->GetXOFSizeInBits());
		HashInstance._finalized = _finalized;
		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<KMAC128>(HashInstance);
	} // end function Clone

	virtual IMACNotBuildIn CloneMAC() const
	{
		// KMAC128 Cloning
		KMAC128 HashInstance = KMAC128(_hash->Clone(), _key, dynamic_cast<IIXOF*>(&(*_hash))->GetXOFSizeInBits());
		HashInstance._finalized = _finalized;
		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<KMAC128>(HashInstance);
	} // end function CloneMAC

	static IKMACNotBuildIn CreateKMAC128(const HashLibByteArray& a_KMACKey, const HashLibByteArray& a_Customization,
		const UInt64 a_OutputLengthInBits)
	{
		return make_shared<KMAC128>(a_KMACKey, a_Customization, a_OutputLengthInBits);
	} // end function CreateKMAC128

}; // end class KMAC128

class KMAC128XOF : public KMACNotBuildInAdapter, public virtual IIXOF
{
protected:
	virtual void DoOutput(HashLibByteArray& destination, const UInt64 destinationOffset, UInt64 outputLength)
	{
		KMACNotBuildInAdapter::DoOutput(destination, destinationOffset, outputLength);
	}

public:
	KMAC128XOF(const HashLibByteArray& a_KMACKey, const HashLibByteArray& a_Customization)
		: KMAC128XOF(make_shared<CShake_128>(KMAC_Bytes, a_Customization), a_KMACKey)
	{} // end constructor
	
	KMAC128XOF(IHash a_hash, const HashLibByteArray& a_KMACKey)
		: KMACNotBuildInAdapter((Int32)HashSize128)
	{
		_name = __func__;

		_key = a_KMACKey;
		
		_hash = ::move(a_hash);
	} // end constructor

	KMAC128XOF Copy() const
	{
		// KMAC128XOF Cloning
		KMAC128XOF HashInstance = KMAC128XOF(_hash->Clone(), _key);
		HashInstance._finalized = _finalized;
		HashInstance.SetXOFSizeInBits(GetXOFSizeInBits());

		HashInstance.SetBufferSize(GetBufferSize());

		return HashInstance;
	} // end function Copy

	virtual IHash Clone() const
	{
		return make_shared<KMAC128XOF>(Copy());
	}

	virtual IXOF CloneXOF() const
	{
		return make_shared<KMAC128XOF>(Copy());
	}

	virtual IMACNotBuildIn CloneMAC() const
	{
		return make_shared<KMAC128XOF>(Copy());
	} // end function CloneMAC

	void inline SetXOFSizeInBitsInternal(const UInt64 a_XofSizeInBits)
	{
		UInt64 XofSizeInBytes = a_XofSizeInBits >> 3;

		if (((XofSizeInBytes & 0x07) != 0) || (XofSizeInBytes < 1))
			throw ArgumentOutOfRangeHashLibException(SHA3::InvalidXOFSize);

		dynamic_cast<IIXOF*>(&(*_hash))->SetXOFSizeInBits(a_XofSizeInBits);
	} // end function SetXOFSizeInBitsInternal

	virtual UInt64 GetXOFSizeInBits() const
	{
		return dynamic_cast<IIXOF*>(&(*_hash))->GetXOFSizeInBits();
	}

	virtual void SetXOFSizeInBits(const UInt64 value)
	{
		SetXOFSizeInBitsInternal(value);
	}

	static IXOF CreateKMAC128XOF(const HashLibByteArray& a_KMACKey, const HashLibByteArray& a_Customization,
		const UInt64 a_XofSizeInBits)
	{
		KMAC128XOF LXof = KMAC128XOF(a_KMACKey, a_Customization);
		LXof.SetXOFSizeInBits(a_XofSizeInBits);

		return make_shared<KMAC128XOF>(LXof);
	} // end function CreateKMAC128XOF

}; // end class KMAC128XOF

class KMAC256 : public KMACNotBuildInAdapter
{
public:
	KMAC256(const IHash a_hash, const HashLibByteArray& a_KMACKey, const HashLibByteArray& a_Customization,
		const UInt64 a_OutputLengthInBits)
		: KMACNotBuildInAdapter((Int32)HashSize256)
	{
		_name = __func__;

		_key = a_KMACKey;
		_customization = a_Customization;

		_hash = ::move(a_hash);
		dynamic_cast<IIXOF*>(&(*_hash))->SetXOFSizeInBits(a_OutputLengthInBits);
	} // end constructor

	KMAC256(const HashLibByteArray& a_KMACKey, const HashLibByteArray& a_Customization,
		const UInt64 a_OutputLengthInBits)
		: KMAC256(make_shared<CShake_256>(KMAC_Bytes, a_Customization),
			a_KMACKey, a_Customization, a_OutputLengthInBits)
	{ } // end constructor

	virtual IHash Clone() const
	{
		// KMAC256 Cloning
		KMAC256 HashInstance(_hash->Clone(), _key, _customization,
			dynamic_cast<IIXOF*>(&(*_hash))->GetXOFSizeInBits());
		HashInstance._finalized = _finalized;
		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<KMAC256>(HashInstance);
	} // end function Clone

	virtual IMACNotBuildIn CloneMAC() const
	{
		// KMAC256 Cloning
		KMAC256 HashInstance(_hash->Clone(), _key, _customization,
			dynamic_cast<IIXOF*>(&(*_hash))->GetXOFSizeInBits());
		HashInstance._finalized = _finalized;
		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<KMAC256>(HashInstance);
	} // end function CloneMAC

	static IKMACNotBuildIn CreateKMAC256(const HashLibByteArray& a_KMACKey, const HashLibByteArray& a_Customization,
		const UInt64 a_OutputLengthInBits)
	{
		return make_shared<KMAC256>(a_KMACKey, a_Customization, a_OutputLengthInBits);
	} // end function CreateKMAC256

}; // end class KMAC256

class KMAC256XOF : public KMACNotBuildInAdapter, public virtual IIXOF
{
protected:
	virtual void DoOutput(HashLibByteArray& destination, const UInt64 destinationOffset, UInt64 outputLength)
	{
		KMACNotBuildInAdapter::DoOutput(destination, destinationOffset, outputLength);
	}

public:
	KMAC256XOF(const HashLibByteArray& a_KMACKey, const HashLibByteArray& a_Customization)
		: KMAC256XOF(make_shared<CShake_256>(KMAC_Bytes, a_Customization),
			a_KMACKey, a_Customization)
	{ } // end constructor

	KMAC256XOF(const IHash a_hash, const HashLibByteArray& a_KMACKey, const HashLibByteArray& a_Customization)
		: KMACNotBuildInAdapter((Int32)HashSize256)
	{
		_name = __func__;

		_key = a_KMACKey;

		_customization = a_Customization;

		_hash = ::move(a_hash);
	} // end constructor

	KMAC256XOF Copy() const
	{
		// KMAC256XOF Cloning
		KMAC256XOF HashInstance(_hash->Clone(), _key, _customization);
		HashInstance._finalized = _finalized;
		HashInstance.SetXOFSizeInBits(GetXOFSizeInBits());

		HashInstance.SetBufferSize(GetBufferSize());

		return HashInstance;
	} // end function Copy

	virtual IHash Clone() const
	{
		return make_shared<KMAC256XOF>(Copy());
	}

	virtual IXOF CloneXOF() const
	{
		return make_shared<KMAC256XOF>(Copy());
	}
	
	virtual IMACNotBuildIn CloneMAC() const
	{
		return make_shared<KMAC256XOF>(Copy());
	} // end function CloneMAC

	void SetXOFSizeInBitsInternal(const UInt64 a_XofSizeInBits)
	{
		UInt64 XofSizeInBytes = a_XofSizeInBits >> 3;

		if (((XofSizeInBytes & 0x07) != 0) || (XofSizeInBytes < 1))
			throw ArgumentOutOfRangeHashLibException(SHA3::InvalidXOFSize);

		dynamic_cast<IIXOF*>(&(*_hash))->SetXOFSizeInBits(a_XofSizeInBits);
	} // end function SetXOFSizeInBitsInternal

	virtual UInt64 GetXOFSizeInBits() const
	{
		return dynamic_cast<IIXOF*>(&(*_hash))->GetXOFSizeInBits();
	}

	virtual void SetXOFSizeInBits(const UInt64 value)
	{
		SetXOFSizeInBitsInternal(value);
	}

	static IXOF CreateKMAC256XOF(const HashLibByteArray& a_KMACKey, const HashLibByteArray& a_Customization,
		const UInt64 a_XofSizeInBits)
	{
		KMAC256XOF LXof(a_KMACKey, a_Customization);
		LXof.SetXOFSizeInBits(a_XofSizeInBits);

		return make_shared<KMAC256XOF>(LXof);
	} // end function CreateKMAC256XOF

}; // end class KMAC256XOF

#pragma endregion
