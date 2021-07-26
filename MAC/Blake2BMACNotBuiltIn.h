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

#include "../Crypto/Blake2B.h"

class Blake2BMACNotBuildInAdapter : public Hash, public virtual IIBlake2BMACNotBuildIn, 
	public virtual IICryptoNotBuildIn
{
public:

	~Blake2BMACNotBuildInAdapter()
	{
		Clear();
	}

	virtual IHash Clone() const override
	{
		Blake2BMACNotBuildInAdapter HashInstance = Blake2BMACNotBuildInAdapter(_hash, _key);

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<Blake2BMACNotBuildInAdapter>(HashInstance);
	}

	virtual IMACNotBuildIn CloneMAC() const
	{
		Blake2BMACNotBuildInAdapter HashInstance = Blake2BMACNotBuildInAdapter(_hash, _key);

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<Blake2BMACNotBuildInAdapter>(HashInstance);
	} // end function CloneMAC

	virtual void Clear() override
	{
		ArrayUtils::zeroFill(_key);
	}

	virtual HashLibByteArray GetKey() const override
	{
		return _key;
	}

	virtual void SetKey(const HashLibByteArray& value) override
	{
		_key = value;
	}

	virtual void Initialize() override
	{
		_hash.GetConfig()->SetKey(_key);
		_hash.Initialize();
	}

	virtual IHashResult TransformFinal() override
	{
		return _hash.TransformFinal();
	}

	virtual void TransformBytes(const HashLibByteArray& a_data, const Int32 a_index, const Int32 a_length) override
	{
		_hash.TransformBytes(a_data, a_index, a_length);
	}

	static IBlake2BMACNotBuildIn CreateBlake2BMAC(const HashLibByteArray& a_Blake2BKey, 
		const HashLibByteArray& a_Salt, const HashLibByteArray& a_Personalisation, const Int32 a_OutputLengthInBits)
	{
		IBlake2BConfig config = Blake2BConfig::CreateBlake2BConfig(a_OutputLengthInBits >> 3);
		config->SetKey(a_Blake2BKey);
		config->SetSalt(a_Salt);
		config->SetPersonalization(a_Personalisation);

		return make_shared<Blake2BMACNotBuildInAdapter>(Blake2B(config, nullptr), config->GetKey());
	}

	Blake2BMACNotBuildInAdapter(const Blake2B& a_Hash, const HashLibByteArray& a_Blake2BKey)
		: Hash(a_Hash.GetHashSize(), a_Hash.GetBlockSize())
	{
		_name = "Blake2BMAC";

		SetKey(a_Blake2BKey);
		_hash = a_Hash;
	}

private:
	HashLibByteArray _key;
	Blake2B _hash;

}; // end class Blake2BMACNotBuildInAdapter
