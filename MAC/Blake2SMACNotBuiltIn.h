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

#include "../Crypto/Blake2S.h"

class Blake2SMACNotBuildInAdapter : public Hash, public virtual IIBlake2SMACNotBuildIn, 
	public virtual IICryptoNotBuildIn
{
public:

	~Blake2SMACNotBuildInAdapter()
	{
		Clear();
	}

	virtual IHash Clone() const
	{
		Blake2SMACNotBuildInAdapter HashInstance = Blake2SMACNotBuildInAdapter(_hash, _key);

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<Blake2SMACNotBuildInAdapter>(HashInstance);
	}

	virtual IMACNotBuildIn CloneMAC() const
	{
		Blake2SMACNotBuildInAdapter HashInstance = Blake2SMACNotBuildInAdapter(_hash, _key);

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<Blake2SMACNotBuildInAdapter>(HashInstance);
	} // end function CloneMAC

	virtual void Clear()
	{
		ArrayUtils::zeroFill(_key);
	}

	virtual HashLibByteArray GetKey() const
	{
		return _key;
	}

	virtual void SetKey(const HashLibByteArray& value)
	{
		_key = value;
	}

	virtual void Initialize()
	{
		_hash.GetConfig()->SetKey(_key);
		_hash.Initialize();
	}

	virtual IHashResult TransformFinal()
	{
		return _hash.TransformFinal();
	}

	virtual void TransformBytes(const HashLibByteArray& a_data, const Int32 a_index, const Int32 a_length)
	{
		_hash.TransformBytes(a_data, a_index, a_length);
	}

	static IBlake2SMACNotBuildIn CreateBlake2SMAC(const HashLibByteArray& a_Blake2SKey, const HashLibByteArray& a_Salt,
		const HashLibByteArray& a_Personalisation, const Int32 a_OutputLengthInBits)
	{
		IBlake2SConfig config = Blake2SConfig::CreateBlake2SConfig(a_OutputLengthInBits >> 3);
		config->SetKey(a_Blake2SKey);
		config->SetSalt(a_Salt);
		config->SetPersonalization(a_Personalisation);

		return make_shared<Blake2SMACNotBuildInAdapter>(Blake2S(config, nullptr), config->GetKey());
	}

	Blake2SMACNotBuildInAdapter(const Blake2S a_Hash, const HashLibByteArray& a_Blake2SKey)
		: Hash(a_Hash.GetHashSize(), a_Hash.GetBlockSize())
	{
		_name = "Blake2SMAC";

		SetKey(a_Blake2SKey);
		_hash = a_Hash;
	}

private:
	HashLibByteArray _key;
	Blake2S _hash;

}; // end class Blake2SMACNotBuildInAdapter
