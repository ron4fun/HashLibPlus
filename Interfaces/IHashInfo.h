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

#include "IHash.h"
#include "IKDF.h"
#include "IBlake2BConfigurations/IBlake2BConfig.h"
#include "IBlake2BConfigurations/IBlake2BTreeConfig.h"
#include "IBlake2SConfigurations/IBlake2SConfig.h"
#include "IBlake2SConfigurations/IBlake2STreeConfig.h"
#include "../Enum/Argon2Type.h"
#include "../Enum/Argon2Version.h"
#include "../Nullable/Nullable.h"

class IITransformBlock
{}; // end class ITransformBlock

typedef shared_ptr<IITransformBlock> ITransformBlock;

class IIBlockHash : public virtual IIHash
{ }; // end IBlockHash

typedef shared_ptr<IIBlockHash> IBlockHash;

class IINonBlockHash
{ }; // end INonBlockHash

typedef shared_ptr<IINonBlockHash> INonBlockHash;

class IIChecksum
{ }; // end IChecksum

typedef shared_ptr<IIChecksum> IChecksum;

class IICrypto : public virtual IIBlockHash
{ }; // end ICrypto

typedef shared_ptr<IICrypto> ICrypto;

class IICryptoNotBuildIn : public virtual IICrypto
{ }; // end ICryptoNotBuildIn

typedef shared_ptr<IICryptoNotBuildIn> ICryptoNotBuildIn;

class IIWithKey : public virtual IIHash
{
public:
	virtual HashLibByteArray GetKey() const = 0;
	virtual void SetKey(const HashLibByteArray& value) = 0;
	virtual NullableInteger GetKeyLength() const = 0;
}; // end IWithKey

typedef shared_ptr<IIWithKey> IWithKey;

class IIMAC : public virtual IIHash
{
public:
	virtual void Clear() = 0;

	virtual HashLibByteArray GetKey() const = 0;
	virtual void SetKey(const HashLibByteArray& value) = 0;
}; // end IMAC

typedef shared_ptr<IIMAC> IMAC;

class IIMACNotBuildIn;

typedef shared_ptr<IIMACNotBuildIn> IMACNotBuildIn;

class IIMACNotBuildIn : public virtual IIMAC
{
	friend ostream& operator<<(ostream& output, const IMACNotBuildIn& hash)
	{
		output << hash->GetName();
		return output;
	}
public:
	virtual IMACNotBuildIn CloneMAC() const = 0;
};

class IIHMAC;

typedef shared_ptr<IIHMAC> IHMAC;

class IIHMAC : public virtual IIMACNotBuildIn
{}; // end IHMAC

class IIHMACNotBuildIn;

typedef shared_ptr<IIHMACNotBuildIn> IHMACNotBuildIn;

class IIHMACNotBuildIn : public virtual IIHMAC
{
	friend ostream& operator<<(ostream& output, const IHMACNotBuildIn& hash)
	{
		output << hash->GetName();
		return output;
	}
public:
	virtual HashLibByteArray GetWorkingKey() const = 0;
	virtual IHMACNotBuildIn CloneHMAC() const = 0;
}; // end IHMACNotBuildIn

class IIKMAC : public virtual IIMACNotBuildIn
{ }; // end IKMAC

typedef shared_ptr<IIKMAC> IKMAC;

class IIKMACNotBuildIn : public virtual IIKMAC
{ }; // end IKMACNotBuildIn

typedef shared_ptr<IIKMACNotBuildIn> IKMACNotBuildIn;



#pragma region Blake2 Interfaces

class IIBlake2BMAC : public virtual IIMACNotBuildIn
{}; // end IBlake2BMAC

typedef shared_ptr<IIBlake2BMAC> IBlake2BMAC;

class IIBlake2BMACNotBuildIn : public virtual IIBlake2BMAC
{}; // end IBlake2BMACNotBuildIn

typedef shared_ptr<IIBlake2BMACNotBuildIn> IBlake2BMACNotBuildIn;

class IIBlake2SMAC : public virtual IIMACNotBuildIn
{}; // end IBlake2SMAC

typedef shared_ptr<IIBlake2SMAC> IBlake2SMAC;

class IIBlake2SMACNotBuildIn : public virtual IIBlake2SMAC
{}; // end IBlake2SMACNotBuildIn

typedef shared_ptr<IIBlake2SMACNotBuildIn> IBlake2SMACNotBuildIn;

#pragma endregion


#pragma region Blake2X _config Interfaces

class IIBlake2XBConfig;

typedef shared_ptr<IIBlake2XBConfig> IBlake2XBConfig;

class IIBlake2XBConfig
{
public:
	virtual IBlake2BConfig GetConfig() const = 0;
	virtual IBlake2BTreeConfig GetTreeConfig() const = 0;

	virtual IBlake2BConfig GetConfig() = 0;
	virtual IBlake2BTreeConfig GetTreeConfig() = 0;

	virtual void SetConfig(const IBlake2BConfig value) = 0;
	virtual void SetTreeConfig(const IBlake2BTreeConfig value) = 0;

	virtual IBlake2XBConfig Clone() const = 0;

}; // end class IBlake2XBConfig

class IIBlake2XSConfig;

typedef shared_ptr<IIBlake2XSConfig> IBlake2XSConfig;

class IIBlake2XSConfig
{
public:
	virtual IBlake2SConfig GetConfig() const = 0;
	virtual IBlake2STreeConfig GetTreeConfig() const = 0;

	virtual IBlake2SConfig GetConfig() = 0;
	virtual IBlake2STreeConfig GetTreeConfig() = 0;

	virtual void SetConfig(const IBlake2SConfig value) = 0;
	virtual void SetTreeConfig(const IBlake2STreeConfig value) = 0;

	virtual IBlake2XSConfig Clone() const = 0;
};

#pragma endregion


class IIHash16 : public virtual IIHash
{ }; // end IHash16

typedef shared_ptr<IIHash16> IHash16;

class IIHash32 : public virtual IIHash
{ }; // end IHash32

typedef shared_ptr<IIHash32> IHash32;

class IIHash64 : public virtual IIHash
{ }; // end IHash64

typedef shared_ptr<IIHash64> IHash64;

class IIHash128 : public virtual IIHash
{ }; // end IHash128

typedef shared_ptr<IIHash128> IHash128;

class IIHashWithKey;

typedef shared_ptr<IIHashWithKey> IHashWithKey;

class IIHashWithKey : public virtual IIWithKey
{
	friend ostream& operator<<(ostream& output, const IHashWithKey& hash)
	{
		output << hash->GetName();
		return output;
	}
public:
	virtual IHashWithKey CloneHashWithKey() const = 0;
}; // end IHashWithKey


#pragma region KDF Interfaces

class IIKDFNotBuildIn;

typedef shared_ptr<IIKDFNotBuildIn> IKDFNotBuildIn;

class IIKDFNotBuildIn : public virtual IIKDF
{
public:
	virtual IKDFNotBuildIn Clone() const = 0;
}; // end IIKDFNotBuildIn

class IIPBKDF2_HMAC : public virtual IIKDFNotBuildIn
{ }; // end IPBKDF2_HMAC

typedef shared_ptr<IIPBKDF2_HMAC> IPBKDF2_HMAC;

class IIPBKDF2_HMACNotBuildIn;

typedef shared_ptr<IIPBKDF2_HMACNotBuildIn> IPBKDF2_HMACNotBuildIn;

class IIPBKDF2_HMACNotBuildIn : public virtual IIPBKDF2_HMAC
{
	friend ostream& operator<<(ostream& output, const IPBKDF2_HMACNotBuildIn& hash)
	{
		output << hash->GetName();
		return output;
	}
}; // end IPBKDF2_HMACNotBuildIn

class IIPBKDF_Argon2 : public virtual IIKDFNotBuildIn
{ }; // end IPBKDF_Argon2

typedef shared_ptr<IIPBKDF_Argon2> IPBKDF_Argon2;

class IIPBKDF_Argon2NotBuildIn : public virtual IIPBKDF_Argon2
{ }; // end IPBKDF_Argon2NotBuildIn

typedef shared_ptr<IIPBKDF_Argon2NotBuildIn> IPBKDF_Argon2NotBuildIn;

class IIPBKDF_Scrypt : public virtual IIKDFNotBuildIn
{ }; // end IPBKDF_Scrypt

typedef shared_ptr<IIPBKDF_Scrypt> IPBKDF_Scrypt;

class IIPBKDF_ScryptNotBuildIn : public virtual IIPBKDF_Scrypt
{ }; // end IPBKDF_ScryptNotBuildIn

typedef shared_ptr<IIPBKDF_ScryptNotBuildIn> IPBKDF_ScryptNotBuildIn;

class IIPBKDF_Blake3 : public virtual IIKDFNotBuildIn
{ }; // end IPBKDF_Blake3

class IIPBKDF_Blake3NotBuildIn : public virtual IIPBKDF_Blake3
{ }; // end IPBKDF_Blake3NotBuildIn

typedef shared_ptr<IIPBKDF_Blake3NotBuildIn> IPBKDF_Blake3NotBuildIn;

class IIXOF;

typedef shared_ptr<IIXOF> IXOF;

class IIXOF : public virtual IIHash
{
public:
	virtual IXOF CloneXOF() const = 0;

	virtual UInt64 GetXOFSizeInBits() const = 0;
	virtual void SetXOFSizeInBits(const UInt64 value) = 0;

	virtual void DoOutput(HashLibByteArray& destination, const UInt64 destinationOffset, const UInt64 outputLength) = 0;
}; // end IXOF


#pragma endregion



#pragma region Argon2 Parameter Interfaces

class IIArgon2Parameters;

typedef shared_ptr<IIArgon2Parameters> IArgon2Parameters;

class IIArgon2Parameters
{
public:
	virtual void Clear() = 0;

	virtual HashLibByteArray GetSalt() const = 0;
	virtual HashLibByteArray GetSecret() const = 0;
	virtual HashLibByteArray GetAdditional() const = 0;
	virtual Int32 GetIterations() const = 0;
	virtual Int32 GetMemory() const = 0;
	virtual Int32 GetLanes() const = 0;
	virtual Argon2Type GetType() const = 0;
	virtual Argon2Version GetVersion() const = 0;

	virtual IArgon2Parameters Clone() const = 0;
};  // end IArgon2Parameters

class IIArgon2ParametersBuilder;

typedef shared_ptr<IIArgon2ParametersBuilder> IArgon2ParametersBuilder;

class IIArgon2ParametersBuilder
{
public:
	virtual IArgon2ParametersBuilder WithParallelism(const Int32 a_parallelism) = 0;

	virtual IArgon2ParametersBuilder WithSalt(const HashLibByteArray& a_salt) = 0;

	virtual IArgon2ParametersBuilder WithSecret(const HashLibByteArray& a_secret) = 0;

	virtual IArgon2ParametersBuilder WithAdditional(const HashLibByteArray& a_additional) = 0;

	virtual IArgon2ParametersBuilder WithIterations(const Int32 a_iterations) = 0;

	virtual IArgon2ParametersBuilder WithMemoryAsKiB(const Int32 a_memory) = 0;

	virtual IArgon2ParametersBuilder WithMemoryPowOfTwo(const Int32 a_memory) = 0;

	virtual IArgon2ParametersBuilder WithType(const Argon2Type& a_type) = 0;

	virtual IArgon2ParametersBuilder WithVersion(const Argon2Version& a_version) = 0;

	virtual void Clear() = 0;

	virtual IArgon2Parameters Build() const = 0;

}; // end IArgon2ParametersBuilder

#pragma endregion
