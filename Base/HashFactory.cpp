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

// Checksum Units //
#include "../Checksum/Adler32.h"
#include "../Checksum/CRC16.h"
#include "../Checksum/CRC32.h"
#include "../Checksum/CRC32Fast.h"
#include "../Checksum/CRC64.h"

// Hash32 Units //
#include "../Hash32/AP.h"
#include "../Hash32/Bernstein.h"
#include "../Hash32/Bernstein1.h"
#include "../Hash32/BKDR.h"
#include "../Hash32/DEK.h"
#include "../Hash32/DJB.h"
#include "../Hash32/ELF.h"
#include "../Hash32/FNV32.h"
#include "../Hash32/FNV1a_32.h"
#include "../Hash32/Jenkins3.h"
#include "../Hash32/JS.h"
#include "../Hash32/Murmur2_32.h"
#include "../Hash32/MurmurHash3_x86_32.h"
#include "../Hash32/OneAtTime.h"
#include "../Hash32/Rotating.h"
#include "../Hash32/PJW.h"
#include "../Hash32/RS.h"
#include "../Hash32/ShiftAndXor.h"
#include "../Hash32/SDBM.h"
#include "../Hash32/SuperFast.h"
#include "../Hash32/XXHash32.h"

// Hash64 Units //
#include "../Hash64/FNV64.h"
#include "../Hash64/FNV1a_64.h"
#include "../Hash64/Murmur2_64.h"
#include "../Hash64/SipHash64.h"
#include "../Hash64/XXHash64.h"

// Hash128 Units //
#include "../Hash128/SipHash128.h"
#include "../Hash128/MurmurHash3_x86_128.h"
#include "../Hash128/MurmurHash3_x64_128.h"

// Crypto Units
#include "../Crypto/Blake2B.h"
#include "../Crypto/Blake2S.h"
#include "../Crypto/Blake2BP.h"
#include "../Crypto/Blake2SP.h"
#include "../Crypto/Blake3.h"
#include "../Crypto/Tiger.h"
#include "../Crypto/Tiger2.h"
#include "../Crypto/MD2.h"
#include "../Crypto/MD4.h"
#include "../Crypto/MD5.h"
#include "../Crypto/SHA0.h"
#include "../Crypto/SHA1.h"
#include "../Crypto/SHA2_224.h"
#include "../Crypto/SHA2_256.h"
#include "../Crypto/SHA2_384.h"
#include "../Crypto/SHA2_512.h"
#include "../Crypto/SHA2_512_224.h"
#include "../Crypto/SHA2_512_256.h"
#include "../Crypto/Grindahl256.h"
#include "../Crypto/Grindahl512.h"
#include "../Crypto/Panama.h"
#include "../Crypto/WhirlPool.h"
#include "../Crypto/RadioGatun32.h"
#include "../Crypto/RadioGatun64.h"
#include "../Crypto/Snefru.h"
#include "../Crypto/Haval.h"
#include "../Crypto/Gost.h"
#include "../Crypto/GOST3411_2012.h"
#include "../Crypto/HAS160.h"
#include "../Crypto/RIPEMD.h"
#include "../Crypto/RIPEMD128.h"
#include "../Crypto/RIPEMD160.h"
#include "../Crypto/RIPEMD256.h"
#include "../Crypto/RIPEMD320.h"
#include "../Crypto/SHA3.h"

// KDF
#include "../KDF/PBKDF2_HMACNotBuildIn.h"
#include "../KDF/PBKDF_ScryptNotBuildIn.h"
#include "../KDF/PBKDF_Blake3NotBuildIn.h"
#include "../KDF/PBKDF_Argon2NotBuildIn.h"

// HMAC
#include "../MAC/HMACNotBuildInAdapter.h"

// KMAC
#include "../MAC/KMACNotBuildInAdapter.h"

// MAC
#include "../MAC/Blake2BMACNotBuiltIn.h"
#include "../MAC/Blake2SMACNotBuiltIn.h"

// NullDigest
#include "../NullDigest/NullDigest.h"

#include "HashFactory.h"

// ====================== Checksum ======================
IHash HashFactory::Checksum::CreateAdler32()
{
	return make_shared<Adler32>();
} // end function CreateAdler32

IHash HashFactory::Checksum::CreateCRC(const Int32 a_Width, const Int64 a_Polynomial, const Int64 a_InitialValue,
	const bool a_ReflectIn, const bool a_ReflectOut, const Int64 a_OutputXor, const Int64 a_CheckValue,
	const HashLibStringArray& a_Names)
{
	return make_shared<_CRC>(a_Width, a_Polynomial, a_InitialValue, a_ReflectIn, a_ReflectOut, a_OutputXor, a_CheckValue, a_Names);
} // end function CreateCRC

ICRC HashFactory::Checksum::CreateCRC(const CRCStandard& a_Value)
{
	return _CRC::CreateCRCObject(a_Value);
} // end function CreateCRC

IHash HashFactory::Checksum::CreateCRC16(const Int64 a_Polynomial, const Int64 a_InitialValue,
	const bool a_ReflectIn, const bool a_ReflectOut, const Int64 a_OutputXor, const Int64 a_CheckValue,
	const HashLibStringArray& a_Names)
{
	return make_shared<_CRC16>(a_Polynomial, a_InitialValue, a_ReflectIn, a_ReflectOut, a_OutputXor, a_CheckValue, a_Names);
} // end function CreateCRC16

IHash HashFactory::Checksum::CreateCRC32(const Int64 a_Polynomial, const Int64 a_InitialValue,
	const bool a_ReflectIn, const bool a_ReflectOut, const Int64 a_OutputXor, const Int64 a_CheckValue,
	const HashLibStringArray& a_Names)
{
	return make_shared<_CRC32>(a_Polynomial, a_InitialValue, a_ReflectIn, a_ReflectOut, a_OutputXor, a_CheckValue, a_Names);
} // end function CreateCRC32

IHash HashFactory::Checksum::CreateCRC64(const Int64 a_Polynomial, const Int64 a_InitialValue,
	const bool a_ReflectIn, const bool a_ReflectOut, const Int64 a_OutputXor, const Int64 a_CheckValue,
	const HashLibStringArray& a_Names)
{
	return make_shared<_CRC64>(a_Polynomial, a_InitialValue, a_ReflectIn, a_ReflectOut, a_OutputXor, a_CheckValue, a_Names);
} // end function CreateCRC64

IHash HashFactory::Checksum::CreateCRC16_BUYPASS()
{
	return make_shared<_CRC16_BUYPASS>();
} // end function CreateCRC16_BUYPASS

IHash HashFactory::Checksum::CreateCRC32_PKZIP()
{
	return make_shared<CRC32_PKZIP_Fast>();
} // end function CreateCRC32_PKZIP

IHash HashFactory::Checksum::CreateCRC32_CASTAGNOLI()
{
	return make_shared<CRC32_CASTAGNOLI_Fast>();
} // end function CreateCRC32_CASTAGNOLI

IHash HashFactory::Checksum::CreateCRC64_ECMA_182()
{
	return make_shared<_CRC64_ECMA_182>();
} // end function CreateCRC64_ECMA_182

// ====================== Crypto ======================
IHash HashFactory::Crypto::CreateHAS160()
{
	return make_shared<HAS160>();
} // end function CreateHAS160

IHash HashFactory::Crypto::CreatePanama()
{
	return make_shared<Panama>();
} // end function CreatePanama

IHash HashFactory::Crypto::CreateWhirlPool()
{
	return make_shared<WhirlPool>();
} // end function CreateWhirlPool

///////////////////////////////////////////
/// <summary>
/// Gost Hash Family
/// </summary>
////////////////////////////////////////////

IHash HashFactory::Crypto::CreateGost()
{
	return make_shared<Gost>();
} // end function CreateGost

IHash HashFactory::Crypto::CreateGOST3411_2012_256()
{
	return make_shared<GOST3411_2012_256>();
} // end function CreateGOST3411_2012_256

IHash HashFactory::Crypto::CreateGOST3411_2012_512()
{
	return make_shared<GOST3411_2012_512>();
} // end function CreateGOST3411_2012_512

///////////////////////////////////////////
/// <summary>
/// Haval Hash Family
/// </summary>
////////////////////////////////////////////

/// <summary>
///
/// </summary>
/// <param name="a_rounds">3, 4, 5</param>
/// <param name="a_hash_size">128, 160, 192, 224, 256</param>
/// <returns></returns>
IHash HashFactory::Crypto::CreateHaval(const HashRounds& a_rounds, const HashSize& a_hash_size)
{
	switch (a_rounds)
	{
	case HashRounds::Rounds3:
		switch (a_hash_size)
		{
		case HashSize::HashSize128:
			return CreateHaval_3_128();

		case HashSize::HashSize160:
			return CreateHaval_3_160();

		case HashSize::HashSize192:
			return CreateHaval_3_192();

		case HashSize::HashSize224:
			return CreateHaval_3_224();

		case HashSize::HashSize256:
			return CreateHaval_3_256();

		default:
			throw ArgumentHashLibException(Haval::InvalidHavalHashSize);
		} // end switch

	case HashRounds::Rounds4:
		switch (a_hash_size)
		{
		case HashSize::HashSize128:
			return CreateHaval_4_128();

		case HashSize::HashSize160:
			return CreateHaval_4_160();

		case HashSize::HashSize192:
			return CreateHaval_4_192();

		case HashSize::HashSize224:
			return CreateHaval_4_224();

		case HashSize::HashSize256:
			return CreateHaval_4_256();

		default:
			throw ArgumentHashLibException(Haval::InvalidHavalHashSize);
		} // end switch

	case HashRounds::Rounds5:
		switch (a_hash_size)
		{
		case HashSize::HashSize128:
			return CreateHaval_5_128();

		case HashSize::HashSize160:
			return CreateHaval_5_160();

		case HashSize::HashSize192:
			return CreateHaval_5_192();

		case HashSize::HashSize224:
			return CreateHaval_5_224();

		case HashSize::HashSize256:
			return CreateHaval_5_256();

		default:
			throw ArgumentHashLibException(Haval::InvalidHavalHashSize);
		} // end switch

	default:
		throw ArgumentHashLibException(Haval::InvalidHavalRound);
	} // end switch
} // end function Haval

IHash HashFactory::Crypto::CreateHaval_3_128()
{
	return make_shared<Haval_3_128>();
} // end function CreateHaval_3_128

IHash HashFactory::Crypto::CreateHaval_4_128()
{
	return make_shared<Haval_4_128>();
} // end function CreateHaval_4_128

IHash HashFactory::Crypto::CreateHaval_5_128()
{
	return make_shared<Haval_5_128>();
} // end function CreateHaval_5_128

IHash HashFactory::Crypto::CreateHaval_3_160()
{
	return make_shared<Haval_3_160>();
} // end function CreateHaval_3_160

IHash HashFactory::Crypto::CreateHaval_4_160()
{
	return make_shared<Haval_4_160>();
} // end function CreateHaval_4_160

IHash HashFactory::Crypto::CreateHaval_5_160()
{
	return make_shared<Haval_5_160>();
} // end function CreateHaval_5_160

IHash HashFactory::Crypto::CreateHaval_3_192()
{
	return make_shared<Haval_3_192>();
} // end function CreateHaval_3_192

IHash HashFactory::Crypto::CreateHaval_4_192()
{
	return make_shared<Haval_4_192>();
} // end function CreateHaval_4_192

IHash HashFactory::Crypto::CreateHaval_5_192()
{
	return make_shared<Haval_5_192>();
} // end function CreateHaval_5_192

IHash HashFactory::Crypto::CreateHaval_3_224()
{
	return make_shared<Haval_3_224>();
} // end function CreateHaval_3_224

IHash HashFactory::Crypto::CreateHaval_4_224()
{
	return make_shared<Haval_4_224>();
} // end function CreateHaval_4_224

IHash HashFactory::Crypto::CreateHaval_5_224()
{
	return make_shared<Haval_5_224>();
} // end function CreateHaval_5_224

IHash HashFactory::Crypto::CreateHaval_3_256()
{
	return make_shared<Haval_3_256>();
} // end function CreateHaval_3_256

IHash HashFactory::Crypto::CreateHaval_4_256()
{
	return make_shared<Haval_4_256>();
} // end function CreateHaval_4_256

IHash HashFactory::Crypto::CreateHaval_5_256()
{
	return make_shared<Haval_5_256>();
} // end function CreateHaval_5_256

///////////////////////////////////////////
/// <summary>
/// RadioGatun Hash Family
/// </summary>
////////////////////////////////////////////

IHash HashFactory::Crypto::CreateRadioGatun32()
{
	return make_shared<RadioGatun32>();
} // end function CreateRadioGatun32

IHash HashFactory::Crypto::CreateRadioGatun64()
{
	return make_shared<RadioGatun64>();
} // end function CreateRadioGatun64

///////////////////////////////////////////
/// <summary>
/// Grindahl Hash Family
/// </summary>
////////////////////////////////////////////

IHash HashFactory::Crypto::CreateGrindahl256()
{
	return make_shared<Grindahl256>();
} // end function CreateGrindahl256

IHash HashFactory::Crypto::CreateGrindahl512()
{
	return make_shared<Grindahl512>();
} // end function CreateGrindahl512

///////////////////////////////////////////
/// <summary>
/// RIPEMD Hash Family
/// </summary>
////////////////////////////////////////////

IHash HashFactory::Crypto::CreateRIPEMD()
{
	return make_shared<RIPEMD>();
} // end function CreateRIPEMD

IHash HashFactory::Crypto::CreateRIPEMD128()
{
	return make_shared<RIPEMD128>();
} // end function CreateRIPEMD128

IHash HashFactory::Crypto::CreateRIPEMD160()
{
	return make_shared<RIPEMD160>();
} // end function CreateRIPEMD160

IHash HashFactory::Crypto::CreateRIPEMD256()
{
	return make_shared<RIPEMD256>();
} // end function CreateRIPEMD256

IHash HashFactory::Crypto::CreateRIPEMD320()
{
	return make_shared<RIPEMD320>();
} // end function CreateRIPEMD320

///////////////////////////////////////////
/// <summary>
/// Snefru Hash Family
/// </summary>
////////////////////////////////////////////

/// <summary>
///
/// </summary>
/// <param name="a_security_level">any Integer value greater than 0. Standard is 8. </param>
/// <param name="a_hash_size">128bit, 256bit</param>
/// <returns></returns>
IHash HashFactory::Crypto::CreateSnefru(const Int32 a_security_level, const HashSize& a_hash_size)
{
	if (a_security_level < 1)
		throw ArgumentHashLibException(Snefru::InvalidSnefruLevel);

	if ((a_hash_size == HashSize::HashSize128) || (a_hash_size == HashSize::HashSize256))
		return make_shared<Snefru>(a_security_level, (Int32)a_hash_size);
	else
		throw ArgumentHashLibException(Snefru::InvalidSnefruHashSize);
} // end function CreateSnefru

IHash HashFactory::Crypto::CreateSnefru_8_128()
{
	return CreateSnefru(8, HashSize::HashSize128);
} // end function CreateSnefru_8_128

IHash HashFactory::Crypto::CreateSnefru_8_256()
{
	return CreateSnefru(8, HashSize::HashSize256);
} // end function CreateSnefru_8_256

///////////////////////////////////////////
/// <summary>
/// MD Hash Family
/// </summary>
////////////////////////////////////////////

IHash HashFactory::Crypto::CreateMD2()
{
	return make_shared<MD2>();
} // end function CreateMD2

IHash HashFactory::Crypto::CreateMD4()
{
	return make_shared<MD4>();
} // end function CreateMD4

IHash HashFactory::Crypto::CreateMD5()
{
	return make_shared<MD5>();
} // end function CreateMD5

///////////////////////////////////////////
/// <summary>
/// SHA Hash Family
/// </summary>
////////////////////////////////////////////

IHash HashFactory::Crypto::CreateSHA0()
{
	return make_shared<SHA0>();
} // end function CreateSHA0

IHash HashFactory::Crypto::CreateSHA1()
{
	return make_shared<SHA1>();
} // end function CreateSHA1

IHash HashFactory::Crypto::CreateSHA2_224()
{
	return make_shared<SHA2_224>();
} // end function CreateSHA2_224

IHash HashFactory::Crypto::CreateSHA2_256()
{
	return make_shared<SHA2_256>();
} // end function CreateSHA2_256

IHash HashFactory::Crypto::CreateSHA2_384()
{
	return make_shared<SHA2_384>();
} // end function CreateSHA2_384

IHash HashFactory::Crypto::CreateSHA2_512()
{
	return make_shared<SHA2_512>();
} // end function CreateSHA2_512

IHash HashFactory::Crypto::CreateSHA2_512_224()
{
	return make_shared<SHA2_512_224>();
} // end function CreateSHA2_512_224

IHash HashFactory::Crypto::CreateSHA2_512_256()
{
	return make_shared<SHA2_512_256>();
} // end function CreateSHA2_512_256

IHash HashFactory::Crypto::CreateSHA3_224()
{
	return make_shared<SHA3_224>();
} // end function CreateSHA3_224

IHash HashFactory::Crypto::CreateSHA3_256()
{
	return make_shared<SHA3_256>();
} // end function CreateSHA3_256

IHash HashFactory::Crypto::CreateSHA3_384()
{
	return make_shared<SHA3_384>();
} // end function CreateSHA3_384

IHash HashFactory::Crypto::CreateSHA3_512()
{
	return make_shared<SHA3_512>();
} // end function CreateSHA3_512

IHash HashFactory::Crypto::CreateKeccak_224()
{
	return make_shared<Keccak_224>();
} // end function CreateKeccak_224

IHash HashFactory::Crypto::CreateKeccak_256()
{
	return make_shared<Keccak_256>();
} // end function CreateKeccak_256

IHash HashFactory::Crypto::CreateKeccak_288()
{
	return make_shared<Keccak_288>();
} // end function CreateKeccak_288

IHash HashFactory::Crypto::CreateKeccak_384()
{
	return make_shared<Keccak_384>();
} // end function CreateKeccak_384

IHash HashFactory::Crypto::CreateKeccak_512()
{
	return make_shared<Keccak_512>();
} // end function CreateKeccak_512

///////////////////////////////////////////
/// <summary>
/// Blake Hash Family
/// </summary>
////////////////////////////////////////////

IHash HashFactory::Crypto::CreateBlake2B(IBlake2BConfig a_Config, IBlake2BTreeConfig a_TreeConfig)
{
	if (!a_Config)
		a_Config = Blake2BConfig::GetDefaultConfig();
	
	return make_shared<Blake2B>(a_Config, a_TreeConfig);
} // end function CreateBlake2B

IHash HashFactory::Crypto::CreateBlake2B_160()
{
	return HashFactory::Crypto::CreateBlake2B(Blake2BConfig::CreateBlake2BConfig(HashSize::HashSize160));
} // end function CreateBlake2B_160

IHash HashFactory::Crypto::CreateBlake2B_256()
{
	return HashFactory::Crypto::CreateBlake2B(Blake2BConfig::CreateBlake2BConfig(HashSize::HashSize256));
}

IHash HashFactory::Crypto::CreateBlake2B_384()
{
	return HashFactory::Crypto::CreateBlake2B(Blake2BConfig::CreateBlake2BConfig(HashSize::HashSize384));
}

IHash HashFactory::Crypto::CreateBlake2B_512()
{
	return HashFactory::Crypto::CreateBlake2B(Blake2BConfig::CreateBlake2BConfig(HashSize::HashSize512));
}

IHash HashFactory::Crypto::CreateBlake2S(IBlake2SConfig a_Config, IBlake2STreeConfig a_TreeConfig)
{
	IBlake2SConfig _config;

	_config = a_Config;
	if (_config == nullptr)
		_config = Blake2SConfig::GetDefaultConfig();

	return make_shared<Blake2S>(_config, a_TreeConfig);
}

IHash HashFactory::Crypto::CreateBlake2S_128()
{
	return HashFactory::Crypto::CreateBlake2S(Blake2SConfig::CreateBlake2SConfig(HashSize::HashSize128));
}

IHash HashFactory::Crypto::CreateBlake2S_160()
{
	return HashFactory::Crypto::CreateBlake2S(Blake2SConfig::CreateBlake2SConfig(HashSize::HashSize160));
}

IHash HashFactory::Crypto::CreateBlake2S_224()
{
	return HashFactory::Crypto::CreateBlake2S(Blake2SConfig::CreateBlake2SConfig(HashSize::HashSize224));
}

IHash HashFactory::Crypto::CreateBlake2S_256()
{
	return HashFactory::Crypto::CreateBlake2S(Blake2SConfig::CreateBlake2SConfig(HashSize::HashSize256));
}

IHash HashFactory::Crypto::CreateBlake2BP(const Int32 a_HashSize, const HashLibByteArray& a_Key)
{
	return make_shared<Blake2BP>(a_HashSize, a_Key);
}

IHash HashFactory::Crypto::CreateBlake2SP(const Int32 a_HashSize, const HashLibByteArray& a_Key)
{
	return make_shared<Blake2SP>(a_HashSize, a_Key);
}

IHash HashFactory::Crypto::CreateBlake3_256(const HashLibByteArray& key)
{
	return make_shared<Blake3>(HashSize::HashSize256, key);
}

IHash HashFactory::Crypto::CreateBlake3_256()
{
	return make_shared<Blake3>(HashSize::HashSize256, HashLibByteArray());
}

///////////////////////////////////////////
/// <summary>
/// Tiger Hash Family
/// </summary>
////////////////////////////////////////////

/// <summary>
/// Tiger Hash
/// </summary>
/// <param name="a_hash_size">16, 20 or 24 bytes. </param>
/// <param name="a_rounds">no of rounds (standard rounds are 3, 4 and 5)</param>
/// <returns></returns>
IHash HashFactory::Crypto::CreateTiger(const Int32 a_hash_size, const HashRounds& a_rounds)
{
	if ((a_hash_size != 16) && (a_hash_size != 20) && (a_hash_size != 24))
		throw ArgumentHashLibException(Tiger::InvalidTigerHashSize);

	return make_shared<Tiger_Base>(a_hash_size, a_rounds);
} // end function CreateTiger

IHash HashFactory::Crypto::CreateTiger_3_128()
{
	return Tiger_128::CreateRound3();
} // end function CreateTiger_3_128

IHash HashFactory::Crypto::CreateTiger_3_160()
{
	return Tiger_160::CreateRound3();
} // end function CreateTiger_3_160

IHash HashFactory::Crypto::CreateTiger_3_192()
{
	return Tiger_192::CreateRound3();
} // end function CreateTiger_3_192

IHash HashFactory::Crypto::CreateTiger_4_128()
{
	return Tiger_128::CreateRound4();
} // end function CreateTiger_4_128

IHash HashFactory::Crypto::CreateTiger_4_160()
{
	return Tiger_160::CreateRound4();
} // end function CreateTiger_4_160

IHash HashFactory::Crypto::CreateTiger_4_192()
{
	return Tiger_192::CreateRound4();
} // end function CreateTiger_4_192

IHash HashFactory::Crypto::CreateTiger_5_128()
{
	return Tiger_128::CreateRound5();
} // end function CreateTiger_5_128

IHash HashFactory::Crypto::CreateTiger_5_160()
{
	return Tiger_160::CreateRound5();
} // end function CreateTiger_5_160

IHash HashFactory::Crypto::CreateTiger_5_192()
{
	return Tiger_192::CreateRound5();
} // end function CreateTiger_5_192

///////////////////////////////////////////
/// <summary>
/// Tiger2 Hash Family
/// </summary>
////////////////////////////////////////////

/// <summary>
/// Tiger2 Hash
/// </summary>
/// <param name="a_hash_size">16, 20 or 24 bytes. </param>
/// <param name="a_rounds">no of rounds (standard rounds are 3, 4 and 5)</param>
/// <returns></returns>
IHash HashFactory::Crypto::CreateTiger2(const Int32 a_hash_size, const HashRounds& a_rounds)
{
	if ((a_hash_size != 16) && (a_hash_size != 20) && (a_hash_size != 24))
		throw ArgumentHashLibException(Tiger2::InvalidTiger2HashSize);

	return make_shared<Tiger2_Base>(a_hash_size, a_rounds);
} // end function CreateTiger2

IHash HashFactory::Crypto::CreateTiger2_3_128()
{
	return Tiger2_128::CreateRound3();
} // end function CreateTiger2_3_128

IHash HashFactory::Crypto::CreateTiger2_3_160()
{
	return Tiger2_160::CreateRound3();
} // end function CreateTiger2_3_160

IHash HashFactory::Crypto::CreateTiger2_3_192()
{
	return Tiger2_192::CreateRound3();
} // end function CreateTiger2_3_192

IHash HashFactory::Crypto::CreateTiger2_4_128()
{
	return Tiger2_128::CreateRound4();
} // end function CreateTiger2_4_128

IHash HashFactory::Crypto::CreateTiger2_4_160()
{
	return Tiger2_160::CreateRound4();
} // end function CreateTiger2_4_160

IHash HashFactory::Crypto::CreateTiger2_4_192()
{
	return Tiger2_192::CreateRound4();
} // end function CreateTiger2_4_192

IHash HashFactory::Crypto::CreateTiger2_5_128()
{
	return Tiger2_128::CreateRound5();
} // end function CreateTiger2_5_128

IHash HashFactory::Crypto::CreateTiger2_5_160()
{
	return Tiger2_160::CreateRound5();
} // end function CreateTiger2_5_160

IHash HashFactory::Crypto::CreateTiger2_5_192()
{
	return Tiger2_192::CreateRound5();
} // end function CreateTiger2_5_192


// ====================== Hash32 ====================== 
IHash HashFactory::Hash32::CreateAP()
{
	return make_shared<AP>();
} //

IHash HashFactory::Hash32::CreateBernstein()
{
	return make_shared<Bernstein>();
} //

IHash HashFactory::Hash32::CreateBernstein1()
{
	return make_shared<Bernstein1>();
} //

IHash HashFactory::Hash32::CreateBKDR()
{
	return make_shared<BKDR>();
} //

IHash HashFactory::Hash32::CreateDEK()
{
	return make_shared<DEK>();
} //

IHash HashFactory::Hash32::CreateDJB()
{
	return make_shared<DJB>();
} //

IHash HashFactory::Hash32::CreateELF()
{
	return make_shared<ELF>();
} //

IHash HashFactory::Hash32::CreateFNV32()
{
	return make_shared<FNV32>();
} //

IHash HashFactory::Hash32::CreateFNV1a_32()
{
	return make_shared<FNV1a_32>();
} //

IHash HashFactory::Hash32::CreateJenkins3(const Int32 initialValue)
{
	return make_shared<Jenkins3>(initialValue);
} //

IHash HashFactory::Hash32::CreateJS()
{
	return make_shared<JS>();
} //

IHashWithKey HashFactory::Hash32::CreateMurmur2_32()
{
	return make_shared<Murmur2_32>();
} //

IHashWithKey HashFactory::Hash32::CreateMurmurHash3_x86_32()
{
	return make_shared<MurmurHash3_x86_32>();
} //

IHash HashFactory::Hash32::CreateOneAtTime()
{
	return make_shared<OneAtTime>();
} //

IHash HashFactory::Hash32::CreatePJW()
{
	return make_shared<PJW>();
} //

IHash HashFactory::Hash32::CreateRotating()
{
	return make_shared<Rotating>();
} //

IHash HashFactory::Hash32::CreateRS()
{
	return make_shared<RS>();
} //

IHash HashFactory::Hash32::CreateSDBM()
{
	return make_shared<SDBM>();
} //

IHash HashFactory::Hash32::CreateShiftAndXor()
{
	return make_shared<ShiftAndXor>();
} //

IHash HashFactory::Hash32::CreateSuperFast()
{
	return make_shared<SuperFast>();
} //

IHashWithKey HashFactory::Hash32::CreateXXHash32()
{
	return make_shared<XXHash32>();
} //

// ====================== Hash64 ====================== 
IHash HashFactory::Hash64::CreateFNV64()
{
	return make_shared<FNV64>();
} // end function CreateFNV64

IHash HashFactory::Hash64::CreateFNV1a_64()
{
	return make_shared<FNV1a_64>();
} // end function CreateFNV1a

IHashWithKey HashFactory::Hash64::CreateMurmur2_64()
{
	return make_shared<Murmur2_64>();
} // end function CreateMurmur2_64

IHashWithKey HashFactory::Hash64::CreateSipHash64_2_4()
{
	return make_shared<SipHash64_2_4>();
} // end function CreateSipHash2_4

IHashWithKey HashFactory::Hash64::CreateXXHash64()
{
	return make_shared<XXHash64>();
} // end function CreateXXHash64

// ====================== Hash128 ======================
IHashWithKey HashFactory::Hash128::CreateSipHash128_2_4()
{
	return make_shared<SipHash128_2_4>();
} // end function CreateSipHash128_2_4

IHashWithKey HashFactory::Hash128::CreateMurmurHash3_x86_128()
{
	return make_shared<MurmurHash3_x86_128>();
} // end function CreateMurmurHash3_x86_128

IHashWithKey HashFactory::Hash128::CreateMurmurHash3_x64_128()
{
	return make_shared<MurmurHash3_x64_128>();
} // end function CreateMurmurHash3_x64_128

// ====================== KDF ======================
IPBKDF2_HMACNotBuildIn HashFactory::KDF::CreatePBKDF2_HMAC(const IHash hash, const HashLibByteArray& password,
	const HashLibByteArray& salt, const UInt32 iterations)
{
	return make_shared<PBKDF2_HMACNotBuildInAdapter>(hash, password, salt, iterations);
}

IPBKDF_ScryptNotBuildIn HashFactory::KDF::CreatePBKDF_Scrypt(const HashLibByteArray& password, const HashLibByteArray& salt,
	const Int32 cost, const Int32 blockSize, const Int32 parallelism)
{
	return make_shared<PBKDF_ScryptNotBuildInAdapter>(password, salt, cost, blockSize, parallelism);
}
IPBKDF_Blake3NotBuildIn HashFactory::KDF::CreatePBKDF_Blake3(const HashLibByteArray& srcKey, const HashLibByteArray& ctx)
{
	return make_shared<PBKDF_Blake3NotBuildInAdapter>(srcKey, ctx);
}

IPBKDF_Argon2NotBuildIn HashFactory::KDF::CreatePBKDF_Argon2(const HashLibByteArray& password,
	const IArgon2Parameters parameters)
{
	return make_shared<PBKDF_Argon2NotBuildInAdapter>(password, parameters);
}

// ====================== HMAC ======================
IHMACNotBuildIn HashFactory::HMAC::CreateHMAC(const IHash hash, const HashLibByteArray& hmacKey)
{
	if (!hash) throw ArgumentNullHashLibException("hash is null");
	return make_shared<HMACNotBuildInAdapter>(hash, hmacKey);
} // end function CreateHMAC

// ====================== KMAC ======================
IKMACNotBuildIn HashFactory::KMAC::CreateKMAC128(const HashLibByteArray& kmacKey, const HashLibByteArray& customization,
	const UInt64 outputLengthInBits)
{
	return KMAC128::CreateKMAC128(kmacKey, customization, outputLengthInBits);
}

IKMACNotBuildIn HashFactory::KMAC::CreateKMAC256(const HashLibByteArray& kmacKey, const HashLibByteArray& customization,
	const UInt64 outputLengthInBits)
{
	return KMAC256::CreateKMAC256(kmacKey, customization, outputLengthInBits);
}

// ====================== Blake2BMAC ======================
IBlake2BMACNotBuildIn HashFactory::Blake2BMAC::CreateBlake2BMAC(const HashLibByteArray& key, const HashLibByteArray& salt,
	const HashLibByteArray& personalization, const Int32 outputLengthInBits)
{
	return Blake2BMACNotBuildInAdapter::CreateBlake2BMAC(key, salt, personalization, outputLengthInBits);
} // end function CreateBlake2BMAC

// ====================== Blake2SMAC ======================
IBlake2SMACNotBuildIn HashFactory::Blake2SMAC::CreateBlake2SMAC(const HashLibByteArray& key, const HashLibByteArray& salt,
	const HashLibByteArray& personalization, const Int32 outputLengthInBits)
{
	return Blake2SMACNotBuildInAdapter::CreateBlake2SMAC(key, salt, personalization, outputLengthInBits);
} // end function CreateBlake2SMAC

// ====================== XOF ======================
IXOF HashFactory::XOF::CreateBlake2XB(const IBlake2XBConfig config, const UInt64 xofSizeInBits)
{
	IXOF hash = make_shared<Blake2XB>(config);
	hash->SetXOFSizeInBits(xofSizeInBits);
	return hash;
}

IXOF HashFactory::XOF::CreateBlake2XB(const HashLibByteArray& key, const UInt64 xofSizeInBits)
{
	IBlake2BConfig config = make_shared<Blake2BConfig>(64);
	config->SetKey(key);
	return CreateBlake2XB(Blake2XBConfig::CreateBlake2XBConfig(config, nullptr), xofSizeInBits);
}

IXOF HashFactory::XOF::CreateBlake2XS(const IBlake2XSConfig config, const UInt64 xofSizeInBits)
{
	IXOF hash = make_shared<Blake2XS>(config);
	hash->SetXOFSizeInBits(xofSizeInBits);
	return hash;
}

IXOF HashFactory::XOF::CreateBlake2XS(const HashLibByteArray& key, const UInt64 xofSizeInBits)
{
	IBlake2SConfig config = make_shared<Blake2SConfig>(32);
	config->SetKey(key);
	return CreateBlake2XS(Blake2XSConfig::CreateBlake2XSConfig(config, nullptr), xofSizeInBits);
}

IXOF HashFactory::XOF::CreateBlake3XOF(const HashLibByteArray& key, const UInt64 xofSizeInBits)
{
	IXOF hash = make_shared<Blake3XOF>(32, key);
	hash->SetXOFSizeInBits(xofSizeInBits);
	return hash;
}

IXOF HashFactory::XOF::CreateCShake_128(const HashLibByteArray& n, const HashLibByteArray& s, const UInt64 xofSizeInBits)
{
	IXOF hash = make_shared<CShake_128>(n, s);
	hash->SetXOFSizeInBits(xofSizeInBits);
	return hash;
}

IXOF HashFactory::XOF::CreateCShake_256(const HashLibByteArray& n, const HashLibByteArray& s, const UInt64 xofSizeInBits)
{
	IXOF hash = make_shared<CShake_256>(n, s);
	hash->SetXOFSizeInBits(xofSizeInBits);
	return hash;
}

IXOF HashFactory::XOF::CreateKMAC128XOF(const HashLibByteArray& kmacKey, const HashLibByteArray& customization,
	const UInt64 xofSizeInBits)
{
	return KMAC128XOF::CreateKMAC128XOF(kmacKey, customization, xofSizeInBits);
}

IXOF HashFactory::XOF::CreateKMAC256XOF(const HashLibByteArray& kmacKey, const HashLibByteArray& customization,
	const UInt64 xofSizeInBits)
{
	return KMAC256XOF::CreateKMAC256XOF(kmacKey, customization, xofSizeInBits);
}

IXOF HashFactory::XOF::CreateShake_128(const UInt64 xofSizeInBits)
{
	IXOF hash = make_shared<Shake_128>();
	hash->SetXOFSizeInBits(xofSizeInBits);
	return hash;
}

IXOF HashFactory::XOF::CreateShake_256(const UInt64 xofSizeInBits)
{
	IXOF hash = make_shared<Shake_256>();
	hash->SetXOFSizeInBits(xofSizeInBits);
	return hash;
}

// ====================== NullDigest ======================
IHash HashFactory::NullDigestFactory::CreateNullDigest()
{
	return make_shared<NullDigest>();
} // end function CreateNullDigest



