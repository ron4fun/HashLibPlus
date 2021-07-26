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

#include "../Enum/HashRounds.h"
#include "../Enum/HashSize.h"
#include "../Interfaces/IHash.h"
#include "../Interfaces/ICRC.h"
#include "../Interfaces/IHashInfo.h"
#include "../Utils/HashLibTypes.h"

#include "../Params/Argon2Parameters.h"
#include "../Params/Blake2SParams.h"
#include "../Params/Blake2BParams.h"
#include "../Params/Blake2XSParams.h"
#include "../Params/Blake2XBParams.h"

#include "../Interfaces/IBlake2BConfigurations/IBlake2BConfig.h"
#include "../Interfaces/IBlake2BConfigurations/IBlake2BTreeConfig.h"
#include "../Interfaces/IBlake2SConfigurations/IBlake2SConfig.h"
#include "../Interfaces/IBlake2SConfigurations/IBlake2STreeConfig.h"

namespace HashFactory
{
	// ====================== Checksum ====================== 
	namespace Checksum
	{
		IHash CreateCRC(const Int32 a_Width, const Int64 a_Polynomial, const Int64 a_InitialValue,
			const bool a_ReflectIn, const bool a_ReflectOut, const Int64 a_OutputXor, const Int64 a_CheckValue,
			const HashLibStringArray& a_Names);

		ICRC CreateCRC(const CRCStandard& a_Value);

		IHash CreateCRC16(const Int64 a_Polynomial, const Int64 a_InitialValue,
			const bool a_ReflectIn, const bool a_ReflectOut, const Int64 a_OutputXor, const Int64 a_CheckValue,
			const HashLibStringArray& a_Names);

		IHash CreateCRC32(const Int64 a_Polynomial, const Int64 a_InitialValue,
			const bool a_ReflectIn, const bool a_ReflectOut, const Int64 a_OutputXor, const Int64 a_CheckValue,
			const HashLibStringArray& a_Names);

		IHash CreateCRC64(const Int64 a_Polynomial, const Int64 a_InitialValue,
			const bool a_ReflectIn, const bool a_ReflectOut, const Int64 a_OutputXor, const Int64 a_CheckValue,
			const HashLibStringArray& a_Names);

		/// <summary>
		/// BUYPASS, polynomial = 0x8005
		/// </summary>
		/// <returns></returns>
		IHash CreateCRC16_BUYPASS();

		/// <summary>
		/// PKZIP, polynomial = 0x04C11DB7, reversed = 0xEDB88320
		/// </summary>
		/// <returns></returns>
		IHash CreateCRC32_PKZIP();

		/// <summary>
		/// Castagnoli, polynomial = 0x1EDC6F41, reversed = 0x82F63B78
		/// </summary>
		/// <returns></returns>
		IHash CreateCRC32_CASTAGNOLI();

		/// <summary>
		/// ECMA-182, polynomial = 0x42F0E1EBA9EA3693
		/// </summary>
		/// <returns></returns>
		IHash CreateCRC64_ECMA_182();

		IHash CreateAdler32();
	} // end namespace Checksum

	// ====================== Crypto ======================
	namespace Crypto
	{
		/// <summary>
		///
		/// </summary>
		/// <param name="a_hash_size">16, 20 or 24 bytes. </param>
		/// <param name="a_rounds">no of rounds (standard rounds are 3, 4 and 5)</param>
		/// <returns></returns>
		IHash CreateTiger(const Int32 a_hash_size, const HashRounds& a_rounds);

		IHash CreateTiger_3_128();

		IHash CreateTiger_3_160();

		IHash CreateTiger_3_192();

		IHash CreateTiger_4_128();

		IHash CreateTiger_4_160();

		IHash CreateTiger_4_192();

		IHash CreateTiger_5_128();

		IHash CreateTiger_5_160();

		IHash CreateTiger_5_192();

		/// <summary>
		///
		/// </summary>
		/// <param name="a_hash_size">16, 20 or 24 bytes. </param>
		/// <param name="a_rounds">no of rounds (standard rounds are 3, 4 and 5)</param>
		/// <returns></returns>
		IHash CreateTiger2(const Int32 a_hash_size, const HashRounds& a_rounds);

		IHash CreateTiger2_3_128();

		IHash CreateTiger2_3_160();

		IHash CreateTiger2_3_192();

		IHash CreateTiger2_4_128();

		IHash CreateTiger2_4_160();

		IHash CreateTiger2_4_192();

		IHash CreateTiger2_5_128();

		IHash CreateTiger2_5_160();

		IHash CreateTiger2_5_192();

		
		IHash CreateMD2();

		IHash CreateMD4();

		IHash CreateMD5();

		
		IHash CreateSHA0();

		IHash CreateSHA1();

		IHash CreateSHA2_224();

		IHash CreateSHA2_256();

		IHash CreateSHA2_384();

		IHash CreateSHA2_512();

		IHash CreateSHA2_512_224();

		IHash CreateSHA2_512_256();

		
		IHash CreateGrindahl256();

		IHash CreateGrindahl512();


		IHash CreatePanama();

		IHash CreateWhirlPool();


		IHash CreateRadioGatun32();

		IHash CreateRadioGatun64();

		/// <summary>
		///
		/// </summary>
		/// <param name="a_security_level">any Integer value greater than 0. Standard is 8. </param>
		/// <param name="a_hash_size">128bit, 256bit</param>
		/// <returns></returns>
		IHash CreateSnefru(const Int32 a_security_level, const HashSize& a_hash_size);

		IHash CreateSnefru_8_128();

		IHash CreateSnefru_8_256();


		IHash CreateHaval_3_128();

		IHash CreateHaval_4_128();

		IHash CreateHaval_5_128();

		IHash CreateHaval_3_160();

		IHash CreateHaval_4_160();

		IHash CreateHaval_5_160();

		IHash CreateHaval_3_192();

		IHash CreateHaval_4_192();

		IHash CreateHaval_5_192();

		IHash CreateHaval_3_224();

		IHash CreateHaval_4_224();

		IHash CreateHaval_5_224();

		IHash CreateHaval_3_256();

		IHash CreateHaval_4_256();

		IHash CreateHaval_5_256();

		/// <summary>
		///
		/// </summary>
		/// <param name="a_rounds">3, 4, 5</param>
		/// <param name="a_hash_size">128, 160, 192, 224, 256</param>
		/// <returns></returns>
		IHash CreateHaval(const HashRounds& a_rounds, const HashSize& a_hash_size);

		
		
		IHash CreateGost();

		IHash CreateGOST3411_2012_256();

		IHash CreateGOST3411_2012_512();

		
		IHash CreateHAS160();


		IHash CreateRIPEMD();

		IHash CreateRIPEMD128();

		IHash CreateRIPEMD160();

		IHash CreateRIPEMD256();

		IHash CreateRIPEMD320();

		IHash CreateSHA3_224();

		IHash CreateSHA3_256();

		IHash CreateSHA3_384();

		IHash CreateSHA3_512();

		IHash CreateKeccak_224();

		IHash CreateKeccak_256();

		IHash CreateKeccak_288();

		IHash CreateKeccak_384();

		IHash CreateKeccak_512();

		IHash CreateBlake2B(IBlake2BConfig a_Config = nullptr, IBlake2BTreeConfig a_TreeConfig = nullptr);
		
		IHash CreateBlake2B_160();

		IHash CreateBlake2B_256();

		IHash CreateBlake2B_384();

		IHash CreateBlake2B_512();
	
		IHash CreateBlake2S(IBlake2SConfig a_Config = nullptr, IBlake2STreeConfig a_TreeConfig = nullptr);

		IHash CreateBlake2S_128();

		IHash CreateBlake2S_160();

		IHash CreateBlake2S_224();

		IHash CreateBlake2S_256();

		IHash CreateBlake2BP(const Int32 a_HashSize, const HashLibByteArray& a_Key);

		IHash CreateBlake2SP(const Int32 a_HashSize, const HashLibByteArray& a_Key);

		IHash CreateBlake3_256(const HashLibByteArray& key);

		IHash CreateBlake3_256();

	} // end namespace Crypto

	// ====================== Hash64 ====================== 
	namespace Hash32
	{
		IHash CreateAP();

		IHash CreateBernstein();

		IHash CreateBernstein1();

		IHash CreateBKDR();

		IHash CreateDEK();

		IHash CreateDJB();

		IHash CreateELF();

		IHash CreateFNV32();

		IHash CreateFNV1a_32();

		IHash CreateJenkins3(const Int32 initialValue = 0);

		IHash CreateJS();

		IHashWithKey CreateMurmur2_32();

		IHashWithKey CreateMurmurHash3_x86_32();

		IHash CreateOneAtTime();

		IHash CreatePJW();

		IHash CreateRotating();

		IHash CreateRS();

		IHash CreateSDBM();

		IHash CreateShiftAndXor();

		IHash CreateSuperFast();

		IHashWithKey CreateXXHash32();
	} // end namespace Hash64

	// ====================== Hash64 ====================== 
	namespace Hash64
	{
		IHash CreateFNV64();

		IHash CreateFNV1a_64();

		IHashWithKey CreateMurmur2_64();

		IHashWithKey CreateSipHash64_2_4();

		IHashWithKey CreateXXHash64();

	} // end namespace Hash64

	// ====================== Hash128 ======================
	namespace Hash128
	{
		IHashWithKey CreateSipHash128_2_4();

		IHashWithKey CreateMurmurHash3_x86_128();

		IHashWithKey CreateMurmurHash3_x64_128();

	} // end namespace Hash128

	// ====================== KDF ======================
	namespace KDF
	{
		/// <summary>
		/// Initializes a new interface instance of the PBKDF2HMAC class using a password, a salt, a number
		/// of iterations and an instance of an "IHash" to be transformed to an "IHMACNotBuiltIn" so it
		/// can be used to derive the key.
		/// </summary>
		/// <param name="_hash">The name of the "IHash" to be transformed to an "IHMACNotBuiltIn" Instance so
		/// it can be used to derive the key.</param>
		/// <param name="password">The password to derive the key for.</param>
		/// <param name="salt">The salt to use to derive the key.</param>
		/// <param name="iterations">The number of iterations used to derive the key.</param>
		IPBKDF2_HMACNotBuildIn CreatePBKDF2_HMAC(const IHash _hash, const HashLibByteArray& password,
			const HashLibByteArray& salt, const UInt32 iterations);

		IPBKDF_ScryptNotBuildIn CreatePBKDF_Scrypt(const HashLibByteArray& password, const HashLibByteArray& salt,
			const Int32 cost, const Int32 blockSize, const Int32 parallelism);

		IPBKDF_Blake3NotBuildIn CreatePBKDF_Blake3(const HashLibByteArray& srcKey, const HashLibByteArray& ctx);

		IPBKDF_Argon2NotBuildIn CreatePBKDF_Argon2(const HashLibByteArray& password, 
			const IArgon2Parameters parameters);	
	}

	// ====================== HMAC ======================
	namespace HMAC
	{
		IHMACNotBuildIn CreateHMAC(const IHash _hash, const HashLibByteArray& hmacKey = {});
	} // end namespace HMAC

	// ====================== KMAC ======================
	namespace KMAC
	{
		IKMACNotBuildIn CreateKMAC128(const HashLibByteArray& kmacKey, const HashLibByteArray& customization,
			const UInt64 outputLengthInBits);;

		IKMACNotBuildIn CreateKMAC256(const HashLibByteArray& kmacKey, const HashLibByteArray& customization,
			const UInt64 outputLengthInBits);
	} // end namespace KMAC

	// ====================== Blake2BMAC ======================
	namespace Blake2BMAC
	{
		IBlake2BMACNotBuildIn CreateBlake2BMAC(const HashLibByteArray& key, const HashLibByteArray& salt,
			const HashLibByteArray& personalization, const Int32 outputLengthInBits);
	} // end namespace Blake2BMAC

	// ====================== Blake2SMAC ======================
	namespace Blake2SMAC
	{
		IBlake2SMACNotBuildIn CreateBlake2SMAC(const HashLibByteArray& key, const HashLibByteArray& salt,
			const HashLibByteArray& personalization, const Int32 outputLengthInBits);
	} // end namespace Blake2SMAC
	
	// ====================== XOF ======================
	namespace XOF
	{
		IXOF CreateBlake2XB(const IBlake2XBConfig config, const UInt64 xofSizeInBits);
		IXOF CreateBlake2XB(const HashLibByteArray& key, const UInt64 xofSizeInBits);

		IXOF CreateBlake2XS(const IBlake2XSConfig config, const UInt64 xofSizeInBits);
		IXOF CreateBlake2XS(const HashLibByteArray& key, const UInt64 xofSizeInBits);

		IXOF CreateBlake3XOF(const HashLibByteArray& key, const UInt64 xofSizeInBits);

		IXOF CreateCShake_128(const HashLibByteArray& n, const HashLibByteArray& s, const UInt64 xofSizeInBits);
		IXOF CreateCShake_256(const HashLibByteArray& n, const HashLibByteArray& s, const UInt64 xofSizeInBits);

		IXOF CreateKMAC128XOF(const HashLibByteArray& kmacKey, const HashLibByteArray& customization,
			const UInt64 xofSizeInBits);
		IXOF CreateKMAC256XOF(const HashLibByteArray& kmacKey, const HashLibByteArray& customization,
			const UInt64 xofSizeInBits);

		IXOF CreateShake_128(const UInt64 xofSizeInBits);
		IXOF CreateShake_256(const UInt64 xofSizeInBits);
	}

	// ====================== NullDigest ======================
	namespace NullDigestFactory
	{
		IHash CreateNullDigest();
	}

} // end namespace HashFactory
