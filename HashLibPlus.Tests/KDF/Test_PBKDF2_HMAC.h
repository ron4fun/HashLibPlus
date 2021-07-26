#pragma once

#include "../Catch2-2.13.6/single_include/catch2/catch.hpp"

#include "../Base/TestConstants.h"

namespace KDFTests
{
	TEST_CASE("PBKDF2_HMACSHA1Test")
	{
		string ExpectedString = "BFDE6BE94DF7E11DD409BCE20A0255EC327CB936FFE93643";
		HashLibByteArray Password = { 0x70, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64 };
		HashLibByteArray Salt = { 0x78, 0x57, 0x8E, 0x5A, 0x5D, 0x63, 0xCB, 0x06 };
		Int32 ByteCount = 24;
		
		IKDFNotBuildIn KdfInstance =
			HashFactory::KDF::CreatePBKDF2_HMAC(HashFactory::Crypto::CreateSHA1(), Password, Salt, 2048);

		UInt32 Iteration = (UInt32)ByteCount;
		Int32 Zero = 0;

		SECTION("TestInvalidByteCountThrowsCorrectException")
		{
			REQUIRE_THROWS_AS(KdfInstance->GetBytes(Zero), ArgumentOutOfRangeHashLibException);
		}

		SECTION("TestNullHashInstanceThrowsCorrectException")
		{
			REQUIRE_THROWS_AS(
				HashFactory::KDF::CreatePBKDF2_HMAC(NullHashInstance, Password, Salt, Iteration), 
				ArgumentNullHashLibException);
		}

		SECTION("TestCorrectResultIsComputed")
		{
			string ActualString = Converters::ConvertBytesToHexString(KdfInstance->GetBytes(ByteCount));
			REQUIRE(ExpectedString == ActualString);
		}

		SECTION("TestKdfCloningWorks")
		{
			IKDFNotBuildIn kdfInstanceClone = KdfInstance->Clone();

			HashLibByteArray result = KdfInstance->GetBytes(ByteCount);
			HashLibByteArray resultClone = kdfInstanceClone->GetBytes(ByteCount);

			REQUIRE(result == resultClone);
		}
	}

	TEST_CASE("PBKDF2_HMACSHA256Test")
	{
		string ExpectedString = "0394A2EDE332C9A13EB82E9B24631604C31DF978B4E2F0FBD2C549944F9D79A5";
		HashLibByteArray Password = { 0x70, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64 };
		HashLibByteArray Salt = { 0x73, 0x61, 0x6C, 0x74 };
		Int32 ByteCount = 32;

		IKDFNotBuildIn KdfInstance =
			HashFactory::KDF::CreatePBKDF2_HMAC(HashFactory::Crypto::CreateSHA2_256(), Password, Salt, 100000);

		UInt32 Iteration = (UInt32)ByteCount;
		Int32 Zero = 0;

		SECTION("TestInvalidByteCountThrowsCorrectException")
		{
			REQUIRE_THROWS_AS(KdfInstance->GetBytes(Zero), ArgumentOutOfRangeHashLibException);
		}

		SECTION("TestNullHashInstanceThrowsCorrectException")
		{
			REQUIRE_THROWS_AS(
				HashFactory::KDF::CreatePBKDF2_HMAC(NullHashInstance, Password, Salt, Iteration),
				ArgumentNullHashLibException);
		}

		SECTION("TestCorrectResultIsComputed")
		{
			string ActualString = Converters::ConvertBytesToHexString(KdfInstance->GetBytes(ByteCount));
			REQUIRE(ExpectedString == ActualString);
		}

		SECTION("TestKdfCloningWorks")
		{
			IKDFNotBuildIn kdfInstanceClone = KdfInstance->Clone();

			HashLibByteArray result = KdfInstance->GetBytes(ByteCount);
			HashLibByteArray resultClone = kdfInstanceClone->GetBytes(ByteCount);

			REQUIRE(result == resultClone);
		}
	}

}