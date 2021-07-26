#pragma once

#include "../Catch2-2.13.6/single_include/catch2/catch.hpp"

#include "../Base/TestConstants.h"

namespace MACTests
{
	TEST_CASE("MD5_HMACTests")
	{
		string ExpectedString, ActualString;

		string HashOfEmptyData = "74E6F7298A9C2D168935F58C001BAD88";
		string HashOfDefaultData = "E26A378B9A20DE63EE8C29402396553D";
		string HashOfOnetoNine = "56BEDC1F02772E32FDC71214BB795047";
		string HashOfABCDE = "B6DE7A4249C9E8338098CB8B18E14CA5";
	
		IHash HashInstance = HashFactory::HMAC::CreateHMAC(HashFactory::Crypto::CreateMD5(), EmptyBytes);
		IMACNotBuildIn MacInstance = HashFactory::HMAC::CreateHMAC(HashFactory::Crypto::CreateMD5(), EmptyBytes);;
		IMACNotBuildIn MacInstanceTwo = HashFactory::HMAC::CreateHMAC(HashFactory::Crypto::CreateMD5(), OneToNineBytes);;

		SECTION("ChangeKeyAndInitializeWorks")
		{
			ExpectedString = MacInstanceTwo->ComputeBytes(DefaultDataBytes)->ToString();
			MacInstance->SetKey(OneToNineBytes);
			MacInstance->Initialize();
			MacInstance->TransformBytes(DefaultDataBytes);
			ActualString = MacInstance->TransformFinal()->ToString();

			REQUIRE(ExpectedString == ActualString);
		}

		SECTION("TestEmptyString")
		{
			string String = HashOfEmptyData;
			string ActualString = HashInstance->ComputeString(EmptyData)->ToString();

			REQUIRE(String == ActualString);
		}

		SECTION("TestDefaultData")
		{
			string String = HashOfDefaultData;
			string ActualString = HashInstance->ComputeString(DefaultData)->ToString();

			REQUIRE(String == ActualString);
		}

		SECTION("TestOnetoNine")
		{
			string String = HashOfOnetoNine;
			string ActualString = HashInstance->ComputeString(OneToNine)->ToString();

			REQUIRE(String == ActualString);
		}

		SECTION("TestBytesABCDE")
		{
			string String = HashOfABCDE;
			string ActualString = HashInstance->ComputeBytes(BytesABCDE)->ToString();

			REQUIRE(String == ActualString);
		}
		
		SECTION("TestSettingNullHashInstanceThrowsCorrectException")
		{
			REQUIRE_THROWS_AS(
				HashFactory::HMAC::CreateHMAC(nullptr, EmptyBytes),
				ArgumentNullHashLibException);
		}

		SECTION("TestMACCloneIsCorrect")
		{
			IMACNotBuildIn Original = MacInstance;
			IMACNotBuildIn Copy;

			Original->SetKey(HMACLongKeyBytes);
			Original->Initialize();
			Original->TransformBytes(ChunkOne);

			// Make Copy Of Current State
			Copy = Original->CloneMAC();

			Original->TransformBytes(ChunkTwo);
			string String = Original->TransformFinal()->ToString();

			Copy->TransformBytes(ChunkTwo);
			string ActualString = Copy->TransformFinal()->ToString();

			REQUIRE(String == ActualString);
		}

	}
}
