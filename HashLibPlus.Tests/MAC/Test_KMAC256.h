#pragma once

#include "../Catch2-2.13.6/single_include/catch2/catch.hpp"

#include "../Base/TestConstants.h"

// Function is contained in Test_KMAC128.h file
//
//void DoComputeKMAC(IHash hashInstance, const HashLibByteArray& data, const string& ExpectedString)
//{
//	hashInstance->Initialize();
//	hashInstance->TransformBytes(data);
//	HashLibByteArray result = hashInstance->TransformFinal()->GetBytes();
//
//	string ActualString = Converters::ConvertBytesToHexString(result);
//
//	REQUIRE(ExpectedString == ActualString);
//}

namespace MACTests
{
	TEST_CASE("KMAC256Tests")
	{
		const Int32 OutputSizeInBits = 64 * 8;

		string ExpectedString, ActualString;

		string HashOfEmptyData = "0B002C51EC240A9AE0E9399CECB6A6A136452522342F7E6C17C62B8CD51F583B";
		string HashOfDefaultData = "3669C34F6FC9F4EC516BE3B5ECF8CEC8F10C6AC58A327E43EA0C8F0C3B2BA324";
		string HashOfOnetoNine = "CBE22F258B331B8997CA00C67BB1CF2A3613EAE562198D6C8DA47F6AC99C44EC";
		string HashOfABCDE = "836FA1A76ED65801295522D8A6EF5A4D2C9FFD23BAAF867E06EA6236D8BFA3CE";

		IHash HashInstance = HashFactory::KMAC::CreateKMAC256(EmptyBytes, EmptyBytes, 256);
		IMACNotBuildIn MacInstance = HashFactory::KMAC::CreateKMAC256(EmptyBytes, EmptyBytes, 256);
		IMACNotBuildIn MacInstanceTwo = HashFactory::KMAC::CreateKMAC256(OneToNineBytes, EmptyBytes, 256);

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

		SECTION("TestSettingInvalidSizeThrowsCorrectException")
		{
			REQUIRE_THROWS_AS(
				HashFactory::KMAC::CreateKMAC256(EmptyBytes, EmptyBytes, 0),
				ArgumentOutOfRangeHashLibException);
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

		SECTION("TestNISTSample1")
		{
			ExpectedString =
				"20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD";
			IHash macInstance = HashFactory::KMAC::CreateKMAC256(ASCIICharacterBytes, CustomizationMessageBytes,
				OutputSizeInBits);
			DoComputeKMAC(macInstance, ZeroToThreeBytes, ExpectedString);
		}

		SECTION("TestNISTSample2")
		{
			ExpectedString =
				"75358CF39E41494E949707927CEE0AF20A3FF553904C86B08F21CC414BCFD691589D27CF5E15369CBBFF8B9A4C2EB17800855D0235FF635DA82533EC6B759B69";
			IHash macInstance = HashFactory::KMAC::CreateKMAC256(ASCIICharacterBytes, EmptyBytes,
				OutputSizeInBits);
			DoComputeKMAC(macInstance, ZeroToOneHundredAndNinetyNineBytes, ExpectedString);
		}

		SECTION("TestNISTSample3")
		{
			ExpectedString =
				"B58618F71F92E1D56C1B8C55DDD7CD188B97B4CA4D99831EB2699A837DA2E4D970FBACFDE50033AEA585F1A2708510C32D07880801BD182898FE476876FC8965";
			IHash macInstance = HashFactory::KMAC::CreateKMAC256(ASCIICharacterBytes, CustomizationMessageBytes,
				OutputSizeInBits);
			DoComputeKMAC(macInstance, ZeroToOneHundredAndNinetyNineBytes, ExpectedString);
		}

	}
}
