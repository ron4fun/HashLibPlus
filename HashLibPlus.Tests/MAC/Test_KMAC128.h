#pragma once

#include "../Catch2-2.13.6/single_include/catch2/catch.hpp"

#include "../Base/TestConstants.h"

void DoComputeKMAC(IHash hashInstance, const HashLibByteArray& data, const string& ExpectedString)
{
	hashInstance->Initialize();
	hashInstance->TransformBytes(data);
	HashLibByteArray result = hashInstance->TransformFinal()->GetBytes();

	string ActualString = Converters::ConvertBytesToHexString(result);

	REQUIRE(ExpectedString == ActualString);
}

namespace MACTests
{
	TEST_CASE("KMAC128Tests")
	{
		const Int32 OutputSizeInBits = 32 * 8;

		string ExpectedString, ActualString;

		string HashOfEmptyData = "E6AFF27FEF95903EB939BC3745730D34";
		string HashOfDefaultData = "C40AE1DBC4E8411712D445D663E4073A";
		string HashOfOnetoNine = "EB3FE9620F82E24E33EAF4543A2B66EA";
		string HashOfABCDE = "C74861532E0154C2B71DC428079BABC3";

		IHash HashInstance = HashFactory::KMAC::CreateKMAC128(EmptyBytes, EmptyBytes, 128);
		IMACNotBuildIn MacInstance = HashFactory::KMAC::CreateKMAC128(EmptyBytes, EmptyBytes, 128);
		IMACNotBuildIn MacInstanceTwo = HashFactory::KMAC::CreateKMAC128(OneToNineBytes, EmptyBytes, 128);

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
				HashFactory::KMAC::CreateKMAC128(EmptyBytes, EmptyBytes, 0),
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
			ExpectedString = "E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E";
			IHash macInstance = HashFactory::KMAC::CreateKMAC128(ASCIICharacterBytes, EmptyBytes,
				OutputSizeInBits);
			DoComputeKMAC(macInstance, ZeroToThreeBytes, ExpectedString);
		}

		SECTION("TestNISTSample2")
		{
			ExpectedString = "3B1FBA963CD8B0B59E8C1A6D71888B7143651AF8BA0A7070C0979E2811324AA5";
			IHash macInstance = HashFactory::KMAC::CreateKMAC128(ASCIICharacterBytes, CustomizationMessageBytes,
				OutputSizeInBits);
			DoComputeKMAC(macInstance, ZeroToThreeBytes, ExpectedString);
		}

		SECTION("TestNISTSample3")
		{
			ExpectedString = "1F5B4E6CCA02209E0DCB5CA635B89A15E271ECC760071DFD805FAA38F9729230";
			IHash macInstance = HashFactory::KMAC::CreateKMAC128(ASCIICharacterBytes, CustomizationMessageBytes,
				OutputSizeInBits);
			DoComputeKMAC(macInstance, ZeroToOneHundredAndNinetyNineBytes, ExpectedString);
		}

	}
}
