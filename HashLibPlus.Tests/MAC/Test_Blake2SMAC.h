#pragma once

#include "../Catch2-2.13.6/single_include/catch2/catch.hpp"

#include "../Base/TestConstants.h"

// Function is contained in Test_Blake2SMAC.h file
//
//void DoComputeBlake2(IHash hashInstance, const HashLibByteArray& data, const string& ExpectedString)
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
	TEST_CASE("Blake2S_MACTests")
	{
		const Int32 OutputSizeInBits = 128;

		string ExpectedString, ActualString;

		string HashOfEmptyData = "64550D6FFE2C0A01A14ABA1EADE0200C";
		string HashOfDefaultData = "90ED1B7647A53ADDFA8C4B969471205D";
		string HashOfOnetoNine = "DCE1C41568C6AA166E2F8EAFCE34E617";
		string HashOfABCDE = "FFD7F0D7C62820AAF911CA23F8656D63";

		HashLibByteArray PersonalizationBytes = Converters::ConvertStringToBytes("app");
		PersonalizationBytes.resize(8);

		IHash HashInstance =
			HashFactory::Blake2SMAC::CreateBlake2SMAC(EmptyBytes, EmptyBytes, EmptyBytes, OutputSizeInBits);

		IMACNotBuildIn MacInstance = HashFactory::Blake2SMAC::CreateBlake2SMAC(EmptyBytes, EmptyBytes, EmptyBytes, OutputSizeInBits);
		IMACNotBuildIn MacInstanceTwo =
			HashFactory::Blake2SMAC::CreateBlake2SMAC(OneToNineBytes, EmptyBytes, EmptyBytes, OutputSizeInBits);

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
				HashFactory::Blake2SMAC::CreateBlake2SMAC(EmptyBytes, EmptyBytes, EmptyBytes, 0),
				ArgumentOutOfRangeHashLibException);
		}

		SECTION("TestMACCloneIsCorrect")
		{
			IMACNotBuildIn Original = MacInstance;
			IMACNotBuildIn Copy;

			Original->SetKey(OneToNineBytes);
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

		SECTION("TestSample1")
		{
			ExpectedString = "07";
			IHash macInstance = HashFactory::Blake2SMAC::CreateBlake2SMAC(ZeroToThirtyOneBytes, EmptyBytes, EmptyBytes,
				1 * 8);
			DoComputeBlake2(macInstance,
				Converters::ConvertStringToBytes("Sample input for outlen<digest_length"),
				ExpectedString);
		}

		SECTION("TestSample2")
		{
			ExpectedString = "6808D8DAAE537A16BF00E837010969A4";
			IHash macInstance = HashFactory::Blake2SMAC::CreateBlake2SMAC(ZeroToFifteenBytes, ZeroToSevenBytes,
				PersonalizationBytes,
				16 * 8);
			DoComputeBlake2(macInstance,
				Converters::ConvertStringToBytes("Combo input with outlen, custom and salt"),
				ExpectedString);
		}

		SECTION("TestSample3")
		{
			ExpectedString =
				"E9F7704DFE5080A4AAFE62A806F53EA7F98FFC24175164158F18EC5497B961F5";
			IHash macInstance = HashFactory::Blake2SMAC::CreateBlake2SMAC(ZeroToFifteenBytes,
				Converters::ConvertHexStringToBytes("A205819E78D6D762"),
				PersonalizationBytes,
				32 * 8);
			DoComputeBlake2(macInstance,
				Converters::ConvertStringToBytes("Sample input for keylen<blocklen, salt and custom"),
				ExpectedString);
		}
	}
}
