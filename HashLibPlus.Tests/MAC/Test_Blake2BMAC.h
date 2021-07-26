#pragma once

#include "../Catch2-2.13.6/single_include/catch2/catch.hpp"

#include "../Base/TestConstants.h"

void DoComputeBlake2(IHash hashInstance, const HashLibByteArray& data, const string& ExpectedString)
{
	hashInstance->Initialize();
	hashInstance->TransformBytes(data);
	HashLibByteArray result = hashInstance->TransformFinal()->GetBytes();

	string ActualString = Converters::ConvertBytesToHexString(result);

	REQUIRE(ExpectedString == ActualString);
}

namespace MACTests
{
	TEST_CASE("Blake2B_MACTests")
	{
		const Int32 OutputSizeInBits = 256;

		string ExpectedString, ActualString;

		string HashOfEmptyData = "0E5751C026E543B2E8AB2EB06099DAA1D1E5DF47778F7787FAAB45CDF12FE3A8";
		string HashOfDefaultData = "DFDBC73BAF47DA4D9F645CC9AFFA76B95D78BF112C4EB3CC5372AD33B3DE004A";
		string HashOfOnetoNine = "16E0BF1F85594A11E75030981C0B670370B3AD83A43F49AE58A2FD6F6513CDE9";
		string HashOfABCDE = "CA96DD6B05B0BC353DD129077A871B7BBB3BD659C592C7E33DADAB30889943EE";

		HashLibByteArray PersonalizationBytes = Converters::ConvertStringToBytes("application");
		PersonalizationBytes.resize(16);

		IHash HashInstance =
			HashFactory::Blake2BMAC::CreateBlake2BMAC(EmptyBytes, EmptyBytes, EmptyBytes, OutputSizeInBits);

		IMACNotBuildIn MacInstance = HashFactory::Blake2BMAC::CreateBlake2BMAC(EmptyBytes, EmptyBytes, EmptyBytes, OutputSizeInBits);
		IMACNotBuildIn MacInstanceTwo =
			HashFactory::Blake2BMAC::CreateBlake2BMAC(OneToNineBytes, EmptyBytes, EmptyBytes, OutputSizeInBits);

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
				HashFactory::Blake2BMAC::CreateBlake2BMAC(EmptyBytes, EmptyBytes, EmptyBytes, 0),
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
			ExpectedString = "2A";
			IHash macInstance = HashFactory::Blake2BMAC::CreateBlake2BMAC(ZeroToThirtyOneBytes, EmptyBytes, EmptyBytes,
				1 * 8);
			DoComputeBlake2(macInstance,
				Converters::ConvertStringToBytes("Sample input for outlen<digest_length"),
				ExpectedString);
		}

		SECTION("TestSample2")
		{
			ExpectedString = "51742FC491171EAF6B9459C8B93A44BBF8F44A0B4869A17FA178C8209918AD96";
			IHash macInstance = HashFactory::Blake2BMAC::CreateBlake2BMAC(ZeroToThirtyOneBytes, ZeroToFifteenBytes,
				PersonalizationBytes,
				32 * 8);
			DoComputeBlake2(macInstance,
				Converters::ConvertStringToBytes("Combo input with outlen, custom and salt"),
				ExpectedString);
		}

		SECTION("TestSample3")
		{
			ExpectedString =
				"233A6C732212F4813EC4C9F357E35297E59A652FD24155205F00363F7C54734EE1E8C7329D92116CBEC62DB35EBB5D51F9E5C2BA41789B84AC9EBC266918E524";
			IHash macInstance = HashFactory::Blake2BMAC::CreateBlake2BMAC(ZeroToThirtyOneBytes, ZeroToFifteenBytes,
				PersonalizationBytes,
				64 * 8);
			DoComputeBlake2(macInstance,
				Converters::ConvertStringToBytes("Sample input for keylen<blocklen, salt and custom"),
				ExpectedString);
		}
	}
}
