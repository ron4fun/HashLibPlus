#pragma once

#include "../Catch2-2.13.6/single_include/catch2/catch.hpp"

#include "../Base/TestConstants.h"
#include "../Base/Blake2STestVectors.h"

namespace XOFTests
{
	TEST_CASE("Blake2XSTests")
	{
		const Int32 HashSize = 32;

		string ExpectedString, ActualString;

		string HashOfEmptyData = "F4B358457E5563FB54DF3060AEC26EA3AA1C959CF89F55A22538117ECF708BFC";
		string HashOfDefaultData = "5ADFC3100CED2EDF93D530E747544B1FF88981E2C8BF4BCA95C434FAEA991718";
		string HashOfOnetoNine = "EA2BBB210CCC659A88EEE6D07900D719E26D801CC6A5E6214214EBA376FF28A5";
		string HashOfABCDE = "3B42907077820444C727CF6B1FD6CC5E9BF8AA5489F57010670D4045AC0A1466";
		string XofOfEmptyData =
			"217B64B104155F7158277FC5B0AFB954138C93A6F1269DC4C642A781BA20EB24B3B4B5C7E6C13645DD584D851BD4280B24E1DBA29C512D3CBD6A5C84A708C1D536A6654DDD1D8E3"
			"885F0B520092E264C73BD11F8788F2841D9B5004CD643F3E39F4188A20A0E0F639E61B45759C68A7DA76CD657F71EB35E1CBC01D16B6DA21CE30CB6E9328451DB8B3F47323CDB0EBBB1BFA"
			"F1D038D8F6721B8A6268CE955FD58A08F2F38F18B6E51E4E787BC171C737CED8988D912F91A89FD8DB0F3BEC0BA9117E05A916350067A2AC55ED14D7B51A77C9D5B368D58871A6687424CC2C"
			"A92FC2F8FD6B1830548B8EC2B10E402F14DF43AAB9F93D73CDE95B14E667D2F00928192651D0681A4C8D9AF7951656162230792D49526E59AE204984E45E3D08F439C04B711E06AC4EB073AD18D95"
			"8E1D853AA463D05646C98C37941CA909C6E6040983120DEE9EB99D03EBD6766D20909481979897B20E34AF07A2EA96637E9F8E9AAFB6A813360C392710D2A408FB6C5F24980ACCB106468"
			"61B111BD5716DDAF96F3740BD6D10645DE8632C44643939D9C3CA8795F145DA32A61A7903EEFA12040A4AC9AC237C3DCD8BE742B384E1E60B37F8F471A7E9122498E48236783DAD631120C8E"
			"A8274F07592FBFF612227EBDB550E954BBA0E8BE25562C7344E5C124FCD96F6F272EF8092BC926735C812873228FE063C8F7B9C54CA7A401AF98A7CA8820D7055BA3B82B8F286B67B415F469"
			"D4A847ADA022AD05FCB75A27BFA3426225DD2C6D62A77EFD8B2A61AE7726876A658EF872B44625D42EA6005BF2207A33D210083B43555F16C60BE798F54080510B9EF53E181C3EA"
			"FA675818A5255A8E963B22170EA2C42AF9534AF29FC58DA8289F5BEB1B2F5CBA50DE3D9E3F2AA34A992B7634B780F8D8367274EECF4ACE2FDE88B92CCA35064521BA335C375C4F285F2537FF34"
			"53F1E1F00D4CFDD91F5F349774DA1BC2D30D7BC0FC84CC087F056FB2425C00C5BD4B79BD048FE79048603961D8910F00EBA4200AF31FD77A9F6D5C051BE29A9555D829F236C425BB65531B"
			"13E4ED3C7F4EEE77014AE46D1E99D32087AA0B4A984A4DEF9A258376F985820BBF97E5A2702F56EC3FD353F552042CDC9D09502393C2DD702CB434AADD632BB8C562010950C865CC890002"
			"6D1A7414FD402F5092C7787E7A74238F866EBB623A5DF76B2A5BF916328B6C612CE53694263C7DEFFC8B3245771C22C585C3FFA9932875A439CF2E2ECE68CD24DFDB2CC40813F348411AF7026F662AFCEE1"
			"3EB53418FB69257FF807691FA896E6486D54FD991E927C492D15C0C9B01D905FAD6FFA294C484DFA6B74400CBDD414A85D458DBFFC366C2AFACCEC7E4EA8D7AB75F52FAAD995ED9CB45D"
			"C69A8D906E1C09A60DEF1447A3D724F54CCE6";

		IHash HashInstance = HashFactory::XOF::CreateBlake2XS(EmptyBytes, 256);
		IXOF XofInstance = HashFactory::XOF::CreateBlake2XS(EmptyBytes, 8000);

		SECTION("TestCheckTestVectors")
		{
			HashLibByteArray data = Converters::ConvertHexStringToBytes(
				Blake2STestVectors::Blake2XS_XofTestInput);

			for (size_t i = 0; i < Blake2STestVectors::Blake2XS_XofTestVectors.size(); i++)
			{
				HashLibStringArray vector = Blake2STestVectors::Blake2XS_XofTestVectors[i];
				HashLibByteArray key = Converters::ConvertHexStringToBytes(vector[0]);

				ActualString =
					HashFactory::XOF::CreateBlake2XS(key, (UInt64)((vector[1].size() >> 1) * 8))
					->ComputeBytes(data)->ToString();
				ExpectedString = vector[1];

				REQUIRE(Converters::toUpper(ExpectedString) == ActualString);
			}
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

		SECTION("TestOutputOverflow")
		{
			XofInstance->Initialize();
			HashLibByteArray output((XofInstance->GetXOFSizeInBits() >> 3) + 1);
			XofInstance->TransformBytes(SmallLettersAToEBytes);
			REQUIRE_THROWS_AS(
				XofInstance->DoOutput(output, 0, (UInt64)output.size()),
				ArgumentOutOfRangeHashLibException);
		}

		SECTION("TestSettingOutOfRangeKeyThrowsCorrectException")
		{
			REQUIRE_THROWS_AS(
				HashFactory::XOF::CreateBlake2XS(HashLibByteArray(HashSize + 1), 256),
				ArgumentOutOfRangeHashLibException);
		}

		SECTION("TestSettingEmptyKeyDoesNotThrowsException")
		{
			REQUIRE_NOTHROW(HashFactory::XOF::CreateBlake2XS(EmptyBytes, 256));
		}

		SECTION("TestSettingOutOfRangeSaltThrowsCorrectException")
		{
			IBlake2SConfig config = Blake2SConfig::CreateBlake2SConfig(HashSize);

			REQUIRE_THROWS_AS(
				config->SetSalt(HashLibByteArray(9)),
				ArgumentOutOfRangeHashLibException);

			/*HashFactory::XOF::CreateBlake2XS(
				Blake2XSConfig::CreateBlake2XSConfig(config, nullptr), 256)*/
		}

		SECTION("TestSettingEmptySaltDoesNotThrow")
		{
			IBlake2SConfig config = Blake2SConfig::CreateBlake2SConfig(HashSize);
			config->SetSalt(EmptyBytes);

			REQUIRE_NOTHROW(
				HashFactory::XOF::CreateBlake2XS(
					Blake2XSConfig::CreateBlake2XSConfig(config, nullptr), 256));
		}

		SECTION("TestSettingOutOfRangePersonalizationThrowsCorrectException")
		{
			IBlake2SConfig config = Blake2SConfig::CreateBlake2SConfig(HashSize);

			REQUIRE_THROWS_AS(
				config->SetPersonalization(HashLibByteArray(9)),
				ArgumentOutOfRangeHashLibException);

			/*HashFactory::XOF::CreateBlake2XS(
				Blake2XSConfig::CreateBlake2XSConfig(config, nullptr), 256)*/
		}

		SECTION("TestSettingEmptyPersonalizationDoesNotThrowsException")
		{
			IBlake2SConfig config = Blake2SConfig::CreateBlake2SConfig(HashSize);
			config->SetPersonalization(EmptyBytes);

			REQUIRE_NOTHROW(
				HashFactory::XOF::CreateBlake2XS(
					Blake2XSConfig::CreateBlake2XSConfig(config, nullptr), 256));
		}

		SECTION("TestSettingInvalidSizeThrowsCorrectException")
		{
			REQUIRE_THROWS_AS(
				HashFactory::XOF::CreateBlake2XS(EmptyBytes, 0),
				ArgumentOutOfRangeHashLibException);
		}

		SECTION("TestOutputBufferTooShort")
		{
			XofInstance->Initialize();
			HashLibByteArray output(XofInstance->GetXOFSizeInBits() >> 3);
			XofInstance->TransformBytes(SmallLettersAToEBytes);

			REQUIRE_THROWS_AS(
				XofInstance->DoOutput(output, 1, (UInt64)output.size()),
				ArgumentOutOfRangeHashLibException);
		}

		SECTION("TestVeryLongXofOfEmptyData")
		{
			ExpectedString = XofOfEmptyData;
			ActualString = XofInstance->ComputeBytes(EmptyBytes)->ToString();

			REQUIRE(ExpectedString == ActualString);
		}

		SECTION("TestVeryLongXofOfEmptyDataWithStreamingOutput")
		{
			const Int32 xofStreamingChunkSize = 250;

			HashLibByteArray tempResult(1000);
			HashLibByteArray actualChunk(xofStreamingChunkSize);
			HashLibByteArray expectedChunk(xofStreamingChunkSize);
			HashLibByteArray xofOfEmptyDataBytes = Converters::ConvertHexStringToBytes(XofOfEmptyData);

			XofInstance->Initialize();
			XofInstance->TransformBytes(EmptyBytes);

			// 1
			XofInstance->DoOutput(tempResult, 0, xofStreamingChunkSize);

			memmove(&actualChunk[0], &tempResult[0], xofStreamingChunkSize);
			memmove(&expectedChunk[0], &xofOfEmptyDataBytes[0], xofStreamingChunkSize);

			REQUIRE(expectedChunk == actualChunk);

			// 2
			XofInstance->DoOutput(tempResult, xofStreamingChunkSize, xofStreamingChunkSize);

			memmove(&actualChunk[0], &tempResult[xofStreamingChunkSize], xofStreamingChunkSize);
			memmove(&expectedChunk[0], &xofOfEmptyDataBytes[xofStreamingChunkSize], xofStreamingChunkSize);

			REQUIRE(expectedChunk == actualChunk);

			// 3
			XofInstance->DoOutput(tempResult, 500, xofStreamingChunkSize);

			memmove(&actualChunk[0], &tempResult[500], xofStreamingChunkSize);
			memmove(&expectedChunk[0], &xofOfEmptyDataBytes[500], xofStreamingChunkSize);

			REQUIRE(expectedChunk == actualChunk);

			// 4
			XofInstance->DoOutput(tempResult, 750, xofStreamingChunkSize);

			memmove(&actualChunk[0], &tempResult[750], xofStreamingChunkSize);
			memmove(&expectedChunk[0], &xofOfEmptyDataBytes[750], xofStreamingChunkSize);

			REQUIRE(expectedChunk == actualChunk);

			ActualString = Converters::ConvertBytesToHexString(tempResult);
			ExpectedString = XofOfEmptyData;

			REQUIRE(ExpectedString == ActualString);

			// Verify that Initialization Works
			XofInstance->Initialize();
			XofInstance->DoOutput(tempResult, 0, xofStreamingChunkSize);

			memmove(&actualChunk[0], &tempResult[0], xofStreamingChunkSize);
			memmove(&expectedChunk[0], &xofOfEmptyDataBytes[0], xofStreamingChunkSize);

			REQUIRE(expectedChunk == actualChunk);
		}

		SECTION("TestXofShouldRaiseExceptionOnWriteAfterRead")
		{
			XofInstance->Initialize();
			HashLibByteArray output(XofInstance->GetXOFSizeInBits() >> 3);
			XofInstance->TransformBytes(SmallLettersAToEBytes);
			XofInstance->DoOutput(output, 0, (UInt64)output.size());

			// this call below should raise exception since we have already read from the Xof
			REQUIRE_THROWS_AS(
				XofInstance->TransformBytes(SmallLettersAToEBytes),
				InvalidOperationHashLibException);
		}

		SECTION("TestXofCloningWorks")
		{
			XofInstance->Initialize();
			XofInstance->TransformBytes(ZeroToOneHundredAndNinetyNineBytes);

			IXOF xofInstanceClone = XofInstance->CloneXOF();

			HashLibByteArray result(XofInstance->GetXOFSizeInBits() >> 3);
			HashLibByteArray resultClone(xofInstanceClone->GetXOFSizeInBits() >> 3);

			XofInstance->DoOutput(result, 0, (UInt64)result.size());
			xofInstanceClone->DoOutput(resultClone, 0, (UInt64)resultClone.size());

			REQUIRE(result == resultClone);
		}

	}
}
