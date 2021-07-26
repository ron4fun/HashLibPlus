#pragma once

#include "../Catch2-2.13.6/single_include/catch2/catch.hpp"

#include "../Base/TestConstants.h"

namespace XOFTests
{
	TEST_CASE("CShake_256Tests")
	{
		string ExpectedString, ActualString;

		HashLibByteArray EmailSignature =
		{ 0x45, 0x6D, 0x61, 0x69, 0x6C, 0x20, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65 };

		string HashOfEmptyData = "46B9DD2B0BA88D13233B3FEB743EEB243FCD52EA62B81B82B50C27646ED5762F";
		string HashOfDefaultData = "922279516284A34F384ADA776D3606FBEC97875E716E6EA0FFCF9372AAB696BE";
		string HashOfOnetoNine = "24347B9C4B6DA2FC9CDE08C87F33EDD2E603C8DCD6840E6B3920F62B1DD69D7B";
		string HashOfABCDE = "98AD79D7ED29F585AD1AFFBC2BB5B5F244917F97CEA8B5424FDC6F7377A22042";
		string XofOfEmptyData =
			"46B9DD2B0BA88D13233B3FEB743EEB243FCD52EA62B81B82B50C27646ED5762FD75DC4DDD8C0F200CB05019D67B592F6FC821C49479AB48640292EACB3B7C4BE141E96616FB1395"
			"7692CC7EDD0B45AE3DC07223C8E92937BEF84BC0EAB862853349EC75546F58FB7C2775C38462C5010D846C185C15111E595522A6BCD16CF86F3D122109E3B1FDD943B6AEC468A2D"
			"621A7C06C6A957C62B54DAFC3BE87567D677231395F6147293B68CEAB7A9E0C58D864E8EFDE4E1B9A46CBE854713672F5CAAAE314ED9083DAB4B099F8E300F01B8650F1F4B1D8F"
			"CF3F3CB53FB8E9EB2EA203BDC970F50AE55428A91F7F53AC266B28419C3778A15FD248D339EDE785FB7F5A1AAA96D313EACC890936C173CDCD0FAB882C45755FEB3AED96D47"
			"7FF96390BF9A66D1368B208E21F7C10D04A3DBD4E360633E5DB4B602601C14CEA737DB3DCF722632CC77851CBDDE2AAF0A33A07B373445DF490CC8FC1E4160FF118378F11F0477DE"
			"055A81A9EDA57A4A2CFB0C83929D310912F729EC6CFA36C6AC6A75837143045D791CC85EFF5B21932F23861BCF23A52B5DA67EAF7BAAE0F5FB1369DB78F3AC45F8C4AC5671D85735C"
			"DDDB09D2B1E34A1FC066FF4A162CB263D6541274AE2FCC865F618ABE27C124CD8B074CCD516301B91875824D09958F341EF274BDAB0BAE316339894304E35877B0C28A9B1FD166C796B9CC"
			"258A064A8F57E27F2A5B8D548A728C9444ECB879ADC19DE0C1B8587DE3E73E15D3CE2DB7C9FA7B58FFC0E87251773FAF3E8F3E3CF1D4DFA723AFD4DA9097CB3C866ACBEFAB2C4E85E1918990"
			"FF93E0656B5F75B08729C60E6A9D7352B9EFD2E33E3D1BA6E6D89EDFA671266ECE6BE7BB5AC948B737E41590ABE138CE1869C08680162F08863D174E77E07A9DDB33B57DE04C"
			"443A5BD77C42036871AAE7893362B27015B84B4139F0E313579B4EF5F6B6426563D7195B8C5B84736B14266160342C4093F8ABEA48371BA94CC06DCB6B8A8E7BCE6354F9BABC949A5F"
			"18F8C9F0AAEFE0B8BECAD386F078CA41CACF2E3D17F4EC21FED0E3B682435AD5B665C25D7B61B379E86824C2B22D5A54835F8B04D4C0B29667BAEB0C3258809EE698DBC03536A1C"
			"936C811F6E6F69210F5632080064923FDF9CF405301E45A3F96E3F57C55C4E0B538EFE8942F6B601AC49EA635F70E4BA39E5FCE513CFB672945BB92E17F7D222EAB2AA29BE89FC3F"
			"F24BC6B6D7A3D307CE7B1731E7DF59690D0530D7F2F5BB9ED37D180169A6C1BB022252AB8CC6860E3CF1F1414C90A19350B526E3741E500717769CDD09D268CC3F8"
			"8B5D521C70AA8BBE631FBF08905A0A833D2005830717ADBA3233DD591BC505C7B13A9D5672AD4BE10C744AC33D9E92A23BDEE6E14D470EE7DC142FE4EFF4182A49BEEEC8E4";

		string XofOfZeroToOneHundredAndNinetyNine = "07DC27B11E51FBAC75BC7B3C1D983E8B4B85FB1DEFAF218912AC864302730917";

		IHash HashInstance = HashFactory::XOF::CreateCShake_256(EmptyBytes, EmptyBytes, 256);
		IXOF XofInstance = HashFactory::XOF::CreateCShake_256(EmptyBytes, EmptyBytes, 8000);
		IXOF XofInstanceShake = HashFactory::XOF::CreateShake_256(8000);
		IXOF XofInstanceCShakeWithN = HashFactory::XOF::CreateCShake_256(EmptyBytes, EmailSignature, 256);

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

		SECTION("TestCShakeAndShakeAreSameWhenNAndSAreEmpty")
		{
			ExpectedString = XofInstanceShake->ComputeBytes(EmptyBytes)->ToString();
			ActualString = XofInstance->ComputeBytes(EmptyBytes)->ToString();

			REQUIRE(ExpectedString == ActualString);
		}

		SECTION("TestCShakeWithN")
		{
			ExpectedString = XofOfZeroToOneHundredAndNinetyNine;
			ActualString = XofInstanceCShakeWithN->ComputeBytes(ZeroToOneHundredAndNinetyNineBytes)
				->ToString();

			REQUIRE(ExpectedString == ActualString);
		}

		SECTION("TestCShakeWithNIncremental")
		{
			ExpectedString = XofOfZeroToOneHundredAndNinetyNine;
			XofInstanceCShakeWithN->Initialize();
			XofInstanceCShakeWithN->TransformBytes(ZeroToOneHundredAndNinetyNineBytes);
			ActualString = XofInstanceCShakeWithN->TransformFinal()->ToString();

			REQUIRE(ExpectedString == ActualString);
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

		SECTION("TestSettingInvalidSizeThrowsCorrectException")
		{
			REQUIRE_THROWS_AS(
				HashFactory::XOF::CreateCShake_256(EmptyBytes, EmptyBytes, 0),
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
