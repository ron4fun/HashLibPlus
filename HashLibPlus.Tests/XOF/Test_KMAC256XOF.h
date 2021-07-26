#pragma once

#include "../Catch2-2.13.6/single_include/catch2/catch.hpp"

#include "../Base/TestConstants.h"

// Function is contained in Test_KMAC128XOF.h file
//
//void DoComputeKMACXOF(IXOF xofInstance, const HashLibByteArray& data, const string& ExpectedString)
//{
//	HashLibByteArray result(xofInstance->GetXOFSizeInBits() >> 3);
//
//	xofInstance->Initialize();
//	xofInstance->TransformBytes(data);
//	xofInstance->DoOutput(result, 0, (UInt64)result.size());
//
//	string ActualString = Converters::ConvertBytesToHexString(result);
//
//	REQUIRE(ExpectedString == ActualString);
//} //

namespace XOFTests
{
	TEST_CASE("KMAC256XOFTests")
	{
		const Int32 OutputSizeInBits = 64 * 8;

		string ExpectedString, ActualString;

		string HashOfEmptyData = "2C9683C318165466C0D3F9467CE77F0CEA513F643AE3BD5B0969165AAFAE3F71";
		string HashOfDefaultData = "81EA035780ABD58788089419CC37BDF39204146FA2650FE1C8D1DB0B5F2E690B";
		string HashOfOnetoNine = "1C76E3A5D8814B5161FA6C99B9352C21BB68D29E09CDFFCE3CB67D589BD05CDF";
		string HashOfABCDE = "46109A951A39A1DF43D4916A9CC1C48EB606DE4AEA3DFF3735733E9ABD39BE63";
		string XofOfEmptyData =
			"2C9683C318165466C0D3F9467CE77F0CEA513F643AE3BD5B0969165AAFAE3F7170D3D7AEEF324B53BCC4C63A1F13A30AA7BE47BC271016D0C8B4CC77D9561399DCD4A136E84AD557D"
			"ADEF140AB12A1BA1B8B664B3A228FC5B781E4F62F1F3239B793938CCA4D95A292E53BCF115665BB974D434382E2DE6D9955176500BFE639B86B8BC661832A8A7DF51E5ADE20A1CEAAEE51F5AE474E153D69DA"
			"BD345ECB53FDE0DAF8C1398C1F673F5D0D9037DA264B3CA728C094DAF2C8FD5A4A3E501931425DB34F7E716EF6C978FD752505FCD177E20EF045CC624CCEB8408A00EFD3EC7D7E9196DBBD6806F47F854EEC3484"
			"DC79C70DECDA08ABBB9F042583E1FBB20C8A7A85B933296D203CE77F1B7701493381BD55A4F0E1BC52F76E13C53D4A26C885A1AD684BEE06C7EE9B36C40152EB2959B6B70A9022435C8"
			"8A354BA4969CBFABBB5542ECD32C9C5DA2351771E3DA89BB8966007F021493121F61F246A35E9317C50AC6CD683CFC6A549CC162A342A6501C139093D95212B8AF2AD26B830BE0A85E55B728736547"
			"EE89EE77A5204DB7E8D465E97B07554D6C2E979FF740861E6E7BA1F8D22650F11E6018F15603C468AC06F95F5666088D7252F877DB481820EFCA2F049D7ABA0A6043E0"
			"4FC13A61FB04B8E125FED02D58F317383FDAE6E89BE9E4587D49D65216BED931D4192D528DB7FF8C8A76A41887161807416B981508911FEA53B86C945FE536C6A7CEAB77D9B5F572"
			"D01A17046E9A5D747697B469246AD34600737EDB30D8A12C81BDBFB6DD65556E5F67E075F4195F27441E29F483D5EC34AC0D5C8F6306C956CE3237E4280A262503BE41DC36141238"
			"B695C81C292D7D458C2D05E899CE1FDF818135EA62641C4526C62D02F537B4B555E2B5237007B98683CB0A92FA3B4B3C890F2E16D9C9F9DAD3DFE165B37E6CBCFD721DB6D901F634892F58B1601981180C2F817F383992"
			"4986676C95CD14A0B52B06667C02AF8C95301699C19982A8F89D8AEDA397618C35FA6CAE4D3AEC18B251DA78A3D151FFB27C66BCD15EA1AFB2861F7FAEACC8E11A1C157C5888"
			"2266CB47F7D4F5FD67E2B76FB2C92478EE7976F24F86A8E690390757023F93BFF04ECF61E6582701E90E3BD958BAC434E5B2CD14A42CF6DCAB0584F3B41B2AB"
			"96273A0F70F3636532F4F9D175F1059C4F1E4AF407979A722D02301258120ADA51776D9C7B96764E271392C4AE714160AA3D6C31C1DD7CA6F66A2448DCC8E2BFF"
			"A2F2999629721E2C877F8FD582B2F7C8265707545BCF74BA921B85166879863D486E0EBD226346003B91BDDA9C303F0E7E07216CE"
			"DB8237D857776BA70259B1CA0E968F8D67354A78EF3AB2C02D481F3D5FDE5EB83D5AA29A8446246CAEA505B09CC9B48C061B4D8B4A1608E20CD72768";

		IHash HashInstance = HashFactory::XOF::CreateKMAC256XOF(EmptyBytes, EmptyBytes, 256);
		IXOF XofInstance = HashFactory::XOF::CreateKMAC256XOF(EmptyBytes, EmptyBytes, 8000);

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

		SECTION("TestNISTXOFSample1")
		{
			ExpectedString =
				"1755133F1534752AAD0748F2C706FB5C784512CAB835CD15676B16C0C6647FA96FAA7AF634A0BF8FF6DF39374FA00FAD9A39E322A7C92065A64EB1FB0801EB2B";
			IXOF xofInstance = HashFactory::XOF::CreateKMAC256XOF(ASCIICharacterBytes, CustomizationMessageBytes,
				OutputSizeInBits);
			DoComputeKMACXOF(xofInstance, ZeroToThreeBytes, ExpectedString);
		}

		SECTION("TestNISTXOFSample2")
		{
			ExpectedString =
				"FF7B171F1E8A2B24683EED37830EE797538BA8DC563F6DA1E667391A75EDC02CA633079F81CE12A25F45615EC89972031D18337331D24CEB8F8CA8E6A19FD98B";
			IXOF xofInstance = HashFactory::XOF::CreateKMAC256XOF(ASCIICharacterBytes, EmptyBytes,
				OutputSizeInBits);
			DoComputeKMACXOF(xofInstance, ZeroToOneHundredAndNinetyNineBytes, ExpectedString);
		}

		SECTION("TestNISTXOFSample3")
		{
			ExpectedString =
				"D5BE731C954ED7732846BB59DBE3A8E30F83E77A4BFF4459F2F1C2B4ECEBB8CE67BA01C62E8AB8578D2D499BD1BB276768781190020A306A97DE281DCC30305D";
			IXOF xofInstance = HashFactory::XOF::CreateKMAC256XOF(ASCIICharacterBytes, CustomizationMessageBytes,
				OutputSizeInBits);
			DoComputeKMACXOF(xofInstance, ZeroToOneHundredAndNinetyNineBytes, ExpectedString);
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
				HashFactory::XOF::CreateKMAC256XOF(EmptyBytes, EmptyBytes, 0),
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
