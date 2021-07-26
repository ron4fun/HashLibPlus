#pragma once

#include "../Catch2-2.13.6/single_include/catch2/catch.hpp"

#include "../Base/TestConstants.h"

namespace XOFTests
{
	TEST_CASE("CShake_128Tests")
	{
		string ExpectedString, ActualString;

		HashLibByteArray EmailSignature =
		{ 0x45, 0x6D, 0x61, 0x69, 0x6C, 0x20, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65 };
		
		string HashOfEmptyData = "7F9C2BA4E88F827D616045507605853E";
		string HashOfDefaultData = "10F69AD42A1BDE254004CD13B5176D6D";
		string HashOfOnetoNine = "1ACA6B9E651B5F20079A305CA8F86D39";
		string HashOfABCDE = "907C1B3F41470218D0DFD8FEDDDA93C1";
		string XofOfEmptyData =
			"7F9C2BA4E88F827D616045507605853ED73B8093F6EFBC88EB1A6EACFA66EF263CB1EEA988004B93103CFB0AEEFD2A686E"
			"01FA4A58E8A3639CA8A1E3F9AE57E235B8CC873C23DC62B8D260169AFA2F75AB916A58D974918835D25E6A435085B2BADFD6DFAAC359A5EFBB7BCC"
			"4B59D538DF9A04302E10C8BC1CBF1A0B3A5120EA17CDA7CFAD765F5623474D368CCCA8AF0007CD9F5E4C849F167A580B14AABDEFAEE7EEF47CB0FCA9767BE1FDA69419DFB927E9DF07348B196691ABAEB580B32DEF58538B8D23F87732EA63B02B4FA0F4873360E2841928CD60DD4CEE8CC0D4C922A96188D0326"
			"75C8AC850933C7AFF1533B94C834ADBB69C6115BAD4692D8619F90B0CDF8A7B9C264029AC185B70B83F2801F2F4B3F70C593EA3AEEB613A7F1B1DE33FD75081F592305F2E4526EDC09631B10958F464D889F31BA010250FDA7F1368EC2967FC84EF2AE9AFF268E0B1700AFFC6820B523A3D917135F2DFF2"
			"EE06BFE72B3124721D4A26C04E53A75E30E73A7A9C4A95D91C55D495E9F51DD0B5E9D83C6D5E8CE803AA62B8D654DB53D09B8DCFF273CDFEB573FAD8BCD45578BEC2E770D01EFDE86E721A3F7C6CCE275DABE6E2143"
			"F1AF18DA7EFDDC4C7B70B5E345DB93CC936BEA323491CCB38A388F546A9FF00DD4E1300B9B2153D2041D205B443E41B45A653F2A5C4492C1AD"
			"D544512DDA2529833462B71A41A45BE97290B6F4CFFDA2CF990051634A4B1EDF6114FB49083C1FA3B302EE097F051266BE69DC716FDEEF91B0D4AB2DE525550BF80DC8A684BC3B5A4D46B7EFAE7AFDC6292988DC9ACAE03F8634486C1ABE2781AAE4C02F3460D2CD4E6A463A2BA956"
			"2EE623CF0E9F82AB4D0B5C9D040A269366479DFF0038ABFAF2E0FF21F36968972E3F104DDCBE1EB831A87C213162E29B34ADFA564D121E9F6E7729F4203FC5C6C22FA7A7350AFDDB620923A4A129B8ACB19EA10F818C30E3B5B1C571FA79E57EE304388316A02FCD93A0D8EE02BB85701EE4FF09753"
			"4B502C1B12FBB95C8CCB2F548921D99CC7C9FE17AC991B675E631144423EEF7A5869168DA63D1F4C21F650C02923BFD396CA6A5DB541068624CBC5FFE208C0D1A"
			"74E1A29618D0BB60036F5249ABFA88898E393718D6EFAB05BB41279EFCD4C5A0CC837CCFC22BE4F725C081F6AA090749DBA7077BAE8D41AF3FEC5A6EE1B8ADCD2"
			"5E72DE36434584EF567C643D344294E8B2086B87F69C3BDC0D5969857082987CA1C63B7182E86898FB9B8039E75EDA219E289331610369271867B145B2908293963CD677C9A1AE6CEB28289B254CDEB76B12F33CE5CF3743131BFB550F0197BFE16AFF92367227ADC5074FE3DC0D8D116253980A38636BC9D29F79"
			"9BBB2D76A0A5F138B8C73BA484D6588764E331D70C378C0641F2D9";

		string XofOfZeroToOneHundredAndNinetyNine = "C5221D50E4F822D96A2E8881A961420F";

		IHash HashInstance = HashFactory::XOF::CreateCShake_128(EmptyBytes, EmptyBytes, 128);
		IXOF XofInstance = HashFactory::XOF::CreateCShake_128(EmptyBytes, EmptyBytes, 8000);
		IXOF XofInstanceShake = HashFactory::XOF::CreateShake_128(8000);
		IXOF XofInstanceCShakeWithN = HashFactory::XOF::CreateCShake_128(EmptyBytes, EmailSignature, 128);
				
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
				HashFactory::XOF::CreateCShake_128(EmptyBytes, EmptyBytes, 0),
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
