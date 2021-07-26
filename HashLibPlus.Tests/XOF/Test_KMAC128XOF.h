#pragma once

#include "../Catch2-2.13.6/single_include/catch2/catch.hpp"

#include "../Base/TestConstants.h"

void DoComputeKMACXOF(IXOF xofInstance, const HashLibByteArray& data, const string& ExpectedString)
{
	HashLibByteArray result(xofInstance->GetXOFSizeInBits() >> 3);

	xofInstance->Initialize();
	xofInstance->TransformBytes(data);
	xofInstance->DoOutput(result, 0, (UInt64)result.size());

	string ActualString = Converters::ConvertBytesToHexString(result);

	REQUIRE(ExpectedString == ActualString);
} //

namespace XOFTests
{
	TEST_CASE("KMAC128XOFTests")
	{
		const Int32 OutputSizeInBits = 32 * 8;

		string ExpectedString, ActualString;

		string HashOfEmptyData = "3F9259E80B35E0719C26025F7E38A4A3";
		string HashOfDefaultData = "724E3EEA4AB7C7B493963F4236D7ACAD";
		string HashOfOnetoNine = "0719366E1969ED79AFF51AE1F4B0633B";
		string HashOfABCDE = "A839214B8ED82E72DEB13112C6D9D8F7";
		string XofOfEmptyData =
			"3F9259E80B35E0719C26025F7E38A4A38172BF1142A6A9C1930E50DF039043121C5ED07BE0252A132CE84DBFA0C541DCF0853B0294CA5BB"
			"9B462C735FF6DB1F256D37207FE0BE125145C082A46CA323C47809B5B3364FFC58C83D987CE66BC9686881274CAF0579971FA8DD4495F379485D13C7F5A73F7686C615AA4B4236A95FF18C"
			"FBA0D0FA4862254713BE5B3844AF7A194BD96DEDEE4D9D05258B00DB83836E1B09A5BA5D1461A57969A42E43D46E3A2391892D3EA7A713D49153B18975919B971110AB5BCB49BDFB1D44F78481F4CEF0A346560FF2C"
			"3D7256F28989C10EEB44FE540DED2341309C39FCD8BE933E7523DFA8BE12BDB1FE3FE4BC3E635DE8C37373CE15E19F20FCE20F1592E125BCF495844FE98DF3E3E20857BAF2F3E8BC90F56D0A8DB"
			"C0B6415887B5783EFCA1B0E4F4FDA93469DD2955A15922B8C0907C9BFF747DA6BD3828ADCA51D49BD8377FD25EBDAA1D33E66CB367"
			"90C9072F62EC84E16D736656A05ACC8508817AE6B422CD630ED889BBB9186F83066D709F1FD4B2DA292C8127E3CAADC88301FCA6416CB7F692927064C0899C8D50951F"
			"2D259CB4007F194E17A8EB1341433E9FE3150351ACA83B0E0D77614975C97B7CFD09811E1D7C4E05F0AC909AE8E0D1D52774A117C7A1482977FD88BC12C512"
			"60D427A49F58FEB13039998EC9181E5016540FF18721DA6E0B295B9897FBED9592ACF46345E95FB8D66E95B0C43E485CED6928984AFD70940DE"
			"B3A8F0E921A716C8A050BABE71BF5364F437807186D35F54EFECBC7EA4B89BFF3E3821BAEE751D1656A33628A1B03C9947AE66A4F9D6C3575D66CD0DFF696465DAE5C970C571CF6FF"
			"94FC3F004C52AF00587AE9614683DBE354209167BB28D478BA38A4BF16EC6C0850AAB30685E1F5B16D0B597E4F1D0170DD4A73B66D5402ABA0780288E5DF1D491B2862E9007AACED6AA76DFF3EA0D8AB9982008C88836E5"
			"81D650EF08BBD9BF1E1C7F63D86E5C4E9C767BD87F32E65D57CDD8ABA07486B6FB9848DA23B472A1FC453160DC6EE3931120DC53490D103017ED0FDAEB1B2138245A2E3E934B0E12EBBED26289B48567BF1D8AF4CF61CC87A55618D49C77C9BD7234DF6847C347F9E46F3E"
			"9FF4D92530EAAF8F5BD0626B05F7B558783CBA23B62E7768208D438E3B36C1A6237D31DF9BB1EE1FD2B7F4E04C742F306AD241103FDF016666B9D5D5F5649B00743C94"
			"A9E4893808754F1E41E74459E52E92DD04CB3209CB118F82481AA48D12224F38D0D202F57EE1AD83800585E9FB1638417D757E44CBF36186487337640C17065FC551EB4418348AF517FD3F22E5A40C7076F6067C6909FC74E0CA2BE140B6683E51D40D21403967FE9F5F9201EB8A56C3D84F40F06FE5B492C1DD24612C5163061D5883AC";

		IHash HashInstance = HashFactory::XOF::CreateKMAC128XOF(EmptyBytes, EmptyBytes, 128);
		IXOF XofInstance = HashFactory::XOF::CreateKMAC128XOF(EmptyBytes, EmptyBytes, 8000);
	
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
			ExpectedString = "CD83740BBD92CCC8CF032B1481A0F4460E7CA9DD12B08A0C4031178BACD6EC35";
			IXOF xofInstance = HashFactory::XOF::CreateKMAC128XOF(ASCIICharacterBytes, EmptyBytes,
				OutputSizeInBits);
			DoComputeKMACXOF(xofInstance, ZeroToThreeBytes, ExpectedString);
		}

		SECTION("TestNISTXOFSample2")
		{
			ExpectedString = "31A44527B4ED9F5C6101D11DE6D26F0620AA5C341DEF41299657FE9DF1A3B16C";
			IXOF xofInstance = HashFactory::XOF::CreateKMAC128XOF(ASCIICharacterBytes, CustomizationMessageBytes,
				OutputSizeInBits);
			DoComputeKMACXOF(xofInstance, ZeroToThreeBytes, ExpectedString);
		}

		SECTION("TestNISTXOFSample3")
		{
			ExpectedString = "47026C7CD793084AA0283C253EF658490C0DB61438B8326FE9BDDF281B83AE0F";
			IXOF xofInstance = HashFactory::XOF::CreateKMAC128XOF(ASCIICharacterBytes, CustomizationMessageBytes,
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
				HashFactory::XOF::CreateKMAC128XOF(EmptyBytes, EmptyBytes, 0),
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
