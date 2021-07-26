#pragma once

#include "../Catch2-2.13.6/single_include/catch2/catch.hpp"

#include "../Base/TestConstants.h"
#include "../Base/Blake2BTestVectors.h"

namespace XOFTests
{
	TEST_CASE("Blake2XBTests")
	{
		const Int32 HashSize = 64;

		string ExpectedString, ActualString;

		string HashOfEmptyData = "C5EF3D8845B9B2BA8EA28E9326C9E46E7A5843AD42BACAF927798BEAF554A43CA0830CCF8BB4A24CE1B1D82BD2DA971AFB2BE73919CC5FFF8E7C6A20F87284FA";
		string HashOfDefaultData = "9A4C47E816EF6A06F9708B8AE2FEE224F18565CE1F08B848945B73A961BB5E83D79B3A71BE6E324243483C265007A2CD67DE3150C26DC799CE7FC201981AC80A";
		string HashOfOnetoNine = "3FD021E013DF681EE479A6E3CE7D36E53971946C586147D59EECF1634C31C318F03BBCE3CDB0B1EC5CD4BD4EDF8ED1441A37754899BB3D8850FCA5EBE0639ABB";
		string HashOfABCDE = "81B9FF044391492C89822F8A96279128E876FC5326B0C5C83552B503409F1A6A6CA66DAECE711FE4FCC5DBD92D8560172A64472FAF845CAA7F4297E17ECA1283";
		string XofOfEmptyData =
			"85DDB224AFA3113F145AC1AA3618BD7496FDC79AF14372734A2CDCE9E8DA30029454BAF1C2D78D528F011B3F3FE824CF05B28C4CF34791B3595AC30AB7B348F"
			"23084628A4315036BE75EDCBE93E217B922E7D8E8CD5EBC35580BC2909432E74506C0080718198A87F44BF22B83DE6FCBE6AC98965D9D8B83F37AACB75064FD6205762BA7CDFFF6F4B83"
			"672D5296D8D550FDE5B8D16E465D95C26DE2819DA44130EAA3698EC5F2F892133E8F20948523CEE89F01723078FA2E4BE0395638CFAF7F05265C43FF7C08A03EDA0516476CD6C9D14B560E"
			"7B1FE6E7D59BD658B434755CC58F1780ADE865EA9D365949BF7D260C46452FFF6CBFA9AB54EED5725E9A4E747F4C8C40F1BBAFCE1EEDDE87476924B78B8F7D61ABC93087327CD3220A"
			"088C757B6E5E8C3A2530B08F7710D4E79E7EBA9C1B839A32E941D934D8B675B5029FE5AC6F00E64F5432DB9E40DFFD9C85A28D2D1786C51026F5AFCB06FD58414E12FF94A50D3F583885"
			"F5547605C11BF0C3F9CA71AC9EE9B4D5499A92FE4D765F48F9AE48441E65B384B14946F9A639B53CECB91636A9C14246B769FE7A3E6AAFD131110F3ABF157887A18EFFA5CA80887C358F5F"
			"7292A09F3AB997D3FD4D08E2178F358F46B8862F220E495940BD60BF96FA219B0B90383E5FBF4DF496E922354DE70363583932F440E839093E3DB3615A3A38A3EF79BEFCA3C8B10FA55"
			"FB997E6B25EB68DF7AD4A69FF2B9D20CB3EC981143CEC641732C4FFB899E1496CF8920167097BE4AD3448385FB25C5BE411027798E89ADC79F8225DE42E292C02D24BD2356F9C9D"
			"CA502C0A1671BB7D25D91A038A6634670C9E9E668B18124C56CBC3FC7E56A01E8BAF23463DC2ACFEDF572070BD3EAD179CD4008A198EE0A544A975D401A5CED306A861FF23D17D91F67F"
			"F2F7CF453F9C444DDFCA81761C482299E098FEA53CD8C809B5E3F5AFEF857BFE918833EBF7B7B272DC014967F5610E39CD09EB8E7AB662F4DFD0CEF98DEC5F95307AA900EF27DF36373FE31"
			"6DCB951C623729B26F61723B73AD442250F8C2EC7033447795860232B9012B4C837EA47E0F69A9C4A0489AD7BC48BC58BB8EB948BBAC2A638549EDE38B215ABFC30FBEB29F255A9C710A2"
			"29B4070A5B09D894E1460DD577173892779BBA4257B60FCC9253BE3E6350221CE615438A04C86E3D6FAB218DE5947459B93D02D00C771F8F3820BABCAE18ADF599649F7716C7CECE86866B"
			"E1B03FC5390199A7607CA7E45CDAD99411A850125C90AD526C2008293185C1B5B008A458F8F885C8614F317ED52DBAF3E82D0A4B0E47E41C63F145FB17B994B5E9829D8138876A3ADA"
			"872FD00914654D504245150B178B919D9F9A7219DB86595D3AACA009798FB52DD0D28F8FFBE4D75063EFD98E655CDEE16";

		IHash HashInstance = HashFactory::XOF::CreateBlake2XB(EmptyBytes, 512);
		IXOF XofInstance = HashFactory::XOF::CreateBlake2XB(EmptyBytes, 8000);

		SECTION("TestCheckTestVectors")
		{
			HashLibByteArray data = Converters::ConvertHexStringToBytes(
				Blake2BTestVectors::Blake2XB_XofTestInput);
			
			for(size_t i = 0; i < Blake2BTestVectors::Blake2XB_XofTestVectors.size(); i++)
			{
				HashLibStringArray vector = Blake2BTestVectors::Blake2XB_XofTestVectors[i];
				HashLibByteArray key = Converters::ConvertHexStringToBytes(vector[0]);

				ActualString = 
					HashFactory::XOF::CreateBlake2XB(key, (UInt64)((vector[1].size() >> 1) * 8))
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
				HashFactory::XOF::CreateBlake2XB(HashLibByteArray(HashSize + 1), 512),
				ArgumentOutOfRangeHashLibException);
		}

		SECTION("TestSettingEmptyKeyDoesNotThrowsException")
		{
			REQUIRE_NOTHROW(HashFactory::XOF::CreateBlake2XB(EmptyBytes, 512));
		}

		SECTION("TestSettingOutOfRangeSaltThrowsCorrectException")
		{
			IBlake2BConfig config = Blake2BConfig::CreateBlake2BConfig(HashSize);
			
			REQUIRE_THROWS_AS(
				config->SetSalt(HashLibByteArray(17)),
				ArgumentOutOfRangeHashLibException);

			/*HashFactory::XOF::CreateBlake2XB(
				Blake2XBConfig::CreateBlake2XBConfig(config, nullptr), 512)*/
		}

		SECTION("TestSettingEmptySaltDoesNotThrow")
		{
			IBlake2BConfig config = Blake2BConfig::CreateBlake2BConfig(HashSize);
			config->SetSalt(EmptyBytes);

			REQUIRE_NOTHROW(
				HashFactory::XOF::CreateBlake2XB(
					Blake2XBConfig::CreateBlake2XBConfig(config, nullptr), 512));
		}

		SECTION("TestSettingOutOfRangePersonalizationThrowsCorrectException")
		{
			IBlake2BConfig config = Blake2BConfig::CreateBlake2BConfig(HashSize);
			
			REQUIRE_THROWS_AS(
				config->SetPersonalization(HashLibByteArray(17)),
				ArgumentOutOfRangeHashLibException);

			/*HashFactory::XOF::CreateBlake2XB(
				Blake2XBConfig::CreateBlake2XBConfig(config, nullptr), 512)*/
		}

		SECTION("TestSettingEmptyPersonalizationDoesNotThrowsException")
		{
			IBlake2BConfig config = Blake2BConfig::CreateBlake2BConfig(HashSize);
			config->SetPersonalization(EmptyBytes);

			REQUIRE_NOTHROW(
				HashFactory::XOF::CreateBlake2XB(
					Blake2XBConfig::CreateBlake2XBConfig(config, nullptr), 512));
		}

		SECTION("TestSettingInvalidSizeThrowsCorrectException")
		{
			REQUIRE_THROWS_AS(
				HashFactory::XOF::CreateBlake2XB(EmptyBytes, 0),
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
