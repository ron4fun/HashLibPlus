#pragma once

#include "../Catch2-2.13.6/single_include/catch2/catch.hpp"

#include "../Base/TestConstants.h"
#include "../Base/Blake3TestVectors.h"

namespace XOFTests
{
	TEST_CASE("Blake3XOFTests")
	{
		string ExpectedString, ActualString;

		string HashOfEmptyData = "AF1349B9F5F9A1A6A0404DEA36DCC9499BCB25C9ADC112B7CC9A93CAE41F3262E00F03E7B69AF26B7FAAF09FCD333050338DDFE085B8CC869CA98B206C08243A";
		string HashOfDefaultData = "BB8DB7E4155BFDB254AD49D8D3105C57B6AC3E783E6D316A75E8B8F8911EB41F800B6ACB7F3593E1787BF62433D016B800B75C14C4E3E395FC5571ADEB1A7143";
		string HashOfOnetoNine = "B7D65B48420D1033CB2595293263B6F72EABEE20D55E699D0DF1973B3C9DEED15042F0A21EE5D17C59E507AE27E48A7CD85F69DCD816C5F421883F36E513D9FE";
		string HashOfABCDE = "0648C03B5AD9BB6DDF8306EEF6A33EBAE8F89CB4741150C1AE9CD662FDCC1EE2AB9CED8A57741468B7C3163AF41767186CE877C7AE21260064FD4EAD6004D549";
		string XofOfEmptyData =
			"AF1349B9F5F9A1A6A0404DEA36DCC9499BCB25C9ADC112B7CC9A93CAE41F3262E00F03E7B69AF26B7FAAF09FCD333050338DDFE085B8CC869CA98B206C08243A26F5"
			"487789E8F660AFE6C99EF9E0C52B92E7393024A80459CF91F476F9FFDBDA7001C22E159B402631F277CA96F2DEFDF1078282314E763699A31C5363165421CCE14D30F"
			"8A03E49EE25D2EA3CD48A568957B378A65AF65FC35FB3E9E12B81CA2D82CDEE16C68908A6772F827564336933C89E6908B2F9C7D1811C0EB795CBD5898FE6F5E8AF7633"
			"19CA863718A59AFF3D99660EF642483E217EF0C8785827284FEA90D42225E3CDD6A179BEE852FD24E7D45B38C27B9C2F9469EA8DBDB893F00E28534C7D15B59BADD5A5BDE"
			"B090E98EB93C5B2F42101394ACB7C72E9B60094D5442096754600DB8C0FA6DBDFEA154C324C07BF17B7AB0D1488AE5EF76CB7611BAEF17087D84C08B4F950D3D85E00E7001"
			"813FE029A10722BB003531D5AE406386E78CCA4CA7CACE8A41D294F6EE3B1C645832109B5B19304360B8AB79581E351C518849EAA7C7E14F37BA5B769D2CAF191F9DDEE2D49"
			"82B6213947A7D047A03F5E456F2588F56E4075C756A319299FBA4001C4B6FB89FBFD93B0739DC684424A439CEFB447D5E191919C4581BC153BD2F2FAE39758F1322AE52EA8B2"
			"D859887A71F70C03E28765709711950C2C06BF5C7D1BB6C235F722CE6DB047FE97CF74B87ADBD6531CB14A1193A8974F939DD2EB21335793880279905402DBDA8B5EC0A7C82A"
			"69151BB42F7126E4157A510C6123139815BA3DF3FD1D810795D1F4F49CB8B0D63D8D07833CE95FCFF2B8B8677D1F6C3EE3CF2A00CE72A32E93F5E225A065A0726DC5C9AD5C26F"
			"2C3560E401BA5079C3D63A8B29175BC9597B09A2BE664E6641F2D2EBFAFE58D5C025EE367396B4C0E31F9D761B779FF27DBAB678CFBB3C62460CC68A4C3187E9788E045EC92437"
			"1C3027903A42059D1ED659406706C5E4381C931886A034E20689FFA78221E39B42326A9725C5D669D5E2ABAA1C4640AFC7E4D3A5FF5C5513F1B13BF865F4F02EC09453DBD0BCD1D0"
			"AC3444141CC78B662F00811F095D1A1614EDCB516C70FB3BBF4C9ED58F8FBBDDE8CB1B5497585C53FB33EB7A98810780056C9952848F129D5A87DD36774C1B91E135C1ACEF799E6E4"
			"320FB862C3619F6874CE0D7550D260308D7E309EEEA5026A534D37DFA4F703BF185C015D99D88A1E350639634D1C7F1DE79FAEBC0DFECAC66089E6F44C916DEBC12965DD0ECFDDF8A"
			"D4CAFB5ABC45FC9FCA9780C26F457EA9DDCF5370A4D042BC5B9BFA87FAC10F88B170CD22CB9AB2255B251529272BADDF757AD471C4935363495B8E626421859FF304F6D5D527AAE2AF"
			"7444F3E14C8CD41F9BB1E19A1418E08A5B535C79554";

		IHash HashInstance = HashFactory::XOF::CreateBlake3XOF(EmptyBytes, 512);
		IXOF XofInstance = HashFactory::XOF::CreateBlake3XOF(EmptyBytes, 8000);

		SECTION("TestCheckTestVectors")
		{
			const string keyString = "whats the Elvish word for friend";

			HashLibByteArray fullInput(1 << 15);
			for(size_t i = 0; i < fullInput.size(); i++)
				fullInput[i] = (byte)(i % 251);

			HashLibByteArray key = Converters::ConvertStringToBytes(keyString);

			HashLibMatrixStringArray vectorList = Blake3TestVectors::Blake3Vectors;

			for(size_t i = 0; i < vectorList.size(); i++)
			{
				HashLibStringArray vector = vectorList[i];

				Int32 size = stoi(vector[0]);
				
				const HashLibByteArray::const_iterator start = fullInput.begin();
				const HashLibByteArray::const_iterator end = start + size;

				HashLibByteArray chunkedInput(start, end);
				
				IXOF xof = HashFactory::XOF::CreateBlake3XOF(EmptyBytes, (UInt64)((vector[1].size() >> 1) * 8));
				IXOF keyedXof = HashFactory::XOF::CreateBlake3XOF(key, (UInt64)((vector[2].size() >> 1) * 8));

				HashLibByteArray output(xof->GetXOFSizeInBits() / 8);
				HashLibByteArray keyedOutput(keyedXof->GetXOFSizeInBits() / 8);

				xof->Initialize();
				keyedXof->Initialize();

				xof->TransformBytes(chunkedInput);
				keyedXof->TransformBytes(chunkedInput);

				xof->DoOutput(output, 0, (UInt64)output.size());
				keyedXof->DoOutput(keyedOutput, 0, (UInt64)keyedOutput.size());

				REQUIRE(output == Converters::ConvertHexStringToBytes(vector[1]));

				REQUIRE(keyedOutput == Converters::ConvertHexStringToBytes(vector[2]));
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

		SECTION("TestSettingInvalidSizeThrowsCorrectException")
		{
			REQUIRE_THROWS_AS(
				HashFactory::XOF::CreateBlake3XOF(EmptyBytes, 0),
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
