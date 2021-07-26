#pragma once

#include "../Catch2-2.13.6/single_include/catch2/catch.hpp"

#include "../Base/TestConstants.h"
#include "../Base/Blake2STestVectors.h"

namespace CryptoHashTests
{
	TEST_CASE("Blake2BPTests")
	{
		string HashOfEmptyData = "B5EF811A8038F70B628FA8B294DAAE7492B1EBE343A80EAABBF1F6AE664DD67B9D90B0120791EAB81DC96985F28849F6A305186A85501B405114BFA678DF9380";
		string HashOfDefaultData = "6F02764BDBA4184E50CAA52539BC392239D31E1BC76CEACBCA42630BCB7B48B527F65AA2F50363C0E26A287B758C87BC77C7175AB7A12B33104330F5A1C6E171";
		string HashOfOnetoNine = "E70843E71EF73EF84D991990687CB72E272E590F7E86F491935E9904F0582A165A388F956D691101C5D2B035634E4415C3CB21D7F721702CC64791D53AEDB9E2";
		string HashOfABCDE = "C96CA7B60257D18A67EC6DAF4E06A6A0F882ECEE22605DBE64DFAD2D7AA2FF939726385C7E60F00A2A38CF302E460C33EAE769CA5652FA8456EA6A75DC6AAC39";
		string HashOfDefaultDataWithHMACWithShortKey = "671A8EE18AD7BCC940CF4B35B47D0AAA89077AA8503E4E374A5BC2803758BBF04C6C80F97E5B71CD79A1E6DCD6585EB82A5F5482DB268B462D651530CE5CB177";
		string HashOfDefaultDataWithHMACWithLongKey = "5FBB74E2A06A9D10762E3B2BD2ECC3B0E83F2FB1652D6F55E426D59354DF3803583E055318762DEF415DE98E441DC153263857B08D5F2462753872E663C13D5C";
		
		IHash HashInstance = HashFactory::Crypto::CreateBlake2BP(64, {});
		IHMACNotBuildIn HMACInstance = HashFactory::HMAC::CreateHMAC(HashInstance, {});
		IHash HashInstanceWithKey = HashFactory::Crypto::CreateBlake2BP(64, ZeroToSixtyThreeBytes);

		HashLibStringArray KeyedTestVectors = Blake2BPTestVectors::KeyedBlake2BP;
		HashLibStringArray UnkeyedTestVectors = Blake2BPTestVectors::UnKeyedBlake2BP;
		
		SECTION("TestCheckKeyedTestVectors")
		{
			string ActualString, ExpectedString;
			Int32 i;

			for (i = 0; i < KeyedTestVectors.size(); i++)
			{
				ActualString = HashInstanceWithKey->ComputeBytes(GenerateByteArrayInRange(0, i))->ToString();
				ExpectedString = KeyedTestVectors[i];
				REQUIRE(ExpectedString == ActualString);
			}
		}

		SECTION("TestCheckUnKeyedTestVectors")
		{
			string ActualString, ExpectedString;
			Int32 i;

			for (i = 0; i < UnkeyedTestVectors.size(); i++)
			{
				ActualString = HashInstance->ComputeBytes(GenerateByteArrayInRange(0, i))->ToString();
				ExpectedString = UnkeyedTestVectors[i];
				REQUIRE(ExpectedString == ActualString);
			}
		}
		
		SECTION("HMACWithDefaultDataAndLongKey")
		{
			IHMACNotBuildIn hmac = HashFactory::HMAC::CreateHMAC(HashInstance);
			hmac->SetKey(HMACLongKeyBytes);

			string String = HashOfDefaultDataWithHMACWithLongKey;
			string ActualString = hmac->ComputeBytes(DefaultDataBytes)->ToString();

			REQUIRE(String == ActualString);
		}

		SECTION("HMACWithDefaultDataAndShortKey")
		{
			IHMACNotBuildIn hmac = HashFactory::HMAC::CreateHMAC(HashInstance);
			hmac->SetKey(HMACShortKeyBytes);

			string String = HashOfDefaultDataWithHMACWithShortKey;
			string ActualString = hmac->ComputeString(DefaultData)->ToString();

			REQUIRE(String == ActualString);
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

		SECTION("TestEmptyStream")
		{
			// Read empty file to stream
			ifstream stream("EmptyFile.txt");

			string String = HashOfEmptyData;
			string ActualString = HashInstance->ComputeStream(stream)->ToString();

			REQUIRE(String == ActualString);
		}

		SECTION("TestIncrementalHash")
		{
			HashInstance->Initialize();
			HashInstance->TransformString(DefaultData.substr(0, 3));
			HashInstance->TransformString(DefaultData.substr(3, 3));
			HashInstance->TransformString(DefaultData.substr(6, 3));
			HashInstance->TransformString(DefaultData.substr(9, 3));
			HashInstance->TransformString(DefaultData.substr(12));

			string String = HashOfDefaultData;
			string ActualString = HashInstance->TransformFinal()->ToString();

			REQUIRE(String == ActualString);
		}

		SECTION("TestIndexChunkedDataIncrementalHash")
		{
			Int32 Count, i;
			HashLibByteArray temp, ChunkedDataBytes;
			IHash HashInstanceCopy = nullptr;

			HashInstanceCopy = HashInstance->Clone();
			ChunkedDataBytes = Converters::ConvertStringToBytes(ChunkedData);
			for (i = 0; i < (Int32)ChunkedDataBytes.size(); i++)
			{
				Count = (Int32)ChunkedDataBytes.size() - i;

				const HashLibByteArray::const_iterator start = ChunkedDataBytes.begin() + i;
				const HashLibByteArray::const_iterator end = ChunkedDataBytes.end();

				temp = HashLibByteArray(start, end);
				HashInstance->Initialize();

				HashInstance->TransformBytes(ChunkedDataBytes, i, Count);

				string ActualString = HashInstance->TransformFinal()->ToString();
				string String = HashInstanceCopy->ComputeBytes(temp)->ToString();

				REQUIRE(String == ActualString);
			}
		}

		SECTION("TestAnotherChunkedDataIncrementalHash")
		{
			size_t x, size, i;
			string temp;
			IHash HashInstanceCopy = nullptr;

			HashInstanceCopy = HashInstance->Clone();
			for (x = 0; x < (sizeof(ChunkSizes) / sizeof(Int32)); x++)
			{
				size = ChunkSizes[x];
				HashInstance->Initialize();
				i = size;
				while (i < ChunkedData.size())
				{
					temp = ChunkedData.substr((i - size), size);
					HashInstance->TransformString(temp);

					i += size;
				}

				temp = ChunkedData.substr((i - size), ChunkedData.size() - ((i - size)));
				HashInstance->TransformString(temp);

				string ActualString = HashInstance->TransformFinal()->ToString();
				string String = HashInstanceCopy->ComputeString(ChunkedData)->ToString();

				REQUIRE(String == ActualString);
			}
		}

		SECTION("TestHashCloneIsCorrect")
		{
			IHash Original = HashInstance->Clone();
			IHash Copy;

			// Initialize Original Hash
			Original->Initialize();
			Original->TransformBytes(ChunkOne);

			// Make Copy Of Current State
			Copy = Original->Clone();

			Original->TransformBytes(ChunkTwo);
			string String = Original->TransformFinal()->ToString();

			Copy->TransformBytes(ChunkTwo);
			string ActualString = Copy->TransformFinal()->ToString();

			REQUIRE(String == ActualString);
		}

		SECTION("TestHashCloneIsUnique")
		{
			IHash Original = HashInstance->Clone();
			IHash Copy;

			Original->Initialize();
			Original->SetBufferSize(64 * 1024); // 64Kb
												// Make Copy Of Current State

			Copy = Original->Clone();
			Copy->SetBufferSize(128 * 1024); // 128Kb

			REQUIRE_FALSE(Original->GetBufferSize() == Copy->GetBufferSize());
		}

		SECTION("TestHMACCloneIsCorrect")
		{
			IHMACNotBuildIn Original;
			IHMACNotBuildIn Copy;

			Original = HashFactory::HMAC::CreateHMAC(HashInstance);
			Original->SetKey(HMACLongKeyBytes);
			Original->Initialize();
			Original->TransformBytes(ChunkOne);

			// Make Copy Of Current State
			Copy = Original->CloneHMAC();

			Original->TransformBytes(ChunkTwo);
			string String = Original->TransformFinal()->ToString();

			Copy->TransformBytes(ChunkTwo);
			string ActualString = Copy->TransformFinal()->ToString();

			REQUIRE(String == ActualString);
		}

	};


}