#pragma once

#include "../Catch2-2.13.6/single_include/catch2/catch.hpp"

#include "../Base/TestConstants.h"
#include "../Base/Blake2BTestVectors.h"

namespace CryptoHashTests
{
	TEST_CASE("Blake2BTests")
	{
		string HashOfEmptyData = "786A02F742015903C6C6FD852552D272912F4740E15847618A86E217F71F5419D25E1031AFEE585313896444934EB04B903A685B1448B755D56F701AFE9BE2CE";
		string HashOfDefaultData = "154F99998573B5FC21E3DF86EE1E0161A6E0E912C4361088FE46D2E3543070EFE9746E326BC09E77EC06BCA60955538821C010411B4D0D6BF9BF2D2221CC8017";
		string HashOfOnetoNine = "F5AB8BAFA6F2F72B431188AC38AE2DE7BB618FB3D38B6CBF639DEFCDD5E10A86B22FCCFF571DA37E42B23B80B657EE4D936478F582280A87D6DBB1DA73F5C47D";
		string HashOfABCDE = "F3E89A60EC4B0B1854744984E421D22B82F181BD4601FB9B1726B2662DA61C29DFF09E75814ACB2639FD79E56616E55FC135F8476F0302B3DC8D44E082EB83A8";
		string HashOfDefaultDataWithHMACWithShortKey = "945EF4F96C681CC9C30A3EB1193FA13FD4ACD87D7C4A86D62AC9D8DCA74A32BB0DDC055EA75383A653E06B8E25266154DE5BE6B23C69723B795A1680EE844834";
		string HashOfDefaultDataWithHMACWithLongKey = "0D70DA6A592E53ADD0900A00A2F1181198B349114D6D089B48BDAE8C2F287617D71FBCEFB375C4EB91222D96407E24DF1C1770CF88FFFDD341DC75D43E562D7E";
		
		string Blake2BTreeHashingMode = "3AD2A9B37C6070E374C7A8C508FE20CA86B6ED54E286E93A0318E95E881DB5AA";
		
		//
		IBlake2BConfig config = Blake2BConfig::CreateBlake2BConfig(64);
		config->SetKey(ZeroToSixtyThreeBytes);

		IHash HashInstance = HashFactory::Crypto::CreateBlake2B();
		IHMACNotBuildIn HMACInstance = HashFactory::HMAC::CreateHMAC(HashInstance);
		IHash HashInstanceWithKey = HashFactory::Crypto::CreateBlake2B(config);

		HashLibStringArray UnkeyedTestVectors = Blake2BTestVectors::UnkeyedBlake2B;
		HashLibStringArray KeyedTestVectors = Blake2BTestVectors::KeyedBlake2B;
		
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

		SECTION("TestUnKeyedVsEmptyKeyAreSame")
		{
			IBlake2BConfig ConfigNoKeyed, ConfigNullKeyed;
			HashLibByteArray MainData;
			Int32 i;

			for (i = 1; i < 64; i++)
			{
				ConfigNoKeyed = Blake2BConfig::CreateBlake2BConfig(i);
				ConfigNullKeyed = Blake2BConfig::CreateBlake2BConfig(i);
				ConfigNullKeyed->SetKey({});

				IHash ExpectedHash = HashFactory::Crypto::CreateBlake2B(ConfigNoKeyed);
				string ExpectedString = ExpectedHash->ComputeBytes(MainData)->ToString();

				IHash ActualHash = HashFactory::Crypto::CreateBlake2B(ConfigNullKeyed);
				string ActualString = ActualHash->ComputeBytes(MainData)->ToString();

				REQUIRE(ExpectedString == ActualString);
			}
		}

		SECTION("TestBlake2BTreeHashingMode")
		{
			const byte FAN_OUT = 2;
			const byte MAX_DEPTH = 2;
			const byte INNER_SIZE = 64;
			const UInt32 LEAF_SIZE = 4096;

			HashLibByteArray buffer = HashLibByteArray(6000);

			// Left leaf
			IBlake2BTreeConfig treeConfigh00 = Blake2BTreeConfig::CreateBlake2BTreeConfig();
			treeConfigh00->SetFanOut(FAN_OUT);
			treeConfigh00->SetMaxDepth(MAX_DEPTH);
			treeConfigh00->SetLeafSize(LEAF_SIZE);
			treeConfigh00->SetInnerHashSize(INNER_SIZE);
			treeConfigh00->SetNodeOffset(0);
			treeConfigh00->SetNodeDepth(0);
			treeConfigh00->SetIsLastNode(false);

			IHash h00 = HashFactory::Crypto::CreateBlake2B(Blake2BConfig::GetDefaultConfig(), treeConfigh00);
			h00->Initialize();

			// Right leaf
			IBlake2BTreeConfig treeConfigh01 = Blake2BTreeConfig::CreateBlake2BTreeConfig();
			treeConfigh01->SetFanOut(FAN_OUT);
			treeConfigh01->SetMaxDepth(MAX_DEPTH);
			treeConfigh01->SetLeafSize(LEAF_SIZE);
			treeConfigh01->SetInnerHashSize(INNER_SIZE);
			treeConfigh01->SetNodeOffset(1);
			treeConfigh01->SetNodeDepth(0);
			treeConfigh01->SetIsLastNode(true);

			IHash h01 = HashFactory::Crypto::CreateBlake2B(Blake2BConfig::GetDefaultConfig(), treeConfigh01);
			h01->Initialize();

			// Root node
			IBlake2BTreeConfig treeConfigh10 = Blake2BTreeConfig::CreateBlake2BTreeConfig();
			treeConfigh10->SetFanOut(FAN_OUT);
			treeConfigh10->SetMaxDepth(MAX_DEPTH);
			treeConfigh10->SetLeafSize(LEAF_SIZE);
			treeConfigh10->SetInnerHashSize(INNER_SIZE);
			treeConfigh10->SetNodeOffset(0);
			treeConfigh10->SetNodeDepth(1);
			treeConfigh10->SetIsLastNode(true);

			IHash h10 = HashFactory::Crypto::CreateBlake2B(Blake2BConfig::CreateBlake2BConfig(32), treeConfigh10);
			h10->Initialize();

			HashLibByteArray temp = HashLibByteArray(LEAF_SIZE);
			memmove(&temp[0], &buffer[0], temp.size());

			h10->TransformBytes(h00->ComputeBytes(temp)->GetBytes());

			temp = HashLibByteArray(buffer.size() - LEAF_SIZE);
			memmove(&temp[0], &buffer[LEAF_SIZE], temp.size());

			h10->TransformBytes(h01->ComputeBytes(temp)->GetBytes());

			string ExpectedString = Blake2BTreeHashingMode;
			string ActualString = h10->TransformFinal()->ToString();

			REQUIRE(ExpectedString == ActualString);
		}

		SECTION("HMACWithDefaultDataAndLongKey")
		{
			IHMACNotBuildIn hmac = HashFactory::HMAC::CreateHMAC(HashInstance);
			hmac->SetKey(HMACLongKeyBytes);

			string String = HashOfDefaultDataWithHMACWithLongKey;
			string ActualString = hmac->ComputeString(DefaultData)->ToString();

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