#pragma once

#include "../Catch2-2.13.6/single_include/catch2/catch.hpp"

#include "../Base/TestConstants.h"
#include "../Base/Blake2STestVectors.h"

namespace CryptoHashTests
{
	TEST_CASE("Blake2STests")
	{
		string HashOfEmptyData = "69217A3079908094E11121D042354A7C1F55B6482CA1A51E1B250DFD1ED0EEF9";
		string HashOfDefaultData = "D9DB23D51529BC163546C2C76F9FDC4611118A691352524D6BCCF5C79AF89E14";
		string HashOfOnetoNine = "7ACC2DD21A2909140507F37396ACCE906864B5F118DFA766B107962B7A82A0D4";
		string HashOfABCDE = "4BD7246C13721CC5B96F045BE71D49D5C82535332C6903771AFE9EF7B772136F";
		string HashOfDefaultDataWithHMACWithShortKey = "105C7994CB1F775C709A9FBC9641FB2495311258268134F460B9895915A7519A";
		string HashOfDefaultDataWithHMACWithLongKey = "2FF5605B8269DE6FA04C03CD30C8C48838605C639A38EBF42A93830CE7CA5E57";

		string Blake2STreeHashingMode = "C81CD326CA1CA6F40E090A9D9E738892";

		//
		IBlake2SConfig config = Blake2SConfig::CreateBlake2SConfig(32);
		config->SetKey(ZeroToThirtyOneBytes);

		IHash HashInstance = HashFactory::Crypto::CreateBlake2S();
		IHMACNotBuildIn HMACInstance = HashFactory::HMAC::CreateHMAC(HashInstance);
		IHash HashInstanceWithKey = HashFactory::Crypto::CreateBlake2S(config);

		HashLibStringArray UnkeyedTestVectors = Blake2STestVectors::UnkeyedBlake2S;
		HashLibStringArray KeyedTestVectors = Blake2STestVectors::KeyedBlake2S;
		
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
			IBlake2SConfig ConfigNoKeyed, ConfigNullKeyed;
			HashLibByteArray MainData;
			Int32 i;

			for (i = 1; i < 32; i++)
			{
				ConfigNoKeyed = Blake2SConfig::CreateBlake2SConfig(i);
				ConfigNullKeyed = Blake2SConfig::CreateBlake2SConfig(i);
				ConfigNullKeyed->SetKey({});

				IHash ExpectedHash = HashFactory::Crypto::CreateBlake2S(ConfigNoKeyed);
				string ExpectedString = ExpectedHash->ComputeBytes(MainData)->ToString();

				IHash ActualHash = HashFactory::Crypto::CreateBlake2S(ConfigNullKeyed);
				string ActualString = ActualHash->ComputeBytes(MainData)->ToString();

				REQUIRE(ExpectedString == ActualString);
			}
		}

		SECTION("TestBlake2STreeHashingMode")
		{
			const byte FAN_OUT = 2;
			const byte MAX_DEPTH = 2;
			const byte INNER_SIZE = 32;
			const UInt32 LEAF_SIZE = 4096;

			HashLibByteArray buffer = HashLibByteArray(6000);

			// Left leaf
			IBlake2STreeConfig treeConfigh00 = Blake2STreeConfig::CreateBlake2STreeConfig();
			treeConfigh00->SetFanOut(FAN_OUT);
			treeConfigh00->SetMaxDepth(MAX_DEPTH);
			treeConfigh00->SetLeafSize(LEAF_SIZE);
			treeConfigh00->SetInnerHashSize(INNER_SIZE);
			treeConfigh00->SetNodeOffset(0);
			treeConfigh00->SetNodeDepth(0);
			treeConfigh00->SetIsLastNode(false);

			IHash h00 = HashFactory::Crypto::CreateBlake2S(Blake2SConfig::GetDefaultConfig(), treeConfigh00);
			h00->Initialize();

			// Right leaf
			IBlake2STreeConfig treeConfigh01 = Blake2STreeConfig::CreateBlake2STreeConfig();
			treeConfigh01->SetFanOut(FAN_OUT);
			treeConfigh01->SetMaxDepth(MAX_DEPTH);
			treeConfigh01->SetLeafSize(LEAF_SIZE);
			treeConfigh01->SetInnerHashSize(INNER_SIZE);
			treeConfigh01->SetNodeOffset(1);
			treeConfigh01->SetNodeDepth(0);
			treeConfigh01->SetIsLastNode(true);

			IHash h01 = HashFactory::Crypto::CreateBlake2S(Blake2SConfig::GetDefaultConfig(), treeConfigh01);
			h01->Initialize();

			// Root node
			IBlake2STreeConfig treeConfigh10 = Blake2STreeConfig::CreateBlake2STreeConfig();
			treeConfigh10->SetFanOut(FAN_OUT);
			treeConfigh10->SetMaxDepth(MAX_DEPTH);
			treeConfigh10->SetLeafSize(LEAF_SIZE);
			treeConfigh10->SetInnerHashSize(INNER_SIZE);
			treeConfigh10->SetNodeOffset(0);
			treeConfigh10->SetNodeDepth(1);
			treeConfigh10->SetIsLastNode(true);

			IHash h10 = HashFactory::Crypto::CreateBlake2S(Blake2SConfig::CreateBlake2SConfig(16), treeConfigh10);
			h10->Initialize();

			HashLibByteArray temp = HashLibByteArray(LEAF_SIZE);
			memmove(&temp[0], &buffer[0], temp.size());

			h10->TransformBytes(h00->ComputeBytes(temp)->GetBytes());

			temp = HashLibByteArray(buffer.size() - LEAF_SIZE);
			memmove(&temp[0], &buffer[LEAF_SIZE], temp.size());

			h10->TransformBytes(h01->ComputeBytes(temp)->GetBytes());

			string ExpectedString = Blake2STreeHashingMode;
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