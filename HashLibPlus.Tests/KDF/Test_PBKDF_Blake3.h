#pragma once

#include <iostream>

#include "../Catch2-2.13.6/single_include/catch2/catch.hpp"

#include "../Base/TestConstants.h"
#include "../Base/Blake3TestVectors.h"

namespace KDFTests
{
	TEST_CASE("PBKDF_Blake3TestVectors")
	{
		string ActualString, ExpectedString;
		Int32 ByteCount = 32;

		IKDFNotBuildIn KdfInstance =
			HashFactory::KDF::CreatePBKDF_Blake3(EmptyBytes, EmptyBytes);

		string ctxString = "BLAKE3 2019-12-27 16:29:52 test vectors context";
		HashLibByteArray ctx = Converters::ConvertStringToBytes(ctxString);
		HashLibByteArray fullInput = HashLibByteArray(1 << 15);

		HashLibMatrixStringArray blake3TestVectors = Blake3TestVectors::Blake3Vectors;

		SECTION("TestCheckTestVectors")
		{	
			for (size_t i = 0; i < fullInput.size(); i++) { fullInput[i] = (byte)(i % 251); }

			for (size_t i = 0; i < blake3TestVectors.size(); i++)
			{
				HashLibStringArray vector = blake3TestVectors[i];

				Int32 count = (Int32)stoi(vector[0]);

				const HashLibByteArray::const_iterator start = fullInput.begin();
				const HashLibByteArray::const_iterator end = start + count;

				HashLibByteArray chunkedInput(start, end);

				KdfInstance = HashFactory::KDF::CreatePBKDF_Blake3(chunkedInput, ctx);

				HashLibByteArray output = KdfInstance->GetBytes((Int32)vector[3].size() >> 1);

				REQUIRE(output == Converters::ConvertHexStringToBytes(vector[3]));
			}
		}

		SECTION("TestKdfCloningWorks")
		{
			IKDFNotBuildIn kdfInstanceClone = KdfInstance->Clone();

			HashLibByteArray result = KdfInstance->GetBytes(ByteCount);
			HashLibByteArray resultClone = kdfInstanceClone->GetBytes(ByteCount);

			REQUIRE(result == resultClone);
		}
	}
}