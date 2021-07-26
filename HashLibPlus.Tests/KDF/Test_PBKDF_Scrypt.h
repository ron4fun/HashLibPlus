#pragma once

#include "../Catch2-2.13.6/single_include/catch2/catch.hpp"

#include "../Base/TestConstants.h"

string DoTestVector(const string& a_Password, const string& a_Salt, const Int32 a_Cost, const Int32 a_BlockSize,
	const Int32 a_Parallelism, const Int32 a_OutputSize)
{
	HashLibByteArray PasswordBytes, SaltBytes, OutputBytes;

	PasswordBytes = Converters::ConvertStringToBytes(a_Password);
	SaltBytes = Converters::ConvertStringToBytes(a_Salt);

	IPBKDF_Scrypt PBKDF_Scrypt = HashFactory::KDF::CreatePBKDF_Scrypt(PasswordBytes,
		SaltBytes, a_Cost, a_BlockSize, a_Parallelism);
	OutputBytes = PBKDF_Scrypt->GetBytes(a_OutputSize);
	PBKDF_Scrypt->Clear();

	return Converters::ConvertBytesToHexString(OutputBytes, false);
} //

void DoCheckOk(const string& a_Msg, const HashLibByteArray& a_Password, const HashLibByteArray& a_Salt, const Int32 a_Cost,
	const Int32 a_BlockSize, const Int32 a_Parallelism, const Int32 a_OutputSize)
{
	try
	{
		IPBKDF_Scrypt PBKDF_Scrypt = HashFactory::KDF::CreatePBKDF_Scrypt(a_Password,
			a_Salt, a_Cost, a_BlockSize, a_Parallelism);
		PBKDF_Scrypt->GetBytes(a_OutputSize);
		PBKDF_Scrypt->Clear();
	} //
	catch (ArgumentHashLibException&)
	{
		REQUIRE(false);
	} //
	catch (exception&)
	{
		REQUIRE(false);
	} //	

} //

void DoCheckIllegal(const string& a_Msg, const HashLibByteArray& a_Password, const HashLibByteArray& a_Salt,
	const Int32 a_Cost, const Int32 a_BlockSize, const Int32 a_Parallelism, const Int32 a_OutputSize)
{
	try
	{
		HashFactory::KDF::CreatePBKDF_Scrypt(a_Password, a_Salt, a_Cost,
			a_BlockSize, a_Parallelism)->GetBytes(a_OutputSize);

		REQUIRE(false);
	}
	catch (ArgumentHashLibException&)
	{
		// pass so we do nothing
	}
	catch (exception&)
	{
		// pass so we do nothing
	} //
} //


namespace KDFTests
{
	/// <summary>
	/// scrypt test vectors from "Stronger Key Derivation Via Sequential Memory-hard Functions" Appendix B.
	/// (http://www.tarsnap.com/scrypt/scrypt.pdf)
	/// </summary>
	TEST_CASE("PBKDF_ScryptTest")
	{
		string ActualString, ExpectedString;
		Int32 ByteCount = 32;
		IKDFNotBuildIn KdfInstance =
			HashFactory::KDF::CreatePBKDF_Scrypt(EmptyBytes, EmptyBytes, 16, 1, 1);

		SECTION("PBKDF_ScryptTestParameters")
		{
			DoCheckOk("Minimal values", {}, {}, 2, 1, 1, 1);
			DoCheckIllegal("Cost parameter must be > 1", {}, {}, 1, 1, 1, 1);
			DoCheckOk("Cost parameter 32768 OK for r = 1", {}, {}, 32768, 1, 1, 1);
			DoCheckIllegal("Cost parameter must < 65536 for r = 1", {}, {},
				65536, 1, 1, 1);
			DoCheckIllegal("Block size must be >= 1", {}, {}, 2, 0, 2, 1);
			DoCheckIllegal("Parallelisation parameter must be >= 1", {}, {}, 2,
				1, 0, 1);
			// disabled test because it"s very expensive
			// DoCheckOk("Parallelisation parameter 65535 OK for r = 4", {}, {}, 2, 32,
			// 65535, 1);
			DoCheckIllegal("Parallelisation parameter must be < 65535 for r = 4", {},
				{}, 2, 32, 65536, 1);

			DoCheckIllegal("Len parameter must be > 1", {}, {}, 2, 1, 1, 0);
		}

		SECTION("PBKDF_ScryptTestVectors")
		{
			ActualString = DoTestVector("", "", 16, 1, 1, 64);
			ExpectedString = "77D6576238657B203B19CA42C18A0497F16B4844E3074AE8DFDFFA3FEDE21442FCD0069DED0948F8326A753A0FC81F17E8D3E0FB2E0D3628CF35E20C38D18906";

			REQUIRE(ExpectedString == ActualString);

			ActualString = DoTestVector("password", "NaCl", 1024, 8, 16, 64);
			ExpectedString = "FDBABE1C9D3472007856E7190D01E9FE7C6AD7CBC8237830E77376634B3731622EAF30D92E22A3886FF109279D9830DAC727AFB94A83EE6D8360CBDFA2CC0640";

			REQUIRE(ExpectedString == ActualString);

			ActualString = DoTestVector("pleaseletmein", "SodiumChloride", 16384, 8, 1, 64);
			ExpectedString = "7023BDCB3AFD7348461C06CD81FD38EBFDA8FBBA904F8E3EA9B543F6545DA1F2D5432955613F0FCF62D49705242A9AF9E61E85DC0D651E40DFCF017B45575887";

			REQUIRE(ExpectedString == ActualString);

			// disabled test because it"s very expensive
			// ActualString  = DoTestVector("pleaseletmein", "SodiumChloride", 1048576,
			// 8, 1, 64);
			// ExpectedString  =
			// "2101CB9B6A511AAEADDBBE09CF70F881EC568D574A2FFD4DABE5EE9820ADAA478E56FD8F4BA5D09FFA1C6D927C40F4C337304049E8A952FBCBF45C6FA77A41A4";
			//
			// Assert.AreEqual(ExpectedString, ActualString, String.Format("Expected %s but got %s.",
			// [ExpectedString, ActualString]));
		}
	}
}