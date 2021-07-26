#pragma once

#include "../Catch2-2.13.6/single_include/catch2/catch.hpp"

#include "../Base/TestConstants.h"

void HashTestOthers(Argon2ParametersBuilder& a_Argon2ParametersBuilder,
	const Argon2Version& a_Version, const Int32 a_Iterations, const Int32 a_Memory,
	const Int32 a_Parallelism, const string& a_Password, const string& a_Salt, 
	const string& a_ExpectedString, const Int32 a_OutputLength)
{
	IPBKDF_Argon2NotBuildIn generator;
	string actual_string;
	HashLibByteArray salt, password;
	IArgon2Parameters argon2Parameter;

	salt = Converters::ConvertStringToBytes(a_Salt);
	password = Converters::ConvertStringToBytes(a_Password);

	a_Argon2ParametersBuilder.WithVersion(a_Version)
		.WithIterations(a_Iterations)
		.WithMemoryPowOfTwo(a_Memory)
		.WithParallelism(a_Parallelism)
		.WithSalt(salt);

	//
	// Set the password.
	//
	argon2Parameter = a_Argon2ParametersBuilder.Build();
	a_Argon2ParametersBuilder.Clear();

	generator = HashFactory::KDF::CreatePBKDF_Argon2(password, argon2Parameter);

	actual_string = Converters::ConvertBytesToHexString(generator->GetBytes(a_OutputLength), false);

	argon2Parameter->Clear();
	generator->Clear();

	REQUIRE(a_ExpectedString == actual_string);
} // 

void HashTestFromInternetDraft(Argon2ParametersBuilder& a_Argon2ParametersBuilder,
	const Argon2Version& a_Version, const Int32 a_Iterations, const Int32 a_MemoryAsKB, 
	const Int32 a_Parallelism, const string& a_Additional, const string& a_Secret, 
	const string& a_Salt, const string& a_Password, const string& a_ExpectedString,
	const Int32 a_OutputLength)
{
	IPBKDF_Argon2NotBuildIn generator;
	string actual_string;
	HashLibByteArray additional, secret, salt, password;
	IArgon2Parameters argon2Parameter;

	additional = Converters::ConvertHexStringToBytes(a_Additional);
	secret = Converters::ConvertHexStringToBytes(a_Secret);
	salt = Converters::ConvertHexStringToBytes(a_Salt);
	password = Converters::ConvertHexStringToBytes(a_Password);

	a_Argon2ParametersBuilder.WithVersion(a_Version)
		.WithIterations(a_Iterations)
		.WithMemoryAsKiB(a_MemoryAsKB)
		.WithParallelism(a_Parallelism)
		.WithAdditional(additional)
		.WithSecret(secret)
		.WithSalt(salt);

	//
	// Set the password.
	//
	argon2Parameter = a_Argon2ParametersBuilder.Build();
	a_Argon2ParametersBuilder.Clear();

	generator = HashFactory::KDF::CreatePBKDF_Argon2(password, argon2Parameter);

	actual_string = Converters::ConvertBytesToHexString(generator->GetBytes(a_OutputLength), false);

	argon2Parameter->Clear();
	generator->Clear();

	REQUIRE(a_ExpectedString == actual_string);
} // 

namespace KDFTests
{
	TEST_CASE("PBKDF_Argon2TestVectors")
	{
		string ActualString, ExpectedString;

		const Int32 ByteCount = 32, DEFAULT_OUTPUTLEN = 32;

		HashLibByteArray password = Converters::ConvertStringToBytes("password");
		HashLibByteArray differentpassword = Converters::ConvertStringToBytes("differentpassword");

		HashLibByteArray salt = Converters::ConvertStringToBytes("salt");
		HashLibByteArray diffsalt = Converters::ConvertStringToBytes("diffsalt");
		HashLibByteArray somesalt = Converters::ConvertStringToBytes("somesalt");

		HashLibByteArray Password = GenerateRepeatingBytes(0x1, 32);
		HashLibByteArray Salt = GenerateRepeatingBytes(0x2, 16);
		HashLibByteArray Secret = GenerateRepeatingBytes(0x3, 8);
		HashLibByteArray Additional = GenerateRepeatingBytes(0x4, 12);

		Argon2ParametersBuilder Builder = Argon2ParametersBuilder()
			.WithIterations(2)
			.WithMemoryAsKiB(32)
			.WithParallelism(4)
			.WithAdditional(Additional)
			.WithSecret(Secret)
			.WithSalt(Salt);

		IKDFNotBuildIn KdfInstance =
			HashFactory::KDF::CreatePBKDF_Argon2(password,
				Argon2ParametersBuilder().Build());

		SECTION("TestVectorsFromInternetDraftAnotherMethod")
		{
			string LAdditional, LSecret, LSalt, LPassword;
			Argon2ParametersBuilder argon2ParametersBuilder;
			Argon2Version Argon2Version;
			Int32 DEFAULT_OUTPUTLEN = 32;

			LAdditional = "040404040404040404040404";
			LSecret = "0303030303030303";
			LSalt = "02020202020202020202020202020202";
			LPassword = "0101010101010101010101010101010101010101010101010101010101010101";

			Argon2Version = Argon2Version::Nineteen;
			
			argon2ParametersBuilder = Argon2dParametersBuilder();

			HashTestFromInternetDraft(argon2ParametersBuilder, Argon2Version, 3, 32, 4,
				LAdditional, LSecret, LSalt, LPassword,
				"512B391B6F1162975371D30919734294F868E3BE3984F3C1A13A4DB9FABE4ACB",
				DEFAULT_OUTPUTLEN);

			argon2ParametersBuilder = Argon2iParametersBuilder();

			HashTestFromInternetDraft(argon2ParametersBuilder, Argon2Version, 3, 32, 4,
				LAdditional, LSecret, LSalt, LPassword,
				"C814D9D1DC7F37AA13F0D77F2494BDA1C8DE6B016DD388D29952A4C4672B6CE8",
				DEFAULT_OUTPUTLEN);

			argon2ParametersBuilder = Argon2idParametersBuilder();

			HashTestFromInternetDraft(argon2ParametersBuilder, Argon2Version, 3, 32, 4,
				LAdditional, LSecret, LSalt, LPassword,
				"0D640DF58D78766C08C037A34A8B53C9D01EF0452D75B65EB52520E96B01E659",
				DEFAULT_OUTPUTLEN);

		} //

		SECTION("TestOthers")
		{
			Argon2ParametersBuilder Argon2ParametersBuilder;
			Argon2Version Argon2Version;

			Argon2Version = Argon2Version::Sixteen;

			Argon2ParametersBuilder = Argon2iParametersBuilder();

			// Multiple test cases for various input values
			HashTestOthers(Argon2ParametersBuilder, Argon2Version, 2, 16, 1, "password",
				"somesalt",
				"F6C4DB4A54E2A370627AFF3DB6176B94A2A209A62C8E36152711802F7B30C694",
				DEFAULT_OUTPUTLEN);

			HashTestOthers(Argon2ParametersBuilder, Argon2Version, 2, 20, 1, "password",
				"somesalt",
				"9690EC55D28D3ED32562F2E73EA62B02B018757643A2AE6E79528459DE8106E9",
				DEFAULT_OUTPUTLEN);

			HashTestOthers(Argon2ParametersBuilder, Argon2Version, 2, 18, 1, "password",
				"somesalt",
				"3E689AAA3D28A77CF2BC72A51AC53166761751182F1EE292E3F677A7DA4C2467",
				DEFAULT_OUTPUTLEN);

			HashTestOthers(Argon2ParametersBuilder, Argon2Version, 2, 8, 1, "password",
				"somesalt",
				"FD4DD83D762C49BDEAF57C47BDCD0C2F1BABF863FDEB490DF63EDE9975FCCF06",
				DEFAULT_OUTPUTLEN);
			HashTestOthers(Argon2ParametersBuilder, Argon2Version, 2, 8, 2, "password",
				"somesalt",
				"B6C11560A6A9D61EAC706B79A2F97D68B4463AA3AD87E00C07E2B01E90C564FB",
				DEFAULT_OUTPUTLEN);
			HashTestOthers(Argon2ParametersBuilder, Argon2Version, 1, 16, 1, "password",
				"somesalt",
				"81630552B8F3B1F48CDB1992C4C678643D490B2B5EB4FF6C4B3438B5621724B2",
				DEFAULT_OUTPUTLEN);
			HashTestOthers(Argon2ParametersBuilder, Argon2Version, 4, 16, 1, "password",
				"somesalt",
				"F212F01615E6EB5D74734DC3EF40ADE2D51D052468D8C69440A3A1F2C1C2847B",
				DEFAULT_OUTPUTLEN);
			HashTestOthers(Argon2ParametersBuilder, Argon2Version, 2, 16, 1,
				"differentpassword", "somesalt",
				"E9C902074B6754531A3A0BE519E5BAF404B30CE69B3F01AC3BF21229960109A3",
				DEFAULT_OUTPUTLEN);
			HashTestOthers(Argon2ParametersBuilder, Argon2Version, 2, 16, 1, "password",
				"diffsalt",
				"79A103B90FE8AEF8570CB31FC8B22259778916F8336B7BDAC3892569D4F1C497",
				DEFAULT_OUTPUTLEN);

			HashTestOthers(Argon2ParametersBuilder, Argon2Version, 2, 16, 1, "password",
				"diffsalt",
				"1A097A5D1C80E579583F6E19C7E4763CCB7C522CA85B7D58143738E12CA39F8E6E42734C950FF2463675B97C37BA"
				"39FEBA4A9CD9CC5B4C798F2AAF70EB4BD044C8D148DECB569870DBD923430B82A083F284BEAE777812CCE18CDAC68EE8CCEF"
				"C6EC9789F30A6B5A034591F51AF830F4", 112);

			Argon2Version = Argon2Version::Nineteen;
			Argon2ParametersBuilder = Argon2iParametersBuilder();

			// Multiple test cases for various input values
			HashTestOthers(Argon2ParametersBuilder, Argon2Version, 2, 16, 1, "password",
				"somesalt",
				"C1628832147D9720C5BD1CFD61367078729F6DFB6F8FEA9FF98158E0D7816ED0",
				DEFAULT_OUTPUTLEN);

			HashTestOthers(Argon2ParametersBuilder, Argon2Version, 2, 20, 1, "password",
				"somesalt",
				"D1587ACA0922C3B5D6A83EDAB31BEE3C4EBAEF342ED6127A55D19B2351AD1F41",
				DEFAULT_OUTPUTLEN);

			HashTestOthers(Argon2ParametersBuilder, Argon2Version, 2, 18, 1, "password",
				"somesalt",
				"296DBAE80B807CDCEAAD44AE741B506F14DB0959267B183B118F9B24229BC7CB",
				DEFAULT_OUTPUTLEN);

			HashTestOthers(Argon2ParametersBuilder, Argon2Version, 2, 8, 1, "password",
				"somesalt",
				"89E9029F4637B295BEB027056A7336C414FADD43F6B208645281CB214A56452F",
				DEFAULT_OUTPUTLEN);

			HashTestOthers(Argon2ParametersBuilder, Argon2Version, 2, 8, 2, "password",
				"somesalt",
				"4FF5CE2769A1D7F4C8A491DF09D41A9FBE90E5EB02155A13E4C01E20CD4EAB61",
				DEFAULT_OUTPUTLEN);
			HashTestOthers(Argon2ParametersBuilder, Argon2Version, 1, 16, 1, "password",
				"somesalt",
				"D168075C4D985E13EBEAE560CF8B94C3B5D8A16C51916B6F4AC2DA3AC11BBECF",
				DEFAULT_OUTPUTLEN);
			HashTestOthers(Argon2ParametersBuilder, Argon2Version, 4, 16, 1, "password",
				"somesalt",
				"AAA953D58AF3706CE3DF1AEFD4A64A84E31D7F54175231F1285259F88174CE5B",
				DEFAULT_OUTPUTLEN);
			HashTestOthers(Argon2ParametersBuilder, Argon2Version, 2, 16, 1,
				"differentpassword", "somesalt",
				"14AE8DA01AFEA8700C2358DCEF7C5358D9021282BD88663A4562F59FB74D22EE",
				DEFAULT_OUTPUTLEN);
			HashTestOthers(Argon2ParametersBuilder, Argon2Version, 2, 16, 1, "password",
				"diffsalt",
				"B0357CCCFBEF91F3860B0DBA447B2348CBEFECADAF990ABFE9CC40726C521271",
				DEFAULT_OUTPUTLEN);
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
