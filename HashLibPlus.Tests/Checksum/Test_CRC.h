#pragma once

#include "../Catch2-2.13.6/single_include/catch2/catch.hpp"

#include "../Base/TestConstants.h"

namespace ChecksumHashTests
{
	string IntToHex(const UInt64 value)
	{
		stringstream ss;
		ss << hex << value;
		return Converters::toUpper(ss.str());
	} // end function IntToHex

	string lstrip(const string& str, const char value)
	{
		UInt32 s_pos = 0;
		for (uint32_t i = 0; i < str.length(); i++, s_pos++)
		{
			if (str[i] != value) break;
		}// end if

		return str.substr(s_pos);
	} // end lstrip

	TEST_CASE("CRCTests")
	{
		SECTION("TestCheckValue")
		{
			for (UInt32 i = 0; i <= 100; i++)
			{
				ICRC crc = HashFactory::Checksum::CreateCRC(CRCStandard(i));

				string ExpectedString = lstrip(IntToHex(crc->GetCheckValue()), '0');

				string ActualString = lstrip(crc->ComputeBytes(OneToNineBytes)->ToString(), '0');

				REQUIRE(ExpectedString == ActualString);
			} // end for
		}

		SECTION("TestCheckValueWithIncrementalHash")
		{
			for (uint32_t i = 0; i <= 100; i++)
			{
				ICRC crc = HashFactory::Checksum::CreateCRC(CRCStandard(i));

				crc->Initialize();

				string ExpectedString = lstrip(IntToHex(crc->GetCheckValue()), '0');

				crc->TransformString(OneToNine.substr(0, 3));
				crc->TransformString(OneToNine.substr(3, 3));
				crc->TransformString(OneToNine.substr(6));

				IHashResult res = crc->TransformFinal();

				string ActualString = lstrip(res->ToString(), '0');

				REQUIRE(ExpectedString == ActualString);
			} // end for
		}

	};


}