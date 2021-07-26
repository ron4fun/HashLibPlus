///////////////////////////////////////////////////////////////////////
/// SharpHash Library
/// Copyright(c) 2021 Mbadiwe Nnaemeka Ronald
/// Github Repository <https://github.com/ron4fun/HashLibPlus>
///
/// The contents of this file are subject to the
/// Mozilla Public License Version 2.0 (the "License");
/// you may not use this file except in
/// compliance with the License. You may obtain a copy of the License
/// at https://www.mozilla.org/en-US/MPL/2.0/
///
/// Software distributed under the License is distributed on an "AS IS"
/// basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
/// the License for the specific language governing rights and
/// limitations under the License.
///
/// Acknowledgements:
///
/// Thanks to Ugochukwu Mmaduekwe (https://github.com/Xor-el) for his creative
/// development of this library in Pascal/Delphi (https://github.com/Xor-el/HashLib4Pascal).
///
////////////////////////////////////////////////////////////////////////

#pragma once

#include <stdint.h>
#include <memory>
#include <utility>
#include <stdexcept>
#include <vector>
#include <string.h>

using namespace std;

#pragma region HashLibPlus Exceptions

class HashLibException : public runtime_error
{
public:
	HashLibException(const string& text)
		: runtime_error(text.c_str())
	{}  // end constructor

	HashLibException(const char * text)
		: runtime_error(text)
	{}  // end constructor
}; // end class HashLibException

class InvalidOperationHashLibException : public HashLibException
{
public:
	InvalidOperationHashLibException(const string& text)
		: HashLibException(text)
	{}

	InvalidOperationHashLibException(const char* text)
		: HashLibException(text)
	{}
}; // end class InvalidOperationHashLibException

class IndexOutOfRangeHashLibException : public HashLibException
{
public:
	IndexOutOfRangeHashLibException(const string& text)
		: HashLibException(text)
	{}

	IndexOutOfRangeHashLibException(const char* text)
		: HashLibException(text)
	{}
}; // end class IndexOutOfRangeHashLibException

class ArgumentInvalidHashLibException : public HashLibException
{
public:
	ArgumentInvalidHashLibException(const string& text)
		: HashLibException(text)
	{}

	ArgumentInvalidHashLibException(const char* text)
		: HashLibException(text)
	{}
}; // end class ArgumentInvalidHashLibException

class ArgumentHashLibException : public HashLibException
{
public:
	ArgumentHashLibException(const string& text)
		: HashLibException(text)
	{}

	ArgumentHashLibException(const char* text)
		: HashLibException(text)
	{}
}; // end class ArgumentHashLibException

class ArgumentNullHashLibException : HashLibException
{
public:
	ArgumentNullHashLibException(const string& text)
		: HashLibException(text)
	{}

	ArgumentNullHashLibException(const char* text)
		: HashLibException(text)
	{}
}; // end class ArgumentNullHashLibException

class ArgumentOutOfRangeHashLibException : public HashLibException
{
public:
	ArgumentOutOfRangeHashLibException(const string& text)
		: HashLibException(text)
	{}

	ArgumentOutOfRangeHashLibException(const char* text)
		: HashLibException(text)
	{}
}; // end class ArgumentOutOfRangeHashLibException

class NullReferenceHashLibException : public HashLibException
{
public:
	NullReferenceHashLibException(const string& text)
		: HashLibException(text)
	{}

	NullReferenceHashLibException(const char* text)
		: HashLibException(text)
	{}
}; // end class NullReferenceHashLibException

class UnsupportedTypeHashLibException : public HashLibException
{
public:
	UnsupportedTypeHashLibException(const string& text)
		: HashLibException(text)
	{}

	UnsupportedTypeHashLibException(const char* text)
		: HashLibException(text)
	{}
}; // end class UnsupportedTypeHashLibException

class NotImplementedHashLibException : public HashLibException
{
public:
	NotImplementedHashLibException(const string& text)
		: HashLibException(text)
	{}

	NotImplementedHashLibException(const char* text)
		: HashLibException(text)
	{}
}; // end class NotImplementedHashLibException

#pragma endregion


#pragma region Integer Types

/// <summary>
/// Represents a Byte.
/// </summary>
using byte = uint8_t;

/// <summary>
/// Represents an int16.
/// </summary>
using Int16 = int16_t;

/// <summary>
/// Represents an unsigned int16.
/// </summary>
using UInt16 = uint16_t;

/// <summary>
/// Represents an int32.
/// </summary>
using Int = int32_t;
using Int32 = int32_t;

/// <summary>
/// Represents an unsigned int32.
/// </summary>
using UInt32 = uint32_t;

/// <summary>
/// Represents an int64.
/// </summary>
using Int64 = int64_t;

/// <summary>
/// Represents an unsigned int64.
/// </summary>
using UInt64 = uint64_t;

#pragma endregion


#pragma region HashLibPlus Types

/// <summary>
/// Represents a dynamic array of Byte.
/// </summary>
using HashLibByteArray = vector<byte>;

/// <summary>
/// Represents a dynamic array of UInt32.
/// </summary>
using HashLibUInt32Array = vector<UInt32>;

/// <summary>
/// Represents a dynamic array of UInt64.
/// </summary>
using HashLibUInt64Array = vector<UInt64>;

/// <summary>
/// Represents a dynamic array of String.
/// </summary>
using HashLibStringArray = vector<string>;

using HashLibMatrixStringArray = vector<HashLibStringArray>;

/// <summary>
/// Represents a dynamic array of Char.
/// </summary>
using HashLibCharArray = vector<char>;

/// <summary>
/// Represents a dynamic array of array of UInt8.
/// </summary>
using HashLibMatrixByteArray = vector<HashLibByteArray>;

/// <summary>
/// Represents a dynamic array of array of UInt32.
/// </summary>
using HashLibMatrixUInt32Array = vector<HashLibUInt32Array>;

/// <summary>
/// Represents a dynamic array of array of UInt64.
/// </summary>
using HashLibMatrixUInt64Array = vector<HashLibUInt64Array>;

template<class T>
using HashLibGenericArray = vector<T>;

#pragma endregion


/// <summary>
/// Enum of all defined and implemented CRC standards.
/// </summary>
enum CRCStandard
{

	/// <summary>
	/// CRC standard named "CRC3_GSM".
	/// </summary>
	CRC3_GSM = 0,

	/// <summary>
	/// CRC standard named "CRC3_ROHC".
	/// </summary>
	CRC3_ROHC,

	/// <summary>
	/// CRC standard named "CRC4_INTERLAKEN".
	/// </summary>
	CRC4_INTERLAKEN,

	/// <summary>
	/// CRC standard named "CRC4_ITU".
	/// </summary>
	CRC4_ITU,

	/// <summary>
	/// CRC standard named "CRC5_EPC".
	/// </summary>
	CRC5_EPC,

	/// <summary>
	/// CRC standard named "CRC5_ITU".
	/// </summary>
	CRC5_ITU,

	/// <summary>
	/// CRC standard named "CRC5_USB".
	/// </summary>
	CRC5_USB,

	/// <summary>
	/// CRC standard named "CRC6_CDMA2000A".
	/// </summary>
	CRC6_CDMA2000A,

	/// <summary>
	/// CRC standard named "CRC6_CDMA2000B".
	/// </summary>
	CRC6_CDMA2000B,

	/// <summary>
	/// CRC standard named "CRC6_DARC".
	/// </summary>
	CRC6_DARC,

	/// <summary>
	/// CRC standard named "CRC6_GSM".
	/// </summary>
	CRC6_GSM,

	/// <summary>
	/// CRC standard named "CRC6_ITU".
	/// </summary>
	CRC6_ITU,

	/// <summary>
	/// CRC standard named "CRC7".
	/// </summary>
	CRC7,

	/// <summary>
	/// CRC standard named "CRC7_ROHC".
	/// </summary>
	CRC7_ROHC,

	/// <summary>
	/// CRC standard named "CRC7_UMTS".
	/// </summary>
	CRC7_UMTS,

	/// <summary>
	/// CRC standard named "CRC8".
	/// </summary>
	CRC8,

	/// <summary>
	/// CRC standard named "CRC8_AUTOSAR".
	/// </summary>
	CRC8_AUTOSAR,

	/// <summary>
	/// CRC standard named "CRC8_BLUETOOTH".
	/// </summary>
	CRC8_BLUETOOTH,

	/// <summary>
	/// CRC standard named "CRC8_CDMA2000".
	/// </summary>
	CRC8_CDMA2000,

	/// <summary>
	/// CRC standard named "CRC8_DARC".
	/// </summary>
	CRC8_DARC,

	/// <summary>
	/// CRC standard named "CRC8_DVBS2".
	/// </summary>
	CRC8_DVBS2,

	/// <summary>
	/// CRC standard named "CRC8_EBU".
	/// </summary>
	CRC8_EBU,

	/// <summary>
	/// CRC standard named "CRC8_GSMA".
	/// </summary>
	CRC8_GSMA,

	/// <summary>
	/// CRC standard named "CRC8_GSMB".
	/// </summary>
	CRC8_GSMB,

	/// <summary>
	/// CRC standard named "CRC8_ICODE".
	/// </summary>
	CRC8_ICODE,

	/// <summary>
	/// CRC standard named "CRC8_ITU".
	/// </summary>
	CRC8_ITU,

	/// <summary>
	/// CRC standard named "CRC8_LTE".
	/// </summary>
	CRC8_LTE,

	/// <summary>
	/// CRC standard named "CRC8_MAXIM".
	/// </summary>
	CRC8_MAXIM,

	/// <summary>
	/// CRC standard named "CRC8_OPENSAFETY".
	/// </summary>
	CRC8_OPENSAFETY,

	/// <summary>
	/// CRC standard named "CRC8_ROHC".
	/// </summary>
	CRC8_ROHC,

	/// <summary>
	/// CRC standard named "CRC8_SAEJ1850".
	/// </summary>
	CRC8_SAEJ1850,

	/// <summary>
	/// CRC standard named "CRC8_WCDMA".
	/// </summary>
	CRC8_WCDMA,

	/// <summary>
	/// CRC standard named "CRC10".
	/// </summary>
	CRC10,

	/// <summary>
	/// CRC standard named "CRC10_CDMA2000".
	/// </summary>
	CRC10_CDMA2000,

	/// <summary>
	/// CRC standard named "CRC10_GSM".
	/// </summary>
	CRC10_GSM,

	/// <summary>
	/// CRC standard named "CRC11".
	/// </summary>
	CRC11,

	/// <summary>
	/// CRC standard named "CRC11_UMTS".
	/// </summary>
	CRC11_UMTS,

	/// <summary>
	/// CRC standard named "CRC12_CDMA2000".
	/// </summary>
	CRC12_CDMA2000,

	/// <summary>
	/// CRC standard named "CRC12_DECT".
	/// </summary>
	CRC12_DECT,

	/// <summary>
	/// CRC standard named "CRC12_GSM".
	/// </summary>
	CRC12_GSM,

	/// <summary>
	/// CRC standard named "CRC12_UMTS".
	/// </summary>
	CRC12_UMTS,

	/// <summary>
	/// CRC standard named "CRC13_BBC".
	/// </summary>
	CRC13_BBC,

	/// <summary>
	/// CRC standard named "CRC14_DARC".
	/// </summary>
	CRC14_DARC,

	/// <summary>
	/// CRC standard named "CRC14_GSM".
	/// </summary>
	CRC14_GSM,

	/// <summary>
	/// CRC standard named "CRC15".
	/// </summary>
	CRC15,

	/// <summary>
	/// CRC standard named "CRC15_MPT1327".
	/// </summary>
	CRC15_MPT1327,

	/// <summary>
	/// CRC standard named "ARC".
	/// </summary>
	ARC,

	/// <summary>
	/// CRC standard named "CRC16_AUGCCITT".
	/// </summary>
	CRC16_AUGCCITT,

	/// <summary>
	/// CRC standard named "CRC16_BUYPASS".
	/// </summary>
	CRC16_BUYPASS,

	/// <summary>
	/// CRC standard named "CRC16_CCITTFALSE".
	/// </summary>
	CRC16_CCITTFALSE,

	/// <summary>
	/// CRC standard named "CRC16_CDMA2000".
	/// </summary>
	CRC16_CDMA2000,

	/// <summary>
	/// CRC standard named "CRC16_CMS".
	/// </summary>
	CRC16_CMS,

	/// <summary>
	/// CRC standard named "CRC16_DDS110".
	/// </summary>
	CRC16_DDS110,

	/// <summary>
	/// CRC standard named "CRC16_DECTR".
	/// </summary>
	CRC16_DECTR,

	/// <summary>
	/// CRC standard named "CRC16_DECTX".
	/// </summary>
	CRC16_DECTX,

	/// <summary>
	/// CRC standard named "CRC16_DNP".
	/// </summary>
	CRC16_DNP,

	/// <summary>
	/// CRC standard named "CRC16_EN13757".
	/// </summary>
	CRC16_EN13757,

	/// <summary>
	/// CRC standard named "CRC16_GENIBUS".
	/// </summary>
	CRC16_GENIBUS,

	/// <summary>
	/// CRC standard named "CRC16_GSM".
	/// </summary>
	CRC16_GSM,

	/// <summary>
	/// CRC standard named "CRC16_LJ1200".
	/// </summary>
	CRC16_LJ1200,

	/// <summary>
	/// CRC standard named "CRC16_MAXIM".
	/// </summary>
	CRC16_MAXIM,

	/// <summary>
	/// CRC standard named "CRC16_MCRF4XX".
	/// </summary>
	CRC16_MCRF4XX,

	/// <summary>
	/// CRC standard named "CRC16_OPENSAFETYA".
	/// </summary>
	CRC16_OPENSAFETYA,

	/// <summary>
	/// CRC standard named "CRC16_OPENSAFETYB".
	/// </summary>
	CRC16_OPENSAFETYB,

	/// <summary>
	/// CRC standard named "CRC16_PROFIBUS".
	/// </summary>
	CRC16_PROFIBUS,

	/// <summary>
	/// CRC standard named "CRC16_RIELLO".
	/// </summary>
	CRC16_RIELLO,

	/// <summary>
	/// CRC standard named "CRC16_T10DIF".
	/// </summary>
	CRC16_T10DIF,

	/// <summary>
	/// CRC standard named "CRC16_TELEDISK".
	/// </summary>
	CRC16_TELEDISK,

	/// <summary>
	/// CRC standard named "CRC16_TMS37157".
	/// </summary>
	CRC16_TMS37157,

	/// <summary>
	/// CRC standard named "CRC16_USB".
	/// </summary>
	CRC16_USB,

	/// <summary>
	/// CRC standard named "CRCA".
	/// </summary>
	CRCA,

	/// <summary>
	/// CRC standard named "KERMIT".
	/// </summary>
	KERMIT,

	/// <summary>
	/// CRC standard named "MODBUS".
	/// </summary>
	MODBUS,

	/// <summary>
	/// CRC standard named "X25".
	/// </summary>
	X25,

	/// <summary>
	/// CRC standard named "XMODEM".
	/// </summary>
	XMODEM,

	/// <summary>
	/// CRC standard named "CRC17_CANFD".
	/// </summary>
	CRC17_CANFD,

	/// <summary>
	/// CRC standard named "CRC21_CANFD".
	/// </summary>
	CRC21_CANFD,

	/// <summary>
	/// CRC standard named "CRC24".
	/// </summary>
	CRC24,

	/// <summary>
	/// CRC standard named "CRC24_BLE".
	/// </summary>
	CRC24_BLE,

	/// <summary>
	/// CRC standard named "CRC24_FLEXRAYA".
	/// </summary>
	CRC24_FLEXRAYA,

	/// <summary>
	/// CRC standard named "CRC24_FLEXRAYB".
	/// </summary>
	CRC24_FLEXRAYB,

	/// <summary>
	/// CRC standard named "CRC24_INTERLAKEN".
	/// </summary>
	CRC24_INTERLAKEN,

	/// <summary>
	/// CRC standard named "CRC24_LTEA".
	/// </summary>
	CRC24_LTEA,

	/// <summary>
	/// CRC standard named "CRC24_LTEB".
	/// </summary>
	CRC24_LTEB,

	/// <summary>
	/// CRC standard named "CRC30_CDMA".
	/// </summary>
	CRC30_CDMA,

	/// <summary>
	/// CRC standard named "CRC31_PHILIPS".
	/// </summary>
	CRC31_PHILIPS,

	/// <summary>
	/// CRC standard named "CRC32".
	/// </summary>
	CRC32,

	/// <summary>
	/// CRC standard named "CRC32_AUTOSAR".
	/// </summary>
	CRC32_AUTOSAR,

	/// <summary>
	/// CRC standard named "CRC32_BZIP2".
	/// </summary>
	CRC32_BZIP2,

	/// <summary>
	/// CRC standard named "CRC32C".
	/// </summary>
	CRC32C,

	/// <summary>
	/// CRC standard named "CRC32D".
	/// </summary>
	CRC32D,

	/// <summary>
	/// CRC standard named "CRC32_MPEG2".
	/// </summary>
	CRC32_MPEG2,

	/// <summary>
	/// CRC standard named "CRC32_POSIX".
	/// </summary>
	CRC32_POSIX,

	/// <summary>
	/// CRC standard named "CRC32Q".
	/// </summary>
	CRC32Q,

	/// <summary>
	/// CRC standard named "JAMCRC".
	/// </summary>
	JAMCRC,

	/// <summary>
	/// CRC standard named "XFER".
	/// </summary>
	XFER,

	/// <summary>
	/// CRC standard named "CRC40_GSM".
	/// </summary>
	CRC40_GSM,

	/// <summary>
	/// CRC standard named "CRC64".
	/// </summary>
	CRC64,

	/// <summary>
	/// CRC standard named "CRC64_GOISO".
	/// </summary>
	CRC64_GOISO,

	/// <summary>
	/// CRC standard named "CRC64_WE".
	/// </summary>
	CRC64_WE,

	/// <summary>
	/// CRC standard named "CRC64_XZ".
	/// </summary>
	CRC64_XZ
}; // end enum
