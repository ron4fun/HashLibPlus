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

#include "KDFNotBuildIn.h"
#include "..//MAC/HMACNotBuildInAdapter.h"
#include "../Utils/BitConverter.h"
#include "../Interfaces/IHashInfo.h"
#include "../Utils/ArrayUtils.h"

class PBKDF2_HMACNotBuildInAdapter : public KDFNotBuildInAdapter, 
	public virtual IIPBKDF2_HMACNotBuildIn
{
public:
	PBKDF2_HMACNotBuildInAdapter(const IHash _hash, const HashLibByteArray &a_password,
		const HashLibByteArray &a_salt, const UInt32 a_iterations)
	{
		if (!_hash) throw ArgumentNullHashLibException("hash is null");
		if (a_iterations <= 0) throw ArgumentOutOfRangeHashLibException(IterationTooSmall);

		_hmac = HMACNotBuildInAdapter::CreateHMAC(_hash, a_password);

		_password = a_password;
		_salt = a_salt;
		_iterationCount = a_iterations;

		_blockSize = _hmac->GetHashSize();

		_buffer.resize(_blockSize);

		Initialize();
	} // end constructor

	~PBKDF2_HMACNotBuildInAdapter()
	{
		Clear();
	} // end destructor

	virtual HashLibByteArray GetBytes(const Int32 bc)
	{
		Int32 LOffset, LSize, LRemainder;

		if (bc <= 0)
			throw ArgumentOutOfRangeHashLibException(InvalidByteCount);

		HashLibByteArray LKey = HashLibByteArray(bc);

		LOffset = 0;
		LSize = _endIndex - _startIndex;
		if (LSize > 0)
		{
			if (bc >= LSize)
			{
				memmove(&LKey[0], &_buffer[_startIndex], LSize);
				_startIndex = 0;
				_endIndex = 0;
				LOffset = LOffset + LSize;
			} // end if
			else
			{
				memmove(&LKey[0], &_buffer[_startIndex], bc);
				_startIndex = _startIndex + bc;
				Initialize();
				return LKey;
			} // end else
		} // end if

		if (_startIndex != 0 && _endIndex != 0)
			throw ArgumentOutOfRangeHashLibException(InvalidIndex);

		while (LOffset < bc)
		{
			HashLibByteArray LT_block = Func();
			LRemainder = bc - LOffset;
			if (LRemainder > _blockSize)
			{
				memmove(&LKey[LOffset], &LT_block[0], _blockSize);
				LOffset = LOffset + _blockSize;
			} // end if
			else
			{
				if (LRemainder > 0) memmove(&LKey[LOffset], &LT_block[0], LRemainder);

				Int32 remCount = _blockSize - LRemainder;

				if (remCount > 0) memmove(&_buffer[_startIndex], &LT_block[LRemainder], remCount);

				_endIndex = _endIndex + remCount;
				Initialize();
				return LKey;
			} // end else
		} // end while

		Initialize();
		return LKey;
	} // end function GetBytes

	virtual void Clear()
	{
		ArrayUtils::zeroFill(_password);
		ArrayUtils::zeroFill(_salt);
	}

	virtual string GetName() const
	{
		return Utils::string_format("PBKDF2_HMACNotBuildIn(%s)", _hmac->GetName().c_str());
	}

	virtual IKDFNotBuildIn Clone() const
	{
		PBKDF2_HMACNotBuildInAdapter hmac = PBKDF2_HMACNotBuildInAdapter();
		hmac._hmac = ::move(_hmac);
		hmac._password = _password;
		hmac._salt = _salt;
		hmac._buffer = _buffer;
		hmac._iterationCount = _iterationCount;
		hmac._block = _block;
		hmac._blockSize = _blockSize;
		hmac._startIndex = _startIndex;
		hmac._endIndex = _endIndex;

		return make_shared<PBKDF2_HMACNotBuildInAdapter>(hmac);
	}

private:
	// initializes the _state of the operation.
	void Initialize()
	{
		memset(&_buffer[0], 0, _buffer.size() * sizeof(byte));
		_block = 1;
		_startIndex = 0;
		_endIndex = 0;
	} // end function Initialize

	// iterative _hash function
	HashLibByteArray Func()
	{
		HashLibByteArray INT_block = GetBigEndianBytes(_block);
		_hmac->Initialize();

		_hmac->TransformBytes(_salt, 0, (Int32)_salt.size());
		_hmac->TransformBytes(INT_block, 0, (Int32)INT_block.size());

		HashLibByteArray temp = _hmac->TransformFinal()->GetBytes();
		HashLibByteArray ret = temp;

		UInt32 i = 2;
		Int32 j = 0;
		while (i <= _iterationCount)
		{
			temp = _hmac->ComputeBytes(temp)->GetBytes();
			j = 0;
			while (j < _blockSize)
			{
				ret[j] = ret[j] ^ temp[j];
				j++;
			} // end while
			i++;
		} // end while

		_block++;

		return ret;
	} // end function Func

	/// <summary>
	/// Encodes an integer into a 4-byte array, in big endian.
	/// </summary>
	/// <param name="i">The integer to encode.</param>
	/// <returns>array of bytes, in big endian.</returns>
	inline static HashLibByteArray GetBigEndianBytes(const UInt32 i)
	{
		HashLibByteArray result = HashLibByteArray(sizeof(UInt32));
		Converters::ReadUInt32AsBytesBE(i, result, 0);
		return result;
	} // end function GetBigEndianBytes

protected:
	PBKDF2_HMACNotBuildInAdapter() {}

	IHMACNotBuildIn _hmac = nullptr;
	HashLibByteArray _password, _salt, _buffer;
	UInt32 _iterationCount = 0, _block = 0;
	Int32 _blockSize = 0, _startIndex = 0, _endIndex = 0;

public:
	static const char *InvalidByteCount;
	static const char *InvalidIndex;
	static const char *IterationTooSmall;

}; // end class PBKDF2_HMACNotBuildInAdapter

const char* PBKDF2_HMACNotBuildInAdapter::InvalidByteCount = "\"(ByteCount)\" argument must be a value greater than zero.";
const char* PBKDF2_HMACNotBuildInAdapter::InvalidIndex = "Invalid start or end index in the internal buffer.";
const char* PBKDF2_HMACNotBuildInAdapter::IterationTooSmall = "Iteration must be greater than zero.";
