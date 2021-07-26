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

#include "PBKDF2_HMACNotBuildIn.h"
#include "../Utils/BitConverter.h"
#include "../Utils/ArrayUtils.h"
#include "../Interfaces/IHashInfo.h"
#include "../Crypto/SHA2_256.h"

/// <summary>
/// Implementation of scrypt, a password-based key derivation function.
/// </summary>
/// <remarks>
/// Scrypt was created by Colin Percival and is specified in
/// <a href="http://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01">draft-josefsson-scrypt-kdf-01</a>.
/// </remarks>
class PBKDF_ScryptNotBuildInAdapter : public KDFNotBuildInAdapter, 
	public virtual IIPBKDF_ScryptNotBuildIn
{
private:
	HashLibByteArray _passwordBytes, _saltBytes;
	Int32 _cost, _blockSize, _parallelism;

public:
	static const char* InvalidByteCount;
	static const char* InvalidCost;
	static const char* BlockSizeAndCostIncompatible;
	static const char* BlockSizeTooSmall;
	static const char* InvalidParallelism;
	static const char* RoundsMustBeEven;

private:
	PBKDF_ScryptNotBuildInAdapter() { } // end cctr

public:
	PBKDF_ScryptNotBuildInAdapter(const HashLibByteArray a_PasswordBytes, const HashLibByteArray a_SaltBytes,
		const Int32 a_Cost, const Int32 a_BlockSize, const Int32 a_Parallelism)
	{
		ValidatePBKDF_ScryptInputs(a_Cost, a_BlockSize, a_Parallelism);

		_passwordBytes = a_PasswordBytes;

		_saltBytes = a_SaltBytes;

		_cost = a_Cost;
		_blockSize = a_BlockSize;
		_parallelism = a_Parallelism;
	} //

	~PBKDF_ScryptNotBuildInAdapter()
	{
		Clear();
	} //

	static void ValidatePBKDF_ScryptInputs(const Int32 a_Cost, const Int32 a_BlockSize,
		const Int32 a_Parallelism)
	{
		if (a_Cost <= 1 || !IsPowerOf2(a_Cost))
			throw ArgumentHashLibException(InvalidCost);

		// Only value of ABlockSize that cost (as an Int32) could be exceeded for is 1
		if ((a_BlockSize == 1) && (a_Cost >= 65536))
			throw ArgumentHashLibException(BlockSizeAndCostIncompatible);

		if (a_BlockSize < 1)
			throw ArgumentHashLibException(BlockSizeTooSmall);

		Int32 maxParallel = INT32_MAX / (128 * a_BlockSize * 8);

		if (a_Parallelism < 1 || a_Parallelism > maxParallel)
			throw ArgumentHashLibException(
				Utils::string_format(InvalidParallelism, maxParallel, a_BlockSize));
	} //

	virtual void Clear() 
	{
		ArrayUtils::zeroFill(_passwordBytes);
		ArrayUtils::zeroFill(_saltBytes);
	} // end function Clear

	virtual string GetName() const
	{
		return "PBKDF_ScryptNotBuildIn";
	}

	virtual IKDFNotBuildIn Clone() const
	{
		PBKDF_ScryptNotBuildInAdapter hash = PBKDF_ScryptNotBuildInAdapter();
		hash._passwordBytes = _passwordBytes;
		hash._saltBytes = _saltBytes;
		hash._cost = _cost;
		hash._blockSize = _blockSize;
		hash._parallelism = _parallelism;

		return make_shared<PBKDF_ScryptNotBuildInAdapter>(hash);
	} // end function Clone

	/// <summary>
	/// Returns the pseudo-random bytes for this object.
	/// </summary>
	/// <param name="bc">The number of pseudo-random key bytes to generate.</param>
	/// <returns>A byte array filled with pseudo-random key bytes.</returns>
	/// /// <exception cref="ArgumentOutOfRangeHashLibException">AByteCount must be greater than zero.</exception>
	virtual HashLibByteArray GetBytes(const Int32 bc) 
	{
		if (bc <= 0)
			throw ArgumentHashLibException(InvalidByteCount);

		return MFCrypt(_passwordBytes, _saltBytes, _cost, _blockSize, _parallelism, bc);
	} // end function GetBytes

private:
	static void ClearArray(HashLibByteArray& a_Input)
	{
		ArrayUtils::zeroFill(a_Input);
	} //

	static void ClearArray(HashLibUInt32Array& a_Input)
	{
		ArrayUtils::zeroFill(a_Input);
	} //

	static void ClearAllArrays(HashLibMatrixUInt32Array& a_Inputs)
	{
		for (Int32 i = 0; i < (Int32)a_Inputs.size(); i++)
		{
			ClearArray(a_Inputs[i]);
		} //
	} //

	static bool IsPowerOf2(const Int32 x)
	{
		return x > 0 && (x & (x - 1)) == 0;
	} //

	static HashLibByteArray SingleIterationPBKDF2(const HashLibByteArray& a_PasswordBytes,
		const HashLibByteArray& a_SaltBytes, const Int32 a_OutputLength)
	{
		PBKDF2_HMACNotBuildInAdapter pbkdf = PBKDF2_HMACNotBuildInAdapter(make_shared<SHA2_256>(), a_PasswordBytes,
			a_SaltBytes, 1);
		HashLibByteArray result = pbkdf.GetBytes(a_OutputLength);
		return result;
	} //

	/// <summary>
	/// Rotate left
	/// </summary>
	/// <param name="a_Value">
	/// value to rotate
	/// </param>
	/// <param name="a_Distance">
	/// distance to rotate AValue
	/// </param>
	/// <returns>
	/// rotated AValue
	/// </returns>
	static UInt32 RotateLeft32(const UInt32 a_Value, const Int32 a_Distance)
	{
		return Bits::RotateLeft32(a_Value, a_Distance);
	} //

	/// <summary>
	/// lifted from <c>ClpSalsa20Engine.pas</c> in CryptoLib4Pascal with
	/// minor modifications.
	/// </summary>
	static void SalsaCore(const Int32 a_Rounds, const HashLibUInt32Array& a_Input, HashLibUInt32Array& x)
	{
		UInt32 x00, x01, x02, x03, x04, x05, x06, x07, x08, x09, x10, x11, x12, x13, x14, x15;
		Int32 i;

		if (a_Input.size() != 16)
			throw ArgumentHashLibException("");

		if (x.size() != 16)
			throw ArgumentHashLibException("");

		if (a_Rounds % 2 != 0)
			throw ArgumentHashLibException(RoundsMustBeEven);

		x00 = a_Input[0];
		x01 = a_Input[1];
		x02 = a_Input[2];
		x03 = a_Input[3];
		x04 = a_Input[4];
		x05 = a_Input[5];
		x06 = a_Input[6];
		x07 = a_Input[7];
		x08 = a_Input[8];
		x09 = a_Input[9];
		x10 = a_Input[10];
		x11 = a_Input[11];
		x12 = a_Input[12];
		x13 = a_Input[13];
		x14 = a_Input[14];
		x15 = a_Input[15];

		i = a_Rounds;
		while (i > 0)
		{
			x04 = x04 ^ (RotateLeft32((x00 + x12), 7));
			x08 = x08 ^ (RotateLeft32((x04 + x00), 9));
			x12 = x12 ^ (RotateLeft32((x08 + x04), 13));
			x00 = x00 ^ (RotateLeft32((x12 + x08), 18));
			x09 = x09 ^ (RotateLeft32((x05 + x01), 7));
			x13 = x13 ^ (RotateLeft32((x09 + x05), 9));
			x01 = x01 ^ (RotateLeft32((x13 + x09), 13));
			x05 = x05 ^ (RotateLeft32((x01 + x13), 18));
			x14 = x14 ^ (RotateLeft32((x10 + x06), 7));
			x02 = x02 ^ (RotateLeft32((x14 + x10), 9));
			x06 = x06 ^ (RotateLeft32((x02 + x14), 13));
			x10 = x10 ^ (RotateLeft32((x06 + x02), 18));
			x03 = x03 ^ (RotateLeft32((x15 + x11), 7));
			x07 = x07 ^ (RotateLeft32((x03 + x15), 9));
			x11 = x11 ^ (RotateLeft32((x07 + x03), 13));
			x15 = x15 ^ (RotateLeft32((x11 + x07), 18));

			x01 = x01 ^ (RotateLeft32((x00 + x03), 7));
			x02 = x02 ^ (RotateLeft32((x01 + x00), 9));
			x03 = x03 ^ (RotateLeft32((x02 + x01), 13));
			x00 = x00 ^ (RotateLeft32((x03 + x02), 18));
			x06 = x06 ^ (RotateLeft32((x05 + x04), 7));
			x07 = x07 ^ (RotateLeft32((x06 + x05), 9));
			x04 = x04 ^ (RotateLeft32((x07 + x06), 13));
			x05 = x05 ^ (RotateLeft32((x04 + x07), 18));
			x11 = x11 ^ (RotateLeft32((x10 + x09), 7));
			x08 = x08 ^ (RotateLeft32((x11 + x10), 9));
			x09 = x09 ^ (RotateLeft32((x08 + x11), 13));
			x10 = x10 ^ (RotateLeft32((x09 + x08), 18));
			x12 = x12 ^ (RotateLeft32((x15 + x14), 7));
			x13 = x13 ^ (RotateLeft32((x12 + x15), 9));
			x14 = x14 ^ (RotateLeft32((x13 + x12), 13));
			x15 = x15 ^ (RotateLeft32((x14 + x13), 18));

			i -= 2;
		} //

		x[0] = x00 + a_Input[0];
		x[1] = x01 + a_Input[1];
		x[2] = x02 + a_Input[2];
		x[3] = x03 + a_Input[3];
		x[4] = x04 + a_Input[4];
		x[5] = x05 + a_Input[5];
		x[6] = x06 + a_Input[6];
		x[7] = x07 + a_Input[7];
		x[8] = x08 + a_Input[8];
		x[9] = x09 + a_Input[9];
		x[10] = x10 + a_Input[10];
		x[11] = x11 + a_Input[11];
		x[12] = x12 + a_Input[12];
		x[13] = x13 + a_Input[13];
		x[14] = x14 + a_Input[14];
		x[15] = x15 + a_Input[15];
	} //

	static void Xor(const HashLibUInt32Array& a, const HashLibUInt32Array& b, 
		const Int32 bOffset, HashLibUInt32Array& a_Output)
	{
		Int32 i = (Int32)a_Output.size() - 1;
		while (i >= 0)
		{
			a_Output[i] = a[i] ^ b[(size_t)bOffset + i];
			i--;
		} //
	} //

	static void SMix(HashLibUInt32Array& block, const Int32 blockOffset, const Int32 cost, const Int32 blockSize)
	{
		Int32 blockCount = blockSize * 32;
		HashLibUInt32Array blockX1(16);
		HashLibUInt32Array blockX2(16);
		HashLibUInt32Array blockY(blockCount);

		HashLibUInt32Array x(blockCount);
		HashLibUInt32Array v(cost * blockCount);

		try
		{
			Int32 idx;

			memmove(&x[0], &block[blockOffset], blockCount * sizeof(UInt32));

			Int32 offset = 0;
			idx = 0;
			while (idx < cost)
			{
				memmove(&v[offset], &x[0], blockCount * sizeof(UInt32));
				
				offset += blockCount;
				BlockMix(x, blockX1, blockX2, blockY, blockSize);

				memmove(&v[offset], &blockY[0], blockCount * sizeof(UInt32));
				
				offset += blockCount;
				BlockMix(blockY, blockX1, blockX2, x, blockSize);
				idx += 2;
			} //			

			UInt32 mask = (UInt32)cost - 1;
			idx = 0;

			while (idx < cost)
			{
				Int32 jdx = (Int32)(x[blockCount - 16] & mask);
			
				memmove(&blockY[0], &v[jdx * blockCount], blockCount * sizeof(UInt32));
				
				Xor(blockY, x, 0, blockY);
				BlockMix(blockY, blockX1, blockX2, x, blockSize);
				idx++;
			} //

			memmove(&block[blockOffset], &x[0], blockCount * sizeof(UInt32));
			
		} //
		catch (exception&){}

		HashLibMatrixUInt32Array temp = HashLibMatrixUInt32Array({ x, blockX1, blockX2, blockY });
		ClearArray(v);
		ClearAllArrays(temp);
	
	} //

	static void BlockMix(const HashLibUInt32Array& b, HashLibUInt32Array& X1, 
		HashLibUInt32Array& X2, HashLibUInt32Array& y, const Int32 R)
	{
		Int32 bOff, yOff, HalfLen, Idx;

		memmove(&X1[0], &b[(Int32)b.size() - 16], 16 * sizeof(UInt32));

		bOff = 0;
		yOff = 0;
		HalfLen = (Int32)b.size() / 2;

		Idx = 2 * R;
		while (Idx > 0)
		{
			Xor(X1, b, bOff, X2);

			SalsaCore(8, X2, X1);

			memmove(&y[yOff], &X1[0], 16 * sizeof(UInt32));

			yOff = HalfLen + bOff - yOff;
			bOff = bOff + 16;

			Idx--;
		} //
	} //

	static void DoSMix(HashLibUInt32Array& b, const Int32 a_Parallelism, const Int32 a_Cost,
		const Int32 a_BlockSize)
	{
		for (Int32 LIdx = 0; LIdx < a_Parallelism; LIdx++)
			SMix(b, LIdx * 32 * a_BlockSize, a_Cost, a_BlockSize);
	} //

	static HashLibByteArray MFCrypt(const HashLibByteArray& a_PasswordBytes, const HashLibByteArray& a_SaltBytes, 
		const Int32 a_Cost, const Int32 a_BlockSize, const Int32 a_Parallelism, const Int32 a_OutputLength)
	{
		Int32 LMFLenBytes, LBLen;
		HashLibByteArray LBytes, result;
		HashLibUInt32Array Lb;

		LMFLenBytes = a_BlockSize * 128;
		LBytes = SingleIterationPBKDF2(a_PasswordBytes, a_SaltBytes,
			a_Parallelism * LMFLenBytes);

		try
		{
			LBLen = (Int32)LBytes.size() / 4;
			Lb.resize(LBLen);

			Converters::le32_copy(&LBytes[0], 0, &Lb[0], 0, (Int32)LBytes.size() * sizeof(byte));

			DoSMix(Lb, a_Parallelism, a_Cost, a_BlockSize);

			Converters::le32_copy(&Lb[0], 0, &LBytes[0], 0, (Int32)Lb.size() * sizeof(UInt32));

			result = SingleIterationPBKDF2(a_PasswordBytes, LBytes, a_OutputLength);
		}
		catch (exception&) {}
		
		ClearArray(Lb);
		ClearArray(LBytes);		

		return result;
	} //

}; // end class PBKDF_ScryptNotBuildInAdapter

const char* PBKDF_ScryptNotBuildInAdapter::InvalidByteCount = "\"(ByteCount)\" argument must be a value greater than zero.";
const char* PBKDF_ScryptNotBuildInAdapter::InvalidCost = "Cost parameter must be > 1 and a power of 2.";
const char* PBKDF_ScryptNotBuildInAdapter::BlockSizeAndCostIncompatible = "Cost parameter must be > 1 and < 65536.";
const char* PBKDF_ScryptNotBuildInAdapter::BlockSizeTooSmall = "Block size must be >= 1.";
const char* PBKDF_ScryptNotBuildInAdapter::InvalidParallelism = "Parallelism parameter must be >= 1 and <= %u (based on block size of %u)";
const char* PBKDF_ScryptNotBuildInAdapter::RoundsMustBeEven = "Number of rounds must be even";