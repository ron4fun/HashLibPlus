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

#include "../Base/HashCryptoNotBuildIn.h"
#include "../Enum/HashSize.h"
#include "../Utils/Utils.h"

enum HashMode
{
	hmKeccak = 0x1,
	hmSHA3 = 0x6,
	hmShake = 0x1F,
	hmCShake = 0x04
}; // end enum HashMode

class SHA3 : public BlockHash, public virtual IICryptoNotBuildIn, public virtual IITransformBlock
{
public:
	virtual void Initialize()
	{
		ArrayUtils::zeroFill(_state);

		BlockHash::Initialize();
	} // end function Initialize

protected:
	SHA3(const Int32 a_hash_size)
		: BlockHash(a_hash_size, 200 - (a_hash_size * 2))
	{
		_state.resize(25);
	} // end constructor

	virtual string GetName() const
	{
		switch (GetHashMode())
		{
		case hmKeccak:
			return Utils::string_format("Keccak_%u", _hash_size * 8);

		case hmSHA3:
			return _name;

		case hmShake:
		case hmCShake:
			return Utils::string_format("%s_%s_%u", _name.c_str(), "XOFSizeInBytes", 
				dynamic_cast<const IIXOF*>(&(*this))->GetXOFSizeInBits() >> 3);
		default:
			throw ArgumentInvalidHashLibException(
				Utils::string_format(InvalidHashMode, "hmKeccak, hmSHA3, hmShake, hmCShake"));
		}
	}

	void KeccakF1600_StatePermute()
	{
		UInt64 Da, De, Di, Do, Du;
		UInt64 Aba, Abe, Abi, Abo, Abu, Aga, Age, Agi, Ago, Agu, Aka, Ake, Aki, Ako, Aku,
			Ama, Ame, Ami, Amo, Amu, Asa, Ase, Asi, Aso, Asu, BCa, BCe, BCi, BCo, BCu,
			Eba, Ebe, Ebi, Ebo, Ebu, Ega, Ege, Egi, Ego, Egu, Eka, Eke, Eki, Eko, Eku,
			Ema, Eme, Emi, Emo, Emu, Esa, Ese, Esi, Eso, Esu;
		Int32 LRound;

		Aba = _state[0];
		Abe = _state[1];
		Abi = _state[2];
		Abo = _state[3];
		Abu = _state[4];
		Aga = _state[5];
		Age = _state[6];
		Agi = _state[7];
		Ago = _state[8];
		Agu = _state[9];
		Aka = _state[10];
		Ake = _state[11];
		Aki = _state[12];
		Ako = _state[13];
		Aku = _state[14];
		Ama = _state[15];
		Ame = _state[16];
		Ami = _state[17];
		Amo = _state[18];
		Amu = _state[19];
		Asa = _state[20];
		Ase = _state[21];
		Asi = _state[22];
		Aso = _state[23];
		Asu = _state[24];

		LRound = 0;
		while (LRound < 24)
		{
			// prepareTheta
			BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
			BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
			BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
			BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
			BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

			// thetaRhoPiChiIotaPrepareTheta(LRound  , A, E)
			Da = BCu ^ Bits::RotateLeft64(BCe, 1);
			De = BCa ^ Bits::RotateLeft64(BCi, 1);
			Di = BCe ^ Bits::RotateLeft64(BCo, 1);
			Do = BCi ^ Bits::RotateLeft64(BCu, 1);
			Du = BCo ^ Bits::RotateLeft64(BCa, 1);

			Aba = Aba ^ Da;
			BCa = Aba;
			Age = Age ^ De;
			BCe = Bits::RotateLeft64(Age, 44);
			Aki = Aki ^ Di;
			BCi = Bits::RotateLeft64(Aki, 43);
			Amo = Amo ^ Do;
			BCo = Bits::RotateLeft64(Amo, 21);
			Asu = Asu ^ Du;
			BCu = Bits::RotateLeft64(Asu, 14);
			Eba = BCa ^ ((~BCe) & BCi);
			Eba = Eba ^ RC[LRound];
			Ebe = BCe ^ ((~BCi) & BCo);
			Ebi = BCi ^ ((~BCo) & BCu);
			Ebo = BCo ^ ((~BCu) & BCa);
			Ebu = BCu ^ ((~BCa) & BCe);

			Abo = Abo ^ Do;
			BCa = Bits::RotateLeft64(Abo, 28);
			Agu = Agu ^ Du;
			BCe = Bits::RotateLeft64(Agu, 20);
			Aka = Aka ^ Da;
			BCi = Bits::RotateLeft64(Aka, 3);
			Ame = Ame ^ De;
			BCo = Bits::RotateLeft64(Ame, 45);
			Asi = Asi ^ Di;
			BCu = Bits::RotateLeft64(Asi, 61);
			Ega = BCa ^ ((~BCe) & BCi);
			Ege = BCe ^ ((~BCi) & BCo);
			Egi = BCi ^ ((~BCo) & BCu);
			Ego = BCo ^ ((~BCu) & BCa);
			Egu = BCu ^ ((~BCa) & BCe);

			Abe = Abe ^ De;
			BCa = Bits::RotateLeft64(Abe, 1);
			Agi = Agi ^ Di;
			BCe = Bits::RotateLeft64(Agi, 6);
			Ako = Ako ^ Do;
			BCi = Bits::RotateLeft64(Ako, 25);
			Amu = Amu ^ Du;
			BCo = Bits::RotateLeft64(Amu, 8);
			Asa = Asa ^ Da;
			BCu = Bits::RotateLeft64(Asa, 18);
			Eka = BCa ^ ((~BCe) & BCi);
			Eke = BCe ^ ((~BCi) & BCo);
			Eki = BCi ^ ((~BCo) & BCu);
			Eko = BCo ^ ((~BCu) & BCa);
			Eku = BCu ^ ((~BCa) & BCe);

			Abu = Abu ^ Du;
			BCa = Bits::RotateLeft64(Abu, 27);
			Aga = Aga ^ Da;
			BCe = Bits::RotateLeft64(Aga, 36);
			Ake = Ake ^ De;
			BCi = Bits::RotateLeft64(Ake, 10);
			Ami = Ami ^ Di;
			BCo = Bits::RotateLeft64(Ami, 15);
			Aso = Aso ^ Do;
			BCu = Bits::RotateLeft64(Aso, 56);
			Ema = BCa ^ ((~BCe) & BCi);
			Eme = BCe ^ ((~BCi) & BCo);
			Emi = BCi ^ ((~BCo) & BCu);
			Emo = BCo ^ ((~BCu) & BCa);
			Emu = BCu ^ ((~BCa) & BCe);

			Abi = Abi ^ Di;
			BCa = Bits::RotateLeft64(Abi, 62);
			Ago = Ago ^ Do;
			BCe = Bits::RotateLeft64(Ago, 55);
			Aku = Aku ^ Du;
			BCi = Bits::RotateLeft64(Aku, 39);
			Ama = Ama ^ Da;
			BCo = Bits::RotateLeft64(Ama, 41);
			Ase = Ase ^ De;
			BCu = Bits::RotateLeft64(Ase, 2);
			Esa = BCa ^ ((~BCe) & BCi);
			Ese = BCe ^ ((~BCi) & BCo);
			Esi = BCi ^ ((~BCo) & BCu);
			Eso = BCo ^ ((~BCu) & BCa);
			Esu = BCu ^ ((~BCa) & BCe);

			// prepareTheta
			BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
			BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
			BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
			BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
			BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

			// thetaRhoPiChiIotaPrepareTheta(LRound+1, E, A)
			Da = BCu ^ Bits::RotateLeft64(BCe, 1);
			De = BCa ^ Bits::RotateLeft64(BCi, 1);
			Di = BCe ^ Bits::RotateLeft64(BCo, 1);
			Do = BCi ^ Bits::RotateLeft64(BCu, 1);
			Du = BCo ^ Bits::RotateLeft64(BCa, 1);

			Eba = Eba ^ Da;
			BCa = Eba;
			Ege = Ege ^ De;
			BCe = Bits::RotateLeft64(Ege, 44);
			Eki = Eki ^ Di;
			BCi = Bits::RotateLeft64(Eki, 43);
			Emo = Emo ^ Do;
			BCo = Bits::RotateLeft64(Emo, 21);
			Esu = Esu ^ Du;
			BCu = Bits::RotateLeft64(Esu, 14);
			Aba = BCa ^ ((~BCe) & BCi);
			Aba = Aba ^ RC[LRound + 1];
			Abe = BCe ^ ((~BCi) & BCo);
			Abi = BCi ^ ((~BCo) & BCu);
			Abo = BCo ^ ((~BCu) & BCa);
			Abu = BCu ^ ((~BCa) & BCe);

			Ebo = Ebo ^ Do;
			BCa = Bits::RotateLeft64(Ebo, 28);
			Egu = Egu ^ Du;
			BCe = Bits::RotateLeft64(Egu, 20);
			Eka = Eka ^ Da;
			BCi = Bits::RotateLeft64(Eka, 3);
			Eme = Eme ^ De;
			BCo = Bits::RotateLeft64(Eme, 45);
			Esi = Esi ^ Di;
			BCu = Bits::RotateLeft64(Esi, 61);
			Aga = BCa ^ ((~BCe) & BCi);
			Age = BCe ^ ((~BCi) & BCo);
			Agi = BCi ^ ((~BCo) & BCu);
			Ago = BCo ^ ((~BCu) & BCa);
			Agu = BCu ^ ((~BCa) & BCe);

			Ebe = Ebe ^ De;
			BCa = Bits::RotateLeft64(Ebe, 1);
			Egi = Egi ^ Di;
			BCe = Bits::RotateLeft64(Egi, 6);
			Eko = Eko ^ Do;
			BCi = Bits::RotateLeft64(Eko, 25);
			Emu = Emu ^ Du;
			BCo = Bits::RotateLeft64(Emu, 8);
			Esa = Esa ^ Da;
			BCu = Bits::RotateLeft64(Esa, 18);
			Aka = BCa ^ ((~BCe) & BCi);
			Ake = BCe ^ ((~BCi) & BCo);
			Aki = BCi ^ ((~BCo) & BCu);
			Ako = BCo ^ ((~BCu) & BCa);
			Aku = BCu ^ ((~BCa) & BCe);

			Ebu = Ebu ^ Du;
			BCa = Bits::RotateLeft64(Ebu, 27);
			Ega = Ega ^ Da;
			BCe = Bits::RotateLeft64(Ega, 36);
			Eke = Eke ^ De;
			BCi = Bits::RotateLeft64(Eke, 10);
			Emi = Emi ^ Di;
			BCo = Bits::RotateLeft64(Emi, 15);
			Eso = Eso ^ Do;
			BCu = Bits::RotateLeft64(Eso, 56);
			Ama = BCa ^ ((~BCe) & BCi);
			Ame = BCe ^ ((~BCi) & BCo);
			Ami = BCi ^ ((~BCo) & BCu);
			Amo = BCo ^ ((~BCu) & BCa);
			Amu = BCu ^ ((~BCa) & BCe);

			Ebi = Ebi ^ Di;
			BCa = Bits::RotateLeft64(Ebi, 62);
			Ego = Ego ^ Do;
			BCe = Bits::RotateLeft64(Ego, 55);
			Eku = Eku ^ Du;
			BCi = Bits::RotateLeft64(Eku, 39);
			Ema = Ema ^ Da;
			BCo = Bits::RotateLeft64(Ema, 41);
			Ese = Ese ^ De;
			BCu = Bits::RotateLeft64(Ese, 2);
			Asa = BCa ^ ((~BCe) & BCi);
			Ase = BCe ^ ((~BCi) & BCo);
			Asi = BCi ^ ((~BCo) & BCu);
			Aso = BCo ^ ((~BCu) & BCa);
			Asu = BCu ^ ((~BCa) & BCe);

			LRound += 2;
		} // end while

		// copyToState(_state, A)
		_state[0] = Aba;
		_state[1] = Abe;
		_state[2] = Abi;
		_state[3] = Abo;
		_state[4] = Abu;
		_state[5] = Aga;
		_state[6] = Age;
		_state[7] = Agi;
		_state[8] = Ago;
		_state[9] = Agu;
		_state[10] = Aka;
		_state[11] = Ake;
		_state[12] = Aki;
		_state[13] = Ako;
		_state[14] = Aku;
		_state[15] = Ama;
		_state[16] = Ame;
		_state[17] = Ami;
		_state[18] = Amo;
		_state[19] = Amu;
		_state[20] = Asa;
		_state[21] = Ase;
		_state[22] = Asi;
		_state[23] = Aso;
		_state[24] = Asu;
	} // end function KeccakF1600_StatePermute

	virtual void Finish()
	{
		Int32 buffer_pos = _buffer.GetPos();

		HashLibByteArray block = _buffer.GetBytesZeroPadded();

		block[buffer_pos] = Int32(GetHashMode());
		block[(size_t)GetBlockSize() - 1] = block[(size_t)GetBlockSize() - 1] ^ 0x80;

		TransformBlock(&block[0], (Int32)block.size(), 0);
	} // end function Finish

	virtual HashLibByteArray GetResult()
	{
		HashLibByteArray result = HashLibByteArray(GetHashSize());

		Converters::le64_copy(&_state[0], 0, &result[0], 0, (Int32)result.size());

		return result;
	} // end function GetResult

	virtual void TransformBlock(const byte* a_data,
		const Int32 a_data_length, const Int32 a_index)
	{
		HashLibUInt64Array data = HashLibUInt64Array(21);
		Int32 j, blockCount;

		Converters::le64_copy(a_data, a_index, &data[0], 0, a_data_length);		

		j = 0;
		blockCount = GetBlockSize() >> 3;
		while (j < blockCount)
		{
			_state[j] = _state[j] ^ data[j];
			j++;
		} // end while

		KeccakF1600_StatePermute();
	
		ArrayUtils::zeroFill(data);
	} // end function TransformBlock

	virtual HashMode GetHashMode() const 
	{
		return HashMode::hmSHA3;
	};

protected:
	HashLibUInt64Array _state;
	
	static const HashLibUInt64Array RC;

public:
	static const char* InvalidHashMode;
	static const char* InvalidXOFSize;
	static const char* InvalidOutputLength;
	static const char* OutputBufferTooShort;
	static const char* WritetoXofAfterReadError;
}; // end class SHA3


const char* SHA3::InvalidHashMode = "Only \"[%s]\" HashModes are supported";
const char* SHA3::InvalidXOFSize = "XOFSize in bits must be multiples of 8 & be greater than zero bytes";
const char* SHA3::InvalidOutputLength = "Output length is above the digest length";
const char* SHA3::OutputBufferTooShort = "Output buffer too short";
const char* SHA3::WritetoXofAfterReadError = "\"%s\" write to xof after read is not allowed";

const HashLibUInt64Array SHA3::RC = HashLibUInt64Array({
			0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
			0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
			0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
			0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
			0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
			0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
	});


#pragma region SHA3 Family

class SHA3_224 : public SHA3
{
public:
	SHA3_224()
		: SHA3(HashSize::HashSize224)
	{
		_name = __func__;
	} // end constructor

	virtual IHash Clone() const
	{
		SHA3_224 HashInstance = SHA3_224();
		HashInstance._state = _state;
		HashInstance._buffer = _buffer.Clone();
		HashInstance._processed_bytes = _processed_bytes;

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<SHA3_224>(HashInstance);
	}

}; // end class SHA3_224

class SHA3_256 : public SHA3
{
public:
	SHA3_256()
		: SHA3(HashSize::HashSize256)
	{
		_name = __func__;
	} // end constructor

	virtual IHash Clone() const
	{
		SHA3_256 HashInstance = SHA3_256();
		HashInstance._state = _state;
		HashInstance._buffer = _buffer.Clone();
		HashInstance._processed_bytes = _processed_bytes;

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<SHA3_256>(HashInstance);
	}

}; // end class SHA3_256

class SHA3_384 : public SHA3
{
public:
	SHA3_384()
		: SHA3(HashSize::HashSize384)
	{
		_name = __func__;
	} // end constructor

	virtual IHash Clone() const
	{
		SHA3_384 HashInstance = SHA3_384();
		HashInstance._state = _state;
		HashInstance._buffer = _buffer.Clone();
		HashInstance._processed_bytes = _processed_bytes;

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<SHA3_384>(HashInstance);
	}

}; // end class SHA3_384

class SHA3_512 : public SHA3
{
public:
	SHA3_512()
		: SHA3(HashSize::HashSize512)
	{
		_name = __func__;
	} // end constructor

	virtual IHash Clone() const
	{
		SHA3_512 HashInstance = SHA3_512();
		HashInstance._state = _state;
		HashInstance._buffer = _buffer.Clone();
		HashInstance._processed_bytes = _processed_bytes;

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<SHA3_512>(HashInstance);
	}

}; // end class SHA3_512

#pragma endregion


#pragma region Keccak Family

class Keccak : public SHA3
{
protected:
	virtual HashMode GetHashMode() const
	{
		return HashMode::hmKeccak;
	}

protected:
	Keccak(const Int32 hashSize)
		: SHA3(hashSize)
	{} // end constructor
};

class Keccak_224 : public Keccak
{
public:
	Keccak_224()
		: Keccak(HashSize::HashSize224)
	{} // end constructor

protected:
	virtual IHash Clone() const
	{
		Keccak_224 HashInstance = Keccak_224();
		HashInstance._state = _state;
		HashInstance._buffer = _buffer.Clone();
		HashInstance._processed_bytes = _processed_bytes;

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<Keccak_224>(HashInstance);
	}

}; // end class Keccak_224

class Keccak_256 : public Keccak
{
public:
	Keccak_256()
		: Keccak(HashSize::HashSize256)
	{} // end constructor

	virtual IHash Clone() const
	{
		Keccak_256 HashInstance = Keccak_256();
		HashInstance._state = _state;
		HashInstance._buffer = _buffer.Clone();
		HashInstance._processed_bytes = _processed_bytes;

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<Keccak_256>(HashInstance);
	}

}; // end class Keccak_256

class Keccak_288 : public Keccak
{
public:
	Keccak_288()
		: Keccak(HashSize::HashSize288)
	{} // end constructor

	virtual IHash Clone() const
	{
		Keccak_288 HashInstance = Keccak_288();
		HashInstance._state = _state;
		HashInstance._buffer = _buffer.Clone();
		HashInstance._processed_bytes = _processed_bytes;

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<Keccak_288>(HashInstance);
	}

}; // end class Keccak_288

class Keccak_384 : public Keccak
{
public:
	Keccak_384()
		: Keccak(HashSize::HashSize384)
	{} // end constructor

	virtual IHash Clone() const
	{
		Keccak_384 HashInstance = Keccak_384();
		HashInstance._state = _state;
		HashInstance._buffer = _buffer.Clone();
		HashInstance._processed_bytes = _processed_bytes;

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<Keccak_384>(HashInstance);
	}

}; // end class Keccak_384

class Keccak_512 : public Keccak
{
public:
	Keccak_512()
		: Keccak(HashSize::HashSize512)
	{} // end constructor

	virtual IHash Clone() const
	{
		Keccak_512 HashInstance = Keccak_512();
		HashInstance._state = _state;
		HashInstance._buffer = _buffer.Clone();
		HashInstance._processed_bytes = _processed_bytes;

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<Keccak_512>(HashInstance);
	}

}; // end class Keccak_512

#pragma endregion


#pragma region Shake Family

class Shake : public SHA3, public virtual IIXOF
{
protected:
	virtual HashMode GetHashMode() const
	{
		return HashMode::hmShake;
	}

	Shake(const Int32 a_hash_size) 
		: SHA3(a_hash_size)
	{
		_name = __func__;

		_shake_buffer.resize(8);
	} // end constructor

public:
	virtual void Initialize()
	{
		_buffer_pos = 0;
		_digest_pos = 0;
		_finalized = false;
		ArrayUtils::zeroFill(_shake_buffer);

		SHA3::Initialize();
	} // end function Initialize

	virtual IHashResult TransformFinal()
	{
		HashLibByteArray temp = GetResult();

		Initialize();

		return make_shared<HashResult>(temp);
	} // end function TransformFinal

	virtual UInt64 GetXOFSizeInBits() const
	{
		return _xofSizeInBits;
	}

	virtual void SetXOFSizeInBits(const UInt64 value)
	{
		SetXOFSizeInBitsInternal(value);
	}

	virtual void DoOutput(HashLibByteArray& a_destination, const UInt64 a_destinationOffset,
		const UInt64 a_outputLength)
	{
		UInt64 destinationOffset, outputLength;

		if (((UInt64)a_destination.size() - a_destinationOffset) < a_outputLength)
			throw ArgumentOutOfRangeHashLibException(SHA3::OutputBufferTooShort);

		if ((_digest_pos + a_outputLength) > (GetXOFSizeInBits() >> 3))
			throw ArgumentOutOfRangeHashLibException(SHA3::InvalidOutputLength);

		if (!_finalized)
		{
			Finish();
			_finalized = true;
		} // end if

		destinationOffset = a_destinationOffset;
		outputLength = a_outputLength;

		while (outputLength > 0)
		{
			if ((_digest_pos & 7) == 0)
			{
				if ((_buffer_pos * 8) >= (UInt64)GetBlockSize())
				{
					KeccakF1600_StatePermute();
					_buffer_pos = 0;
				} // end if

				Converters::ReadUInt64AsBytesLE(_state[(Int32)_buffer_pos], _shake_buffer, 0);

				_buffer_pos++;
			} // end if

			UInt64 blockOffset = _digest_pos & 7;
			UInt64 diff = (UInt64)_shake_buffer.size() - blockOffset;
			UInt64 count = min(outputLength, diff);

			memmove(&a_destination[(Int32)destinationOffset], &_shake_buffer[(Int32)blockOffset], (size_t)count);

			outputLength -= count;
			destinationOffset += count;
			_digest_pos += count;
		} // end while
	} // end function DoOutput

	virtual void TransformBytes(const HashLibByteArray& a_data, const Int32 a_index, const Int32 a_length)
	{
		if (_finalized)
			throw InvalidOperationHashLibException(
				Utils::string_format(SHA3::WritetoXofAfterReadError, GetName().c_str()));

		SHA3::TransformBytes(a_data, a_index, a_length);
	} // end function TransformBytes

protected:
	HashLibByteArray GetResult()
	{
		UInt64 XofSizeInBytes = GetXOFSizeInBits() >> 3;

		HashLibByteArray result = HashLibByteArray((Int32)XofSizeInBytes);

		DoOutput(result, 0, XofSizeInBytes);

		return result;
	} // end function GetResult

private:
	void inline SetXOFSizeInBitsInternal(const UInt64 a_XOFSizeInBits)
	{
		UInt64 LXofSizeInBytes = a_XOFSizeInBits >> 3;

		if (((a_XOFSizeInBits & 0x07) != 0) || (LXofSizeInBytes < 1))
			throw ArgumentOutOfRangeHashLibException(SHA3::InvalidXOFSize);

		_xofSizeInBits = a_XOFSizeInBits;
	} // end function SetXOFSizeInBitsInternal

private:
	UInt64 _xofSizeInBits;

protected:
	UInt64 _buffer_pos = 0, _digest_pos = 0;
	HashLibByteArray _shake_buffer;
	bool _finalized = false;

}; // end class Shake

class Shake_128 : public Shake
{
public:
	Shake_128() :
		Shake((Int32)HashSize::HashSize128)
	{ } // end constructor

	Shake_128 Copy() const
	{
		// Xof Cloning
		Shake_128 HashInstance = Shake_128();
		HashInstance.SetXOFSizeInBits(GetXOFSizeInBits());

		// Shake_128 Cloning
		HashInstance._buffer_pos = _buffer_pos;
		HashInstance._digest_pos = _digest_pos;
		HashInstance._finalized = _finalized;

		HashInstance._shake_buffer = _shake_buffer;

		// Internal SHA3 Cloning
		HashInstance._buffer = _buffer.Clone();
		HashInstance._processed_bytes = _processed_bytes;

		HashInstance._state = _state;

		HashInstance.SetBufferSize(GetBufferSize());

		return HashInstance;
	} //

	virtual IHash Clone() const
	{
		return make_shared<Shake_128>(Copy());
	} // end function Clone

	virtual IXOF CloneXOF() const
	{
		return make_shared<Shake_128>(Copy());
	} // end function CloneXOF
}; // end class Shake_128

class Shake_256 : public Shake
{
public:
	Shake_256() :
		Shake((Int32)HashSize::HashSize256)
	{ } // end constructor

	Shake_256 Copy() const
	{
		// Xof Cloning
		Shake_256 HashInstance = Shake_256();
		HashInstance.SetXOFSizeInBits(GetXOFSizeInBits());

		// Shake_256 Cloning
		HashInstance._buffer_pos = _buffer_pos;
		HashInstance._digest_pos = _digest_pos;
		HashInstance._finalized = _finalized;

		HashInstance._shake_buffer = _shake_buffer;

		// Internal SHA3 Cloning
		HashInstance._buffer = _buffer.Clone();
		HashInstance._processed_bytes = _processed_bytes;

		HashInstance._state = _state;

		HashInstance.SetBufferSize(GetBufferSize());

		return HashInstance;
	} // end function Copy

	virtual IHash Clone() const
	{
		return make_shared<Shake_256>(Copy());
	} // end function Clone

	virtual IXOF CloneXOF() const
	{
		return make_shared<Shake_256>(Copy());
	} // end function CloneXOF
}; // end class Shake_256

#pragma endregion


#pragma region CShake Family

class CShake : public Shake
{
protected:
	HashLibByteArray _fn, _fs, _initBlock;

protected:
	virtual HashMode GetHashMode() const
	{
		return _fn.empty() && _fs.empty() ? HashMode::hmShake : HashMode::hmCShake;
	}

	/// <param name="a_hash_size">
	/// the HashSize of the underlying Shake function
	/// </param>
	/// <param name="N">
	/// the function name string, note this is reserved for use by NIST.
	/// Avoid using if not required
	/// </param>
	/// <param name="S">
	/// the customization string - available for local use
	/// </param>
	CShake(const Int32 a_hash_size, const HashLibByteArray& N, const HashLibByteArray& S)
		: Shake(a_hash_size)
	{
		_name = __func__;

		_fn = N;
		_fs = S;

		if (!(_fn.empty() && _fs.empty()))
		{
			_initBlock = Utils::concat(EncodeString(N), EncodeString(S));
		} // end else
	} // end constructor

private:
	// LeftEncode returns max 9 bytes
	static inline HashLibByteArray LeftEncode(const UInt64 a_input)
	{
		byte LN;
		UInt64 LV;
		Int32 LIdx;

		LN = 1;
		LV = a_input;
		LV = LV >> 8;

		while (LV != 0)
		{
			LN++;
			LV = LV >> 8;
		} // end while

		HashLibByteArray result = HashLibByteArray((size_t)LN + 1);
		result[0] = LN;

		for (LIdx = 1; LIdx <= LN; LIdx++)
			result[LIdx] = (byte)(a_input >> (8 * (LN - LIdx)));

		return result;
	} // end function LeftEncode

public:
	virtual void Initialize()
	{
		Shake::Initialize();

		if (!_initBlock.empty())
			TransformBytes(BytePad(_initBlock, GetBlockSize()));
	} // end function Initialize

	virtual void TransformBytes(const HashLibByteArray& a_data)
	{
		Shake::TransformBytes(a_data, 0, (Int32)a_data.size());
	} // end function TransformBytes

	static inline HashLibByteArray RightEncode(const UInt64 a_input)
	{
		Int32 LIdx;

		byte LN = 1;
		UInt64 LV = a_input;
		LV = LV >> 8;

		while (LV != 0)
		{
			LN++;
			LV = LV >> 8;
		} // end while

		HashLibByteArray result = HashLibByteArray((size_t)LN + 1);
		result[LN] = LN;

		for (LIdx = 1; LIdx <= LN; LIdx++)
			result[(size_t)LIdx - 1] = (byte)(a_input >> (8 * (LN - LIdx)));

		return result;
	} // end function RightEncode

	static inline HashLibByteArray BytePad(const HashLibByteArray& a_input, const Int32 AW)
	{
		HashLibByteArray buffer = Utils::concat(LeftEncode((UInt64)AW), a_input);
		Int32 padLength = AW - (buffer.size() % AW);

		return Utils::concat(buffer, HashLibByteArray(padLength));
	} // end function BytePad

	static inline HashLibByteArray EncodeString(const HashLibByteArray& a_input)
	{
		if (a_input.empty()) return LeftEncode(0);

		return Utils::concat(LeftEncode((UInt64)a_input.size() * 8), a_input);
	} // end function EncodeString

}; // end function CShake

class CShake_128 : public CShake
{
public:
	CShake_128(const HashLibByteArray& N, const HashLibByteArray& S) :
		CShake((Int32)HashSize::HashSize128, N, S)
	{ } // end constructor

	CShake_128 Copy() const
	{
		// Xof Cloning
		CShake_128 HashInstance = CShake_128(_fn, _fs);
		HashInstance.SetXOFSizeInBits(GetXOFSizeInBits());
		
		// CShake_128 Cloning
		HashInstance._initBlock = _initBlock;

		HashInstance._buffer_pos = _buffer_pos;
		HashInstance._digest_pos = _digest_pos;
		HashInstance._finalized = _finalized;

		HashInstance._shake_buffer = _shake_buffer;

		// Internal SHA3 Cloning
		HashInstance._buffer = _buffer.Clone();
		HashInstance._processed_bytes = _processed_bytes;

		HashInstance._state = _state;

		HashInstance.SetBufferSize(GetBufferSize());

		return HashInstance;
	} // end function Copy

	virtual IHash Clone() const
	{
		return make_shared<CShake_128>(Copy());
	} // end function Clone

	virtual IXOF CloneXOF() const
	{
		return make_shared<CShake_128>(Copy());
	} // end function CloneXOF
}; // end class CShake_128

class CShake_256 : public CShake
{
public:
	CShake_256(const HashLibByteArray& N, const HashLibByteArray& S) :
		CShake((Int32)HashSize::HashSize256, N, S)
	{ } // end constructor

	CShake_256 Copy() const
	{
		// Xof Cloning
		CShake_256 HashInstance = CShake_256(_fn, _fs);
		HashInstance.SetXOFSizeInBits(GetXOFSizeInBits());

		// CShake_256 Cloning
		HashInstance._initBlock = _initBlock;

		HashInstance._buffer_pos = _buffer_pos;
		HashInstance._digest_pos = _digest_pos;
		HashInstance._finalized = _finalized;

		HashInstance._shake_buffer = _shake_buffer;

		// Internal SHA3 Cloning
		HashInstance._buffer = _buffer.Clone();
		HashInstance._processed_bytes = _processed_bytes;

		HashInstance._state = _state;

		HashInstance.SetBufferSize(GetBufferSize());

		return HashInstance;
	} // end function Copy

	virtual IHash Clone() const
	{
		return make_shared<CShake_256>(Copy());
	} // end function Clone

	virtual IXOF CloneXOF() const
	{
		return make_shared<CShake_256>(Copy());
	} // end function CloneXOF
}; // end class CShake_256

#pragma endregion
