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

#include "CRC.h"

class CRC32Polynomials
{
public:
	static const UInt32 PKZIP = 0x04C11DB7;
	static const UInt32 Castagnoli = 0x1EDC6F41;

}; // end class CRC32Polynomials

class _CRC32 : public Hash, public virtual IIChecksum, public virtual IIBlockHash, 
	public virtual IIHash32, public virtual IITransformBlock
{
public:
	_CRC32(const UInt64 _poly, const UInt64 _Init,
		const bool _refIn, const bool _refOut, const UInt64 _XorOut,
		const UInt64 _check, const HashLibStringArray& _Names)
		: Hash(4, 1)
	{
		_crcAlgorithm = make_shared<_CRC>(32, _poly, _Init, _refIn, _refOut, _XorOut, _check, _Names);
	} // end constructor

	~_CRC32()
	{} // end destructor

	virtual string GetName() const
	{
		return _crcAlgorithm->GetName();
	}

	virtual void Initialize()
	{
		_crcAlgorithm->Initialize();
	} // end function Initialize

	virtual IHashResult TransformFinal()
	{
		return _crcAlgorithm->TransformFinal();
	} // end function TransformFinal

	virtual void TransformBytes(const HashLibByteArray& a_data, const Int32 a_index, const Int32 a_length)
	{
		_crcAlgorithm->TransformBytes(a_data, a_index, a_length);
	} // end function TransformBytes

private:
	ICRC _crcAlgorithm = nullptr;

}; // end class _CRC32

class _CRC32_PKZIP : public _CRC32
{
public:
	_CRC32_PKZIP()
		: _CRC32(CRC32Polynomials::PKZIP, 0xFFFFFFFF, true, true, 0xFFFFFFFF, 0xCBF43926, HashLibStringArray({ "CRC-32", "CRC-32/ADCCP", "PKZIP" }))
	{} // end constructor
}; // end class CRC32_PKZIP

class _CRC32_CASTAGNOLI : public _CRC32
{
public:
	_CRC32_CASTAGNOLI()
		: _CRC32(CRC32Polynomials::Castagnoli, 0xFFFFFFFF, true, true, 0xFFFFFFFF, 0xE3069283, HashLibStringArray({ "CRC-32C", "CRC-32/ISCSI", "CRC-32/CASTAGNOLI" }))
	{} // end constructor
}; // end class CRC32_CASTAGNOLI
