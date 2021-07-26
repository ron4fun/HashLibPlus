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

class CRC64Polynomials
{
public:
	static const UInt64 ECMA_182 = 0x42F0E1EBA9EA3693;

}; // end class CRC64Polynomials

class _CRC64 : public Hash, public virtual IIChecksum, public virtual IIBlockHash, 
	public virtual IIHash64, public virtual IITransformBlock
{
public:
	_CRC64(const UInt64 _poly, const UInt64 _Init,
		const bool _refIn, const bool _refOut, const UInt64 _XorOut,
		const UInt64 _check, const HashLibStringArray& _Names)
		: Hash(8, 1)
	{
		_crcAlgorithm = make_shared<_CRC>(64, _poly, _Init, _refIn, _refOut, _XorOut, _check, _Names);
	} // end constructor

	~_CRC64()
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

}; // end class _CRC64

class _CRC64_ECMA_182 : public _CRC64
{
public:
	_CRC64_ECMA_182()
		: _CRC64(CRC64Polynomials::ECMA_182, 0x0000000000000000, false, false, 0x0000000000000000, 0x6C40DF5F0B497347, HashLibStringArray({ "CRC-64/ECMA" }))
	{} // end constructor
}; // end class CRC64_ECMA_182
