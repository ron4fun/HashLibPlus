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
#include "../Utils/ArrayUtils.h"
#include "../Interfaces/IHashInfo.h"
#include "../Crypto/Blake3.h"

class PBKDF_Blake3NotBuildInAdapter : public KDFNotBuildInAdapter,
	public virtual IIPBKDF_Blake3NotBuildIn
{
private:
	HashLibByteArray _srcKey;
	IXOF _xof;

	const Int32 derivationIVLen = 32;
	const UInt32 flagDeriveKeyContext = 1 << 5;
	const UInt32 flagDeriveKeyMaterial = 1 << 6;

public:
	PBKDF_Blake3NotBuildInAdapter()
	{}
	
	// derives a subkey from ctx and srcKey. ctx should be hardcoded,
	// globally unique, and application-specific. A good format for ctx strings is:
	//
	// [application] [commit timestamp] [purpose]
	//
	// e.g.:
	//
	// example.com 2019-12-25 16:18:03 session tokens v1
	//
	// The purpose of these requirements is to ensure that an attacker cannot trick
	// two different applications into using the same context string.
	PBKDF_Blake3NotBuildInAdapter(const HashLibByteArray& srcKey, const HashLibByteArray& ctx)
	{
		_srcKey = srcKey;

		HashLibUInt32Array ivWords = Blake3::IV;

		// construct the derivation Hasher and get the derivationIV
		HashLibByteArray derivationIv = Blake3(derivationIVLen, ivWords, flagDeriveKeyContext)
			.ComputeBytes(ctx)->GetBytes();
		
		Converters::le32_copy(&derivationIv[0], 0, &ivWords[0], 0, Blake3::KeyLengthInBytes);
		
		_xof = make_shared<Blake3XOF>(32, ivWords, flagDeriveKeyMaterial);
	}

	virtual void Clear()
	{
		ArrayUtils::zeroFill(_srcKey);
	} //

	virtual string GetName() const
	{
		return "PBKDF_Blake3NotBuildIn";
	}

	virtual IKDFNotBuildIn Clone() const
	{
		PBKDF_Blake3NotBuildInAdapter result = PBKDF_Blake3NotBuildInAdapter();	
		result._srcKey = _srcKey;
		result._xof = _xof->CloneXOF();

		return make_shared<PBKDF_Blake3NotBuildInAdapter>(result);
	} //

	virtual HashLibByteArray GetBytes(const Int32 bc)
	{
		HashLibByteArray result = HashLibByteArray(bc);

		_xof->SetXOFSizeInBits((UInt64)bc * 8);
		_xof->Initialize();
		_xof->TransformBytes(_srcKey);
		// derive the SubKey
		_xof->DoOutput(result, 0, (UInt64)result.size());
		_xof->Initialize();

		return result;
	}

};