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

#include "../Base/Hash.h"
#include "../Interfaces/IHashInfo.h"


class Rotating : public Hash, public virtual IIBlockHash, 
	public virtual IIHash32, public virtual IITransformBlock
{
public:
	Rotating()
		: Hash(4, 1)
	{
		_name = __func__;
	} // end constructor

	virtual IHash Clone() const
	{
		Rotating HashInstance = Rotating();
		HashInstance._hash = _hash;

		IHash _hash = make_shared<Rotating>(HashInstance);
		_hash->SetBufferSize(GetBufferSize());

		return _hash;
	}

	virtual void Initialize()
	{
		_hash = 0;
	} // end function Initialize

	virtual IHashResult TransformFinal()
	{
		IHashResult result = make_shared<HashResult>(_hash);

		Initialize();

		return result;
	} // end function TransformFinal

	virtual void TransformBytes(const HashLibByteArray &a_data, const Int32 a_index, const Int32 a_length)
	{
		UInt32 i = a_index, length = a_length;

		while (length > 0)
		{
			_hash = Bits::RotateLeft32(_hash, 4) ^ a_data[i];
			i++;
			length--;
		} // end while
	} // end function TransformBytes

private:
	UInt32 _hash;

}; // end class Rotating
