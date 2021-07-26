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

class Adler32 : public Hash, public virtual IIChecksum, public virtual IIBlockHash, 
	public virtual IIHash32, public virtual IITransformBlock
{
public:
	Adler32()
		: Hash(4, 1)
	{
		_name = __func__;
	} // end constructor

	virtual IHash Clone() const override
	{
		Adler32 HashInstance = Adler32();
		HashInstance._a = _a;
		HashInstance._b = _b;

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<Adler32>(HashInstance);
	}

	virtual void Initialize() override
	{
		_a = 1;
		_b = 0;
	} // end function Initialize

	virtual IHashResult TransformFinal() override
	{
		IHashResult result = make_shared<HashResult>(int32_t((_b << 16) | _a));

		Initialize();

		return result;
	} // end function TransformFinal

	virtual void TransformBytes(const HashLibByteArray& a_data, const Int32 a_index, const Int32 a_length) override
	{
		Int32 n, length = a_length, index = a_index;

		// lifted from PngEncoder Adler32.cs

		while (length > 0)
		{
			// We can defer the modulo operation:
			// a maximally grows from 65521 to 65521 + 255 * 3800
			// b maximally grows by3800 * median(a) = 2090079800 < 2^31
			n = 3800;
			if (n > length)
				n = length;

			length = length - n;

			while ((n - 1) >= 0)
			{
				_a = (_a + a_data[index]);
				_b = (_b + _a);
				index++;
				n--;
			} // end while

			_a = _a % MOD_ADLER;
			_b = _b % MOD_ADLER;
		} // end while

	} // end function TransformBlock

private:
	UInt32 _a = 1, _b = 0;

	static const UInt32 MOD_ADLER = 65521;

}; // end class Adler32
