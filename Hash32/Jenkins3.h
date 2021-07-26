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

#include "../Base/MultipleTransformNonBlock.h"


class Jenkins3 : public MultipleTransformNonBlock, public virtual IIHash32, 
	public virtual IITransformBlock
{
private: Int32 _initialValue;

public:
	Jenkins3(const Int32 initialValue = 0)
		: MultipleTransformNonBlock(4, 12)
	{
		_name = __func__;

		_initialValue = initialValue;
	} // end constructor

	virtual IHash Clone() const
	{
		Jenkins3 HashInstance = Jenkins3();
		HashInstance._initialValue = _initialValue;
		HashInstance._buffer = _buffer;

		IHash _hash = make_shared<Jenkins3>(HashInstance);
		_hash->SetBufferSize(GetBufferSize());

		return _hash;
	}

protected:
	virtual IHashResult ComputeAggregatedBytes(const HashLibByteArray &a_data)
	{
		Int32 length, currentIndex, i1, i2, i3, i4;
		UInt32 a, b, c;
		
		length = (Int32)a_data.size();
		
		a = 0xDEADBEEF + UInt32(length) + (UInt32)_initialValue;
		b = a;
		c = b;

		if (length == 0) return make_shared<HashResult>(c);

		currentIndex = 0;
		while (length > 12)
		{
			i1 = a_data[currentIndex];
			currentIndex++;
			i2 = a_data[currentIndex] << 8;
			currentIndex++;
			i3 = a_data[currentIndex] << 16;
			currentIndex++;
			i4 = a_data[currentIndex] << 24;
			currentIndex++;

			a = a + UInt32(i1 | i2 | i3 | i4);

			i1 = a_data[currentIndex];
			currentIndex++;
			i2 = a_data[currentIndex] << 8;
			currentIndex++;
			i3 = a_data[currentIndex] << 16;
			currentIndex++;
			i4 = a_data[currentIndex] << 24;
			currentIndex++;

			b = b + UInt32(i1 | i2 | i3 | i4);

			i1 = a_data[currentIndex];
			currentIndex++;
			i2 = a_data[currentIndex] << 8;
			currentIndex++;
			i3 = a_data[currentIndex] << 16;
			currentIndex++;
			i4 = a_data[currentIndex] << 24;
			currentIndex++;

			c = c + UInt32(i1 | i2 | i3 | i4);

			a = a - c;
			a = a ^ Bits::RotateLeft32(c, 4);
			c = c + b;
			b = b - a;
			b = b ^ Bits::RotateLeft32(a, 6);
			a = a + c;
			c = c - b;
			c = c ^ Bits::RotateLeft32(b, 8);
			b = b + a;
			a = a - c;
			a = a ^ Bits::RotateLeft32(c, 16);
			c = c + b;
			b = b - a;
			b = b ^ Bits::RotateLeft32(a, 19);
			a = a + c;
			c = c - b;
			c = c ^ Bits::RotateLeft32(b, 4);
			b = b + a;

			length -= 12;
		} // end while

		switch (length)
		{
		case 12:
			i1 = a_data[currentIndex];
			currentIndex++;
			i2 = a_data[currentIndex] << 8;
			currentIndex++;
			i3 = a_data[currentIndex] << 16;
			currentIndex++;
			i4 = a_data[currentIndex] << 24;
			currentIndex++;

			a = a + UInt32(i1 | i2 | i3 | i4);

			i1 = a_data[currentIndex];
			currentIndex++;
			i2 = a_data[currentIndex] << 8;
			currentIndex++;
			i3 = a_data[currentIndex] << 16;
			currentIndex++;
			i4 = a_data[currentIndex] << 24;
			currentIndex++;

			b = b + UInt32(i1 | i2 | i3 | i4);

			i1 = a_data[currentIndex];
			currentIndex++;
			i2 = a_data[currentIndex] << 8;
			currentIndex++;
			i3 = a_data[currentIndex] << 16;
			currentIndex++;
			i4 = a_data[currentIndex] << 24;

			c = c + UInt32(i1 | i2 | i3 | i4);
			break;

		case 11:
			i1 = a_data[currentIndex];
			currentIndex++;
			i2 = a_data[currentIndex] << 8;
			currentIndex++;
			i3 = a_data[currentIndex] << 16;
			currentIndex++;
			i4 = a_data[currentIndex] << 24;
			currentIndex++;

			a = a + UInt32(i1 | i2 | i3 | i4);

			i1 = a_data[currentIndex];
			currentIndex++;
			i2 = a_data[currentIndex] << 8;
			currentIndex++;
			i3 = a_data[currentIndex] << 16;
			currentIndex++;
			i4 = a_data[currentIndex] << 24;
			currentIndex++;

			b = b + UInt32(i1 | i2 | i3 | i4);

			i1 = a_data[currentIndex];
			currentIndex++;
			i2 = a_data[currentIndex] << 8;
			currentIndex++;
			i3 = a_data[currentIndex] << 16;

			c = c + UInt32(i1 | i2 | i3);
			break;

		case 10:
			i1 = a_data[currentIndex];
			currentIndex++;
			i2 = a_data[currentIndex] << 8;
			currentIndex++;
			i3 = a_data[currentIndex] << 16;
			currentIndex++;
			i4 = a_data[currentIndex] << 24;
			currentIndex++;

			a = a + UInt32(i1 | i2 | i3 | i4);

			i1 = a_data[currentIndex];
			currentIndex++;
			i2 = a_data[currentIndex] << 8;
			currentIndex++;
			i3 = a_data[currentIndex] << 16;
			currentIndex++;
			i4 = a_data[currentIndex] << 24;
			currentIndex++;

			b = b + UInt32(i1 | i2 | i3 | i4);

			i1 = a_data[currentIndex];
			currentIndex++;
			i2 = a_data[currentIndex] << 8;

			c = c + UInt32(i1 | i2);
			break;

		case 9:
			i1 = a_data[currentIndex];
			currentIndex++;
			i2 = a_data[currentIndex] << 8;
			currentIndex++;
			i3 = a_data[currentIndex] << 16;
			currentIndex++;
			i4 = a_data[currentIndex] << 24;
			currentIndex++;

			a = a + UInt32(i1 | i2 | i3 | i4);

			i1 = a_data[currentIndex];
			currentIndex++;
			i2 = a_data[currentIndex] << 8;
			currentIndex++;
			i3 = a_data[currentIndex] << 16;
			currentIndex++;
			i4 = a_data[currentIndex] << 24;
			currentIndex++;

			b = b + UInt32(i1 | i2 | i3 | i4);

			i1 = a_data[currentIndex];

			c = c + UInt32(i1);
			break;

		case 8:
			i1 = a_data[currentIndex];
			currentIndex++;
			i2 = a_data[currentIndex] << 8;
			currentIndex++;
			i3 = a_data[currentIndex] << 16;
			currentIndex++;
			i4 = a_data[currentIndex] << 24;
			currentIndex++;

			a = a + UInt32(i1 | i2 | i3 | i4);

			i1 = a_data[currentIndex];
			currentIndex++;
			i2 = a_data[currentIndex] << 8;
			currentIndex++;
			i3 = a_data[currentIndex] << 16;
			currentIndex++;
			i4 = a_data[currentIndex] << 24;

			b = b + UInt32(i1 | i2 | i3 | i4);
			break;

		case 7:
			i1 = a_data[currentIndex];
			currentIndex++;
			i2 = a_data[currentIndex] << 8;
			currentIndex++;
			i3 = a_data[currentIndex] << 16;
			currentIndex++;
			i4 = a_data[currentIndex] << 24;
			currentIndex++;

			a = a + UInt32(i1 | i2 | i3 | i4);

			i1 = a_data[currentIndex];
			currentIndex++;
			i2 = a_data[currentIndex] << 8;
			currentIndex++;
			i3 = a_data[currentIndex] << 16;

			b = b + UInt32(i1 | i2 | i3);
			break;

		case 6:
			i1 = a_data[currentIndex];
			currentIndex++;
			i2 = a_data[currentIndex] << 8;
			currentIndex++;
			i3 = a_data[currentIndex] << 16;
			currentIndex++;
			i4 = a_data[currentIndex] << 24;
			currentIndex++;

			a = a + UInt32(i1 | i2 | i3 | i4);

			i1 = a_data[currentIndex];
			currentIndex++;
			i2 = a_data[currentIndex] << 8;

			b = b + UInt32(i1 | i2);
			break;

		case 5:
			i1 = a_data[currentIndex];
			currentIndex++;
			i2 = a_data[currentIndex] << 8;
			currentIndex++;
			i3 = a_data[currentIndex] << 16;
			currentIndex++;
			i4 = a_data[currentIndex] << 24;
			currentIndex++;

			a = a + UInt32(i1 | i2 | i3 | i4);

			i1 = a_data[currentIndex];

			b = b + UInt32(i1);
			break;

		case 4:
			i1 = a_data[currentIndex];
			currentIndex++;
			i2 = a_data[currentIndex] << 8;
			currentIndex++;
			i3 = a_data[currentIndex] << 16;
			currentIndex++;
			i4 = a_data[currentIndex] << 24;

			a = a + UInt32(i1 | i2 | i3 | i4);
			break;

		case 3:
			i1 = a_data[currentIndex];
			currentIndex++;
			i2 = a_data[currentIndex] << 8;
			currentIndex++;
			i3 = a_data[currentIndex] << 16;

			a = a + UInt32(i1 | i2 | i3);
			break;

		case 2:
			i1 = a_data[currentIndex];
			currentIndex++;
			i2 = a_data[currentIndex] << 8;

			a = a + UInt32(i1 | i2);
			break;

		case 1:
			i1 = a_data[currentIndex];

			a = a + UInt32(i1);
		} // end switch

		c = c ^ b;
		c = c - Bits::RotateLeft32(b, 14);
		a = a ^ c;
		a = a - Bits::RotateLeft32(c, 11);
		b = b ^ a;
		b = b - Bits::RotateLeft32(a, 25);
		c = c ^ b;
		c = c - Bits::RotateLeft32(b, 16);
		a = a ^ c;
		a = a - Bits::RotateLeft32(c, 4);
		b = b ^ a;
		b = b - Bits::RotateLeft32(a, 14);
		c = c ^ b;
		c = c - Bits::RotateLeft32(b, 24);

		return make_shared<HashResult>(c);
	} // end function ComputeAggregatedBytes

}; // end class Jenkins3
