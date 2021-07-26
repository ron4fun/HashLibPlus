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


class SuperFast : public MultipleTransformNonBlock, 
	public virtual IIHash32, public virtual IITransformBlock
{
public:
	SuperFast()
		: MultipleTransformNonBlock(4, 4)
	{
		_name = __func__;
	} // end constructor

	virtual IHash Clone() const
	{
		SuperFast HashInstance = SuperFast();
		HashInstance._buffer = _buffer;

		IHash _hash = make_shared<SuperFast>(HashInstance);
		_hash->SetBufferSize(GetBufferSize());

		return _hash;
	}

protected:
	virtual IHashResult ComputeAggregatedBytes(const HashLibByteArray &a_data)
	{
		UInt32 _hash, tmp, u1;
		Int32 Length, currentIndex, i1, i2;
		
		Length = (Int32)a_data.size();

		if (Length == 0)
			return make_shared<HashResult>(Int32(0));
		
		_hash = UInt32(Length);
		currentIndex = 0;

		while (Length >= 4)
		{
			i1 = a_data[currentIndex];
			currentIndex++;
			i2 = a_data[currentIndex] << 8;
			currentIndex++;
			_hash = UInt16(_hash + UInt32(i1 | i2));
			u1 = UInt32(a_data[currentIndex]);
			currentIndex++;
			tmp = UInt32((byte(u1) | a_data[currentIndex] << 8) << 11) ^ _hash;
			currentIndex++;
			_hash = (_hash << 16) ^ tmp;
			_hash = _hash + (_hash >> 11);

			Length -= 4;
		} // end while

		switch (Length)
		{
		case 3:
			i1 = a_data[currentIndex];
			currentIndex++;
			i2 = a_data[currentIndex];
			currentIndex++;
			_hash = _hash + UInt16(i1 | i2 << 8);
			_hash = _hash ^ (_hash << 16);
			_hash = _hash ^ (UInt32(a_data[currentIndex]) << 18);
			_hash = _hash + (_hash >> 11);
			break;

		case 2:
			i1 = a_data[currentIndex];
			currentIndex++;
			i2 = a_data[currentIndex];
			_hash = _hash + UInt16(i1 | i2 << 8);
			_hash = _hash ^ (_hash << 11);
			_hash = _hash + (_hash >> 17);
			break;

		case 1:
			i1 = a_data[currentIndex];
			_hash = _hash + UInt32(i1);
			_hash = _hash ^ (_hash << 10);
			_hash = _hash + (_hash >> 1);
			break;
		} // end switch

		_hash = _hash ^ (_hash << 3);
		_hash = _hash + (_hash >> 5);
		_hash = _hash ^ (_hash << 4);
		_hash = _hash + (_hash >> 17);
		_hash = _hash ^ (_hash << 25);
		_hash = _hash + (_hash >> 6);

		return make_shared<HashResult>(_hash);
	} // end function ComputeAggregatedBytes

}; // end class SuperFast
