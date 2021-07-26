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

#include "MDBase.h"

class RIPEMD256 : public MDBase, public virtual IITransformBlock
{
public:
	RIPEMD256()
		: MDBase(8, 32)
	{
		_name = __func__;		
	} // end constructor

	virtual IHash Clone() const
	{
		RIPEMD256 HashInstance = RIPEMD256();
		HashInstance._state = _state;
		HashInstance._buffer = _buffer.Clone();
		HashInstance._processed_bytes = _processed_bytes;

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<RIPEMD256>(HashInstance);
	}

	virtual void Initialize()
	{
		_state[4] = 0x76543210;
		_state[5] = 0xFEDCBA98;
		_state[6] = 0x89ABCDEF;
		_state[7] = 0x01234567;

		MDBase::Initialize();
	} // end function Initialize

protected:
	virtual void TransformBlock(const byte* a_data,
		const Int32 a_data_length, const Int32 a_index)
	{
		UInt32 a, b, c, d, aa, bb, cc, dd;

		HashLibUInt32Array data = HashLibUInt32Array(16);

		Converters::le32_copy(a_data, a_index, &data[0], 0, 64);

		a = _state[0];
		b = _state[1];
		c = _state[2];
		d = _state[3];
		aa = _state[4];
		bb = _state[5];
		cc = _state[6];
		dd = _state[7];

		a = a + (data[0] + (b ^ c ^ d));
		a = Bits::RotateLeft32(a, 11);
		d = d + (data[1] + (a ^ b ^ c));
		d = Bits::RotateLeft32(d, 14);
		c = c + (data[2] + (d ^ a ^ b));
		c = Bits::RotateLeft32(c, 15);
		b = b + (data[3] + (c ^ d ^ a));
		b = Bits::RotateLeft32(b, 12);
		a = a + (data[4] + (b ^ c ^ d));
		a = Bits::RotateLeft32(a, 5);
		d = d + (data[5] + (a ^ b ^ c));
		d = Bits::RotateLeft32(d, 8);
		c = c + (data[6] + (d ^ a ^ b));
		c = Bits::RotateLeft32(c, 7);
		b = b + (data[7] + (c ^ d ^ a));
		b = Bits::RotateLeft32(b, 9);
		a = a + (data[8] + (b ^ c ^ d));
		a = Bits::RotateLeft32(a, 11);
		d = d + (data[9] + (a ^ b ^ c));
		d = Bits::RotateLeft32(d, 13);
		c = c + (data[10] + (d ^ a ^ b));
		c = Bits::RotateLeft32(c, 14);
		b = b + (data[11] + (c ^ d ^ a));
		b = Bits::RotateLeft32(b, 15);
		a = a + (data[12] + (b ^ c ^ d));
		a = Bits::RotateLeft32(a, 6);
		d = d + (data[13] + (a ^ b ^ c));
		d = Bits::RotateLeft32(d, 7);
		c = c + (data[14] + (d ^ a ^ b));
		c = Bits::RotateLeft32(c, 9);
		b = b + (data[15] + (c ^ d ^ a));
		b = Bits::RotateLeft32(b, 8);

		aa = aa + (data[5] + C1 + ((bb & dd) | (cc & ~dd)));
		aa = Bits::RotateLeft32(aa, 8);
		dd = dd + (data[14] + C1 + ((aa & cc) | (bb & ~cc)));
		dd = Bits::RotateLeft32(dd, 9);
		cc = cc + (data[7] + C1 + ((dd & bb) | (aa & ~bb)));
		cc = Bits::RotateLeft32(cc, 9);
		bb = bb + (data[0] + C1 + ((cc & aa) | (dd & ~aa)));
		bb = Bits::RotateLeft32(bb, 11);
		aa = aa + (data[9] + C1 + ((bb & dd) | (cc & ~dd)));
		aa = Bits::RotateLeft32(aa, 13);
		dd = dd + (data[2] + C1 + ((aa & cc) | (bb & ~cc)));
		dd = Bits::RotateLeft32(dd, 15);
		cc = cc + (data[11] + C1 + ((dd & bb) | (aa & ~bb)));
		cc = Bits::RotateLeft32(cc, 15);
		bb = bb + (data[4] + C1 + ((cc & aa) | (dd & ~aa)));
		bb = Bits::RotateLeft32(bb, 5);
		aa = aa + (data[13] + C1 + ((bb & dd) | (cc & ~dd)));
		aa = Bits::RotateLeft32(aa, 7);
		dd = dd + (data[6] + C1 + ((aa & cc) | (bb & ~cc)));
		dd = Bits::RotateLeft32(dd, 7);
		cc = cc + (data[15] + C1 + ((dd & bb) | (aa & ~bb)));
		cc = Bits::RotateLeft32(cc, 8);
		bb = bb + (data[8] + C1 + ((cc & aa) | (dd & ~aa)));
		bb = Bits::RotateLeft32(bb, 11);
		aa = aa + (data[1] + C1 + ((bb & dd) | (cc & ~dd)));
		aa = Bits::RotateLeft32(aa, 14);
		dd = dd + (data[10] + C1 + ((aa & cc) | (bb & ~cc)));
		dd = Bits::RotateLeft32(dd, 14);
		cc = cc + (data[3] + C1 + ((dd & bb) | (aa & ~bb)));
		cc = Bits::RotateLeft32(cc, 12);
		bb = bb + (data[12] + C1 + ((cc & aa) | (dd & ~aa)));
		bb = Bits::RotateLeft32(bb, 6);

		aa = aa + (data[7] + C2 + ((b & c) | (~b & d)));
		aa = Bits::RotateLeft32(aa, 7);
		d = d + (data[4] + C2 + ((aa & b) | (~aa & c)));
		d = Bits::RotateLeft32(d, 6);
		c = c + (data[13] + C2 + ((d & aa) | (~d & b)));
		c = Bits::RotateLeft32(c, 8);
		b = b + (data[1] + C2 + ((c & d) | (~c & aa)));
		b = Bits::RotateLeft32(b, 13);
		aa = aa + (data[10] + C2 + ((b & c) | (~b & d)));
		aa = Bits::RotateLeft32(aa, 11);
		d = d + (data[6] + C2 + ((aa & b) | (~aa & c)));
		d = Bits::RotateLeft32(d, 9);
		c = c + (data[15] + C2 + ((d & aa) | (~d & b)));
		c = Bits::RotateLeft32(c, 7);
		b = b + (data[3] + C2 + ((c & d) | (~c & aa)));
		b = Bits::RotateLeft32(b, 15);
		aa = aa + (data[12] + C2 + ((b & c) | (~b & d)));
		aa = Bits::RotateLeft32(aa, 7);
		d = d + (data[0] + C2 + ((aa & b) | (~aa & c)));
		d = Bits::RotateLeft32(d, 12);
		c = c + (data[9] + C2 + ((d & aa) | (~d & b)));
		c = Bits::RotateLeft32(c, 15);
		b = b + (data[5] + C2 + ((c & d) | (~c & aa)));
		b = Bits::RotateLeft32(b, 9);
		aa = aa + (data[2] + C2 + ((b & c) | (~b & d)));
		aa = Bits::RotateLeft32(aa, 11);
		d = d + (data[14] + C2 + ((aa & b) | (~aa & c)));
		d = Bits::RotateLeft32(d, 7);
		c = c + (data[11] + C2 + ((d & aa) | (~d & b)));
		c = Bits::RotateLeft32(c, 13);
		b = b + (data[8] + C2 + ((c & d) | (~c & aa)));
		b = Bits::RotateLeft32(b, 12);

		a = a + (data[6] + C3 + ((bb | ~cc) ^ dd));
		a = Bits::RotateLeft32(a, 9);
		dd = dd + (data[11] + C3 + ((a | ~bb) ^ cc));
		dd = Bits::RotateLeft32(dd, 13);
		cc = cc + (data[3] + C3 + ((dd | ~a) ^ bb));
		cc = Bits::RotateLeft32(cc, 15);
		bb = bb + (data[7] + C3 + ((cc | ~dd) ^ a));
		bb = Bits::RotateLeft32(bb, 7);
		a = a + (data[0] + C3 + ((bb | ~cc) ^ dd));
		a = Bits::RotateLeft32(a, 12);
		dd = dd + (data[13] + C3 + ((a | ~bb) ^ cc));
		dd = Bits::RotateLeft32(dd, 8);
		cc = cc + (data[5] + C3 + ((dd | ~a) ^ bb));
		cc = Bits::RotateLeft32(cc, 9);
		bb = bb + (data[10] + C3 + ((cc | ~dd) ^ a));
		bb = Bits::RotateLeft32(bb, 11);
		a = a + (data[14] + C3 + ((bb | ~cc) ^ dd));
		a = Bits::RotateLeft32(a, 7);
		dd = dd + (data[15] + C3 + ((a | ~bb) ^ cc));
		dd = Bits::RotateLeft32(dd, 7);
		cc = cc + (data[8] + C3 + ((dd | ~a) ^ bb));
		cc = Bits::RotateLeft32(cc, 12);
		bb = bb + (data[12] + C3 + ((cc | ~dd) ^ a));
		bb = Bits::RotateLeft32(bb, 7);
		a = a + (data[4] + C3 + ((bb | ~cc) ^ dd));
		a = Bits::RotateLeft32(a, 6);
		dd = dd + (data[9] + C3 + ((a | ~bb) ^ cc));
		dd = Bits::RotateLeft32(dd, 15);
		cc = cc + (data[1] + C3 + ((dd | ~a) ^ bb));
		cc = Bits::RotateLeft32(cc, 13);
		bb = bb + (data[2] + C3 + ((cc | ~dd) ^ a));
		bb = Bits::RotateLeft32(bb, 11);

		aa = aa + (data[3] + C4 + ((bb | ~c) ^ d));
		aa = Bits::RotateLeft32(aa, 11);
		d = d + (data[10] + C4 + ((aa | ~bb) ^ c));
		d = Bits::RotateLeft32(d, 13);
		c = c + (data[14] + C4 + ((d | ~aa) ^ bb));
		c = Bits::RotateLeft32(c, 6);
		bb = bb + (data[4] + C4 + ((c | ~d) ^ aa));
		bb = Bits::RotateLeft32(bb, 7);
		aa = aa + (data[9] + C4 + ((bb | ~c) ^ d));
		aa = Bits::RotateLeft32(aa, 14);
		d = d + (data[15] + C4 + ((aa | ~bb) ^ c));
		d = Bits::RotateLeft32(d, 9);
		c = c + (data[8] + C4 + ((d | ~aa) ^ bb));
		c = Bits::RotateLeft32(c, 13);
		bb = bb + (data[1] + C4 + ((c | ~d) ^ aa));
		bb = Bits::RotateLeft32(bb, 15);
		aa = aa + (data[2] + C4 + ((bb | ~c) ^ d));
		aa = Bits::RotateLeft32(aa, 14);
		d = d + (data[7] + C4 + ((aa | ~bb) ^ c));
		d = Bits::RotateLeft32(d, 8);
		c = c + (data[0] + C4 + ((d | ~aa) ^ bb));
		c = Bits::RotateLeft32(c, 13);
		bb = bb + (data[6] + C4 + ((c | ~d) ^ aa));
		bb = Bits::RotateLeft32(bb, 6);
		aa = aa + (data[13] + C4 + ((bb | ~c) ^ d));
		aa = Bits::RotateLeft32(aa, 5);
		d = d + (data[11] + C4 + ((aa | ~bb) ^ c));
		d = Bits::RotateLeft32(d, 12);
		c = c + (data[5] + C4 + ((d | ~aa) ^ bb));
		c = Bits::RotateLeft32(c, 7);
		bb = bb + (data[12] + C4 + ((c | ~d) ^ aa));
		bb = Bits::RotateLeft32(bb, 5);

		a = a + (data[15] + C5 + ((b & cc) | (~b & dd)));
		a = Bits::RotateLeft32(a, 9);
		dd = dd + (data[5] + C5 + ((a & b) | (~a & cc)));
		dd = Bits::RotateLeft32(dd, 7);
		cc = cc + (data[1] + C5 + ((dd & a) | (~dd & b)));
		cc = Bits::RotateLeft32(cc, 15);
		b = b + (data[3] + C5 + ((cc & dd) | (~cc & a)));
		b = Bits::RotateLeft32(b, 11);
		a = a + (data[7] + C5 + ((b & cc) | (~b & dd)));
		a = Bits::RotateLeft32(a, 8);
		dd = dd + (data[14] + C5 + ((a & b) | (~a & cc)));
		dd = Bits::RotateLeft32(dd, 6);
		cc = cc + (data[6] + C5 + ((dd & a) | (~dd & b)));
		cc = Bits::RotateLeft32(cc, 6);
		b = b + (data[9] + C5 + ((cc & dd) | (~cc & a)));
		b = Bits::RotateLeft32(b, 14);
		a = a + (data[11] + C5 + ((b & cc) | (~b & dd)));
		a = Bits::RotateLeft32(a, 12);
		dd = dd + (data[8] + C5 + ((a & b) | (~a & cc)));
		dd = Bits::RotateLeft32(dd, 13);
		cc = cc + (data[12] + C5 + ((dd & a) | (~dd & b)));
		cc = Bits::RotateLeft32(cc, 5);
		b = b + (data[2] + C5 + ((cc & dd) | (~cc & a)));
		b = Bits::RotateLeft32(b, 14);
		a = a + (data[10] + C5 + ((b & cc) | (~b & dd)));
		a = Bits::RotateLeft32(a, 13);
		dd = dd + (data[0] + C5 + ((a & b) | (~a & cc)));
		dd = Bits::RotateLeft32(dd, 13);
		cc = cc + (data[4] + C5 + ((dd & a) | (~dd & b)));
		cc = Bits::RotateLeft32(cc, 7);
		b = b + (data[13] + C5 + ((cc & dd) | (~cc & a)));
		b = Bits::RotateLeft32(b, 5);

		aa = aa + (data[1] + C6 + ((bb & d) | (cc & ~d)));
		aa = Bits::RotateLeft32(aa, 11);
		d = d + (data[9] + C6 + ((aa & cc) | (bb & ~cc)));
		d = Bits::RotateLeft32(d, 12);
		cc = cc + (data[11] + C6 + ((d & bb) | (aa & ~bb)));
		cc = Bits::RotateLeft32(cc, 14);
		bb = bb + (data[10] + C6 + ((cc & aa) | (d & ~aa)));
		bb = Bits::RotateLeft32(bb, 15);
		aa = aa + (data[0] + C6 + ((bb & d) | (cc & ~d)));
		aa = Bits::RotateLeft32(aa, 14);
		d = d + (data[8] + C6 + ((aa & cc) | (bb & ~cc)));
		d = Bits::RotateLeft32(d, 15);
		cc = cc + (data[12] + C6 + ((d & bb) | (aa & ~bb)));
		cc = Bits::RotateLeft32(cc, 9);
		bb = bb + (data[4] + C6 + ((cc & aa) | (d & ~aa)));
		bb = Bits::RotateLeft32(bb, 8);
		aa = aa + (data[13] + C6 + ((bb & d) | (cc & ~d)));
		aa = Bits::RotateLeft32(aa, 9);
		d = d + (data[3] + C6 + ((aa & cc) | (bb & ~cc)));
		d = Bits::RotateLeft32(d, 14);
		cc = cc + (data[7] + C6 + ((d & bb) | (aa & ~bb)));
		cc = Bits::RotateLeft32(cc, 5);
		bb = bb + (data[15] + C6 + ((cc & aa) | (d & ~aa)));
		bb = Bits::RotateLeft32(bb, 6);
		aa = aa + (data[14] + C6 + ((bb & d) | (cc & ~d)));
		aa = Bits::RotateLeft32(aa, 8);
		d = d + (data[5] + C6 + ((aa & cc) | (bb & ~cc)));
		d = Bits::RotateLeft32(d, 6);
		cc = cc + (data[6] + C6 + ((d & bb) | (aa & ~bb)));
		cc = Bits::RotateLeft32(cc, 5);
		bb = bb + (data[2] + C6 + ((cc & aa) | (d & ~aa)));
		bb = Bits::RotateLeft32(bb, 12);

		a = a + (data[8] + (b ^ c ^ dd));
		a = Bits::RotateLeft32(a, 15);
		dd = dd + (data[6] + (a ^ b ^ c));
		dd = Bits::RotateLeft32(dd, 5);
		c = c + (data[4] + (dd ^ a ^ b));
		c = Bits::RotateLeft32(c, 8);
		b = b + (data[1] + (c ^ dd ^ a));
		b = Bits::RotateLeft32(b, 11);
		a = a + (data[3] + (b ^ c ^ dd));
		a = Bits::RotateLeft32(a, 14);
		dd = dd + (data[11] + (a ^ b ^ c));
		dd = Bits::RotateLeft32(dd, 14);
		c = c + (data[15] + (dd ^ a ^ b));
		c = Bits::RotateLeft32(c, 6);
		b = b + (data[0] + (c ^ dd ^ a));
		b = Bits::RotateLeft32(b, 14);
		a = a + (data[5] + (b ^ c ^ dd));
		a = Bits::RotateLeft32(a, 6);
		dd = dd + (data[12] + (a ^ b ^ c));
		dd = Bits::RotateLeft32(dd, 9);
		c = c + (data[2] + (dd ^ a ^ b));
		c = Bits::RotateLeft32(c, 12);
		b = b + (data[13] + (c ^ dd ^ a));
		b = Bits::RotateLeft32(b, 9);
		a = a + (data[9] + (b ^ c ^ dd));
		a = Bits::RotateLeft32(a, 12);
		dd = dd + (data[7] + (a ^ b ^ c));
		dd = Bits::RotateLeft32(dd, 5);
		c = c + (data[10] + (dd ^ a ^ b));
		c = Bits::RotateLeft32(c, 15);
		b = b + (data[14] + (c ^ dd ^ a));
		b = Bits::RotateLeft32(b, 8);

		_state[0] = _state[0] + aa;
		_state[1] = _state[1] + bb;
		_state[2] = _state[2] + cc;
		_state[3] = _state[3] + dd;
		_state[4] = _state[4] + a;
		_state[5] = _state[5] + b;
		_state[6] = _state[6] + c;
		_state[7] = _state[7] + d;

		ArrayUtils::zeroFill(data);
	} // end function 
	
}; // end class RIPEMD256
