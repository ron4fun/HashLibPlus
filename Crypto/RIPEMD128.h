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

class RIPEMD128 : public MDBase, public virtual IITransformBlock
{
public:
	RIPEMD128()
		: MDBase(4, 16)
	{
		_name = __func__;
	} // end constructor

	virtual IHash Clone() const
	{
		RIPEMD128 HashInstance = RIPEMD128();
		HashInstance._state = _state;
		HashInstance._buffer = _buffer.Clone();
		HashInstance._processed_bytes = _processed_bytes;

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<RIPEMD128>(HashInstance);
	}

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
		aa = a;
		bb = b;
		cc = c;
		dd = d;

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

		a = a + (data[7] + C2 + ((b & c) | (~b & d)));
		a = Bits::RotateLeft32(a, 7);
		d = d + (data[4] + C2 + ((a & b) | (~a & c)));
		d = Bits::RotateLeft32(d, 6);
		c = c + (data[13] + C2 + ((d & a) | (~d & b)));
		c = Bits::RotateLeft32(c, 8);
		b = b + (data[1] + C2 + ((c & d) | (~c & a)));
		b = Bits::RotateLeft32(b, 13);
		a = a + (data[10] + C2 + ((b & c) | (~b & d)));
		a = Bits::RotateLeft32(a, 11);
		d = d + (data[6] + C2 + ((a & b) | (~a & c)));
		d = Bits::RotateLeft32(d, 9);
		c = c + (data[15] + C2 + ((d & a) | (~d & b)));
		c = Bits::RotateLeft32(c, 7);
		b = b + (data[3] + C2 + ((c & d) | (~c & a)));
		b = Bits::RotateLeft32(b, 15);
		a = a + (data[12] + C2 + ((b & c) | (~b & d)));
		a = Bits::RotateLeft32(a, 7);
		d = d + (data[0] + C2 + ((a & b) | (~a & c)));
		d = Bits::RotateLeft32(d, 12);
		c = c + (data[9] + C2 + ((d & a) | (~d & b)));
		c = Bits::RotateLeft32(c, 15);
		b = b + (data[5] + C2 + ((c & d) | (~c & a)));
		b = Bits::RotateLeft32(b, 9);
		a = a + (data[2] + C2 + ((b & c) | (~b & d)));
		a = Bits::RotateLeft32(a, 11);
		d = d + (data[14] + C2 + ((a & b) | (~a & c)));
		d = Bits::RotateLeft32(d, 7);
		c = c + (data[11] + C2 + ((d & a) | (~d & b)));
		c = Bits::RotateLeft32(c, 13);
		b = b + (data[8] + C2 + ((c & d) | (~c & a)));
		b = Bits::RotateLeft32(b, 12);

		a = a + (data[3] + C4 + ((b | ~c) ^ d));
		a = Bits::RotateLeft32(a, 11);
		d = d + (data[10] + C4 + ((a | ~b) ^ c));
		d = Bits::RotateLeft32(d, 13);
		c = c + (data[14] + C4 + ((d | ~a) ^ b));
		c = Bits::RotateLeft32(c, 6);
		b = b + (data[4] + C4 + ((c | ~d) ^ a));
		b = Bits::RotateLeft32(b, 7);
		a = a + (data[9] + C4 + ((b | ~c) ^ d));
		a = Bits::RotateLeft32(a, 14);
		d = d + (data[15] + C4 + ((a | ~b) ^ c));
		d = Bits::RotateLeft32(d, 9);
		c = c + (data[8] + C4 + ((d | ~a) ^ b));
		c = Bits::RotateLeft32(c, 13);
		b = b + (data[1] + C4 + ((c | ~d) ^ a));
		b = Bits::RotateLeft32(b, 15);
		a = a + (data[2] + C4 + ((b | ~c) ^ d));
		a = Bits::RotateLeft32(a, 14);
		d = d + (data[7] + C4 + ((a | ~b) ^ c));
		d = Bits::RotateLeft32(d, 8);
		c = c + (data[0] + C4 + ((d | ~a) ^ b));
		c = Bits::RotateLeft32(c, 13);
		b = b + (data[6] + C4 + ((c | ~d) ^ a));
		b = Bits::RotateLeft32(b, 6);
		a = a + (data[13] + C4 + ((b | ~c) ^ d));
		a = Bits::RotateLeft32(a, 5);
		d = d + (data[11] + C4 + ((a | ~b) ^ c));
		d = Bits::RotateLeft32(d, 12);
		c = c + (data[5] + C4 + ((d | ~a) ^ b));
		c = Bits::RotateLeft32(c, 7);
		b = b + (data[12] + C4 + ((c | ~d) ^ a));
		b = Bits::RotateLeft32(b, 5);

		a = a + (data[1] + C6 + ((b & d) | (c & ~d)));
		a = Bits::RotateLeft32(a, 11);
		d = d + (data[9] + C6 + ((a & c) | (b & ~c)));
		d = Bits::RotateLeft32(d, 12);
		c = c + (data[11] + C6 + ((d & b) | (a & ~b)));
		c = Bits::RotateLeft32(c, 14);
		b = b + (data[10] + C6 + ((c & a) | (d & ~a)));
		b = Bits::RotateLeft32(b, 15);
		a = a + (data[0] + C6 + ((b & d) | (c & ~d)));
		a = Bits::RotateLeft32(a, 14);
		d = d + (data[8] + C6 + ((a & c) | (b & ~c)));
		d = Bits::RotateLeft32(d, 15);
		c = c + (data[12] + C6 + ((d & b) | (a & ~b)));
		c = Bits::RotateLeft32(c, 9);
		b = b + (data[4] + C6 + ((c & a) | (d & ~a)));
		b = Bits::RotateLeft32(b, 8);
		a = a + (data[13] + C6 + ((b & d) | (c & ~d)));
		a = Bits::RotateLeft32(a, 9);
		d = d + (data[3] + C6 + ((a & c) | (b & ~c)));
		d = Bits::RotateLeft32(d, 14);
		c = c + (data[7] + C6 + ((d & b) | (a & ~b)));
		c = Bits::RotateLeft32(c, 5);
		b = b + (data[15] + C6 + ((c & a) | (d & ~a)));
		b = Bits::RotateLeft32(b, 6);
		a = a + (data[14] + C6 + ((b & d) | (c & ~d)));
		a = Bits::RotateLeft32(a, 8);
		d = d + (data[5] + C6 + ((a & c) | (b & ~c)));
		d = Bits::RotateLeft32(d, 6);
		c = c + (data[6] + C6 + ((d & b) | (a & ~b)));
		c = Bits::RotateLeft32(c, 5);
		b = b + (data[2] + C6 + ((c & a) | (d & ~a)));
		b = Bits::RotateLeft32(b, 12);

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

		aa = aa + (data[6] + C3 + ((bb | ~cc) ^ dd));
		aa = Bits::RotateLeft32(aa, 9);
		dd = dd + (data[11] + C3 + ((aa | ~bb) ^ cc));
		dd = Bits::RotateLeft32(dd, 13);
		cc = cc + (data[3] + C3 + ((dd | ~aa) ^ bb));
		cc = Bits::RotateLeft32(cc, 15);
		bb = bb + (data[7] + C3 + ((cc | ~dd) ^ aa));
		bb = Bits::RotateLeft32(bb, 7);
		aa = aa + (data[0] + C3 + ((bb | ~cc) ^ dd));
		aa = Bits::RotateLeft32(aa, 12);
		dd = dd + (data[13] + C3 + ((aa | ~bb) ^ cc));
		dd = Bits::RotateLeft32(dd, 8);
		cc = cc + (data[5] + C3 + ((dd | ~aa) ^ bb));
		cc = Bits::RotateLeft32(cc, 9);
		bb = bb + (data[10] + C3 + ((cc | ~dd) ^ aa));
		bb = Bits::RotateLeft32(bb, 11);
		aa = aa + (data[14] + C3 + ((bb | ~cc) ^ dd));
		aa = Bits::RotateLeft32(aa, 7);
		dd = dd + (data[15] + C3 + ((aa | ~bb) ^ cc));
		dd = Bits::RotateLeft32(dd, 7);
		cc = cc + (data[8] + C3 + ((dd | ~aa) ^ bb));
		cc = Bits::RotateLeft32(cc, 12);
		bb = bb + (data[12] + C3 + ((cc | ~dd) ^ aa));
		bb = Bits::RotateLeft32(bb, 7);
		aa = aa + (data[4] + C3 + ((bb | ~cc) ^ dd));
		aa = Bits::RotateLeft32(aa, 6);
		dd = dd + (data[9] + C3 + ((aa | ~bb) ^ cc));
		dd = Bits::RotateLeft32(dd, 15);
		cc = cc + (data[1] + C3 + ((dd | ~aa) ^ bb));
		cc = Bits::RotateLeft32(cc, 13);
		bb = bb + (data[2] + C3 + ((cc | ~dd) ^ aa));
		bb = Bits::RotateLeft32(bb, 11);

		aa = aa + (data[15] + C5 + ((bb & cc) | (~bb & dd)));
		aa = Bits::RotateLeft32(aa, 9);
		dd = dd + (data[5] + C5 + ((aa & bb) | (~aa & cc)));
		dd = Bits::RotateLeft32(dd, 7);
		cc = cc + (data[1] + C5 + ((dd & aa) | (~dd & bb)));
		cc = Bits::RotateLeft32(cc, 15);
		bb = bb + (data[3] + C5 + ((cc & dd) | (~cc & aa)));
		bb = Bits::RotateLeft32(bb, 11);
		aa = aa + (data[7] + C5 + ((bb & cc) | (~bb & dd)));
		aa = Bits::RotateLeft32(aa, 8);
		dd = dd + (data[14] + C5 + ((aa & bb) | (~aa & cc)));
		dd = Bits::RotateLeft32(dd, 6);
		cc = cc + (data[6] + C5 + ((dd & aa) | (~dd & bb)));
		cc = Bits::RotateLeft32(cc, 6);
		bb = bb + (data[9] + C5 + ((cc & dd) | (~cc & aa)));
		bb = Bits::RotateLeft32(bb, 14);
		aa = aa + (data[11] + C5 + ((bb & cc) | (~bb & dd)));
		aa = Bits::RotateLeft32(aa, 12);
		dd = dd + (data[8] + C5 + ((aa & bb) | (~aa & cc)));
		dd = Bits::RotateLeft32(dd, 13);
		cc = cc + (data[12] + C5 + ((dd & aa) | (~dd & bb)));
		cc = Bits::RotateLeft32(cc, 5);
		bb = bb + (data[2] + C5 + ((cc & dd) | (~cc & aa)));
		bb = Bits::RotateLeft32(bb, 14);
		aa = aa + (data[10] + C5 + ((bb & cc) | (~bb & dd)));
		aa = Bits::RotateLeft32(aa, 13);
		dd = dd + (data[0] + C5 + ((aa & bb) | (~aa & cc)));
		dd = Bits::RotateLeft32(dd, 13);
		cc = cc + (data[4] + C5 + ((dd & aa) | (~dd & bb)));
		cc = Bits::RotateLeft32(cc, 7);
		bb = bb + (data[13] + C5 + ((cc & dd) | (~cc & aa)));
		bb = Bits::RotateLeft32(bb, 5);

		aa = aa + (data[8] + (bb ^ cc ^ dd));
		aa = Bits::RotateLeft32(aa, 15);
		dd = dd + (data[6] + (aa ^ bb ^ cc));
		dd = Bits::RotateLeft32(dd, 5);
		cc = cc + (data[4] + (dd ^ aa ^ bb));
		cc = Bits::RotateLeft32(cc, 8);
		bb = bb + (data[1] + (cc ^ dd ^ aa));
		bb = Bits::RotateLeft32(bb, 11);
		aa = aa + (data[3] + (bb ^ cc ^ dd));
		aa = Bits::RotateLeft32(aa, 14);
		dd = dd + (data[11] + (aa ^ bb ^ cc));
		dd = Bits::RotateLeft32(dd, 14);
		cc = cc + (data[15] + (dd ^ aa ^ bb));
		cc = Bits::RotateLeft32(cc, 6);
		bb = bb + (data[0] + (cc ^ dd ^ aa));
		bb = Bits::RotateLeft32(bb, 14);
		aa = aa + (data[5] + (bb ^ cc ^ dd));
		aa = Bits::RotateLeft32(aa, 6);
		dd = dd + (data[12] + (aa ^ bb ^ cc));
		dd = Bits::RotateLeft32(dd, 9);
		cc = cc + (data[2] + (dd ^ aa ^ bb));
		cc = Bits::RotateLeft32(cc, 12);
		bb = bb + (data[13] + (cc ^ dd ^ aa));
		bb = Bits::RotateLeft32(bb, 9);
		aa = aa + (data[9] + (bb ^ cc ^ dd));
		aa = Bits::RotateLeft32(aa, 12);
		dd = dd + (data[7] + (aa ^ bb ^ cc));
		dd = Bits::RotateLeft32(dd, 5);
		cc = cc + (data[10] + (dd ^ aa ^ bb));
		cc = Bits::RotateLeft32(cc, 15);
		bb = bb + (data[14] + (cc ^ dd ^ aa));
		bb = Bits::RotateLeft32(bb, 8);

		dd = dd + c + _state[1];
		_state[1] = _state[2] + d + aa;
		_state[2] = _state[3] + a + bb;
		_state[3] = _state[0] + b + cc;
		_state[0] = dd;

		ArrayUtils::zeroFill(data);
	} // end function 

}; // end class RIPEMD128
