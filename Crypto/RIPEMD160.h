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

class RIPEMD160 : public MDBase, public virtual IITransformBlock
{
public:
	RIPEMD160()
		: MDBase(5, 20)
	{
		_name = __func__;
	} // end constructor

	virtual IHash Clone() const
	{
		RIPEMD160 HashInstance = RIPEMD160();
		HashInstance._state = _state;
		HashInstance._buffer = _buffer.Clone();
		HashInstance._processed_bytes = _processed_bytes;

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<RIPEMD160>(HashInstance);
	}

	virtual void Initialize()
	{
		_state[4] = 0xC3D2E1F0;

		MDBase::Initialize();
	} // end function Initialize

protected:
	virtual void TransformBlock(const byte* a_data,
		const Int32 a_data_length, const Int32 a_index)
	{
		UInt32 a, b, c, d, e, aa, bb, cc, dd, ee;

		HashLibUInt32Array data = HashLibUInt32Array(16);

		Converters::le32_copy(a_data, a_index, &data[0], 0, 64);

		a = _state[0];
		b = _state[1];
		c = _state[2];
		d = _state[3];
		e = _state[4];
		aa = a;
		bb = b;
		cc = c;
		dd = d;
		ee = e;

		a = a + (data[0] + (b ^ c ^ d));
		a = Bits::RotateLeft32(a, 11) + e;
		c = Bits::RotateLeft32(c, 10);
		e = e + (data[1] + (a ^ b ^ c));
		e = Bits::RotateLeft32(e, 14) + d;
		b = Bits::RotateLeft32(b, 10);
		d = d + (data[2] + (e ^ a ^ b));
		d = Bits::RotateLeft32(d, 15) + c;
		a = Bits::RotateLeft32(a, 10);
		c = c + (data[3] + (d ^ e ^ a));
		c = Bits::RotateLeft32(c, 12) + b;
		e = Bits::RotateLeft32(e, 10);
		b = b + (data[4] + (c ^ d ^ e));
		b = Bits::RotateLeft32(b, 5) + a;
		d = Bits::RotateLeft32(d, 10);
		a = a + (data[5] + (b ^ c ^ d));
		a = Bits::RotateLeft32(a, 8) + e;
		c = Bits::RotateLeft32(c, 10);
		e = e + (data[6] + (a ^ b ^ c));
		e = Bits::RotateLeft32(e, 7) + d;
		b = Bits::RotateLeft32(b, 10);
		d = d + (data[7] + (e ^ a ^ b));
		d = Bits::RotateLeft32(d, 9) + c;
		a = Bits::RotateLeft32(a, 10);
		c = c + (data[8] + (d ^ e ^ a));
		c = Bits::RotateLeft32(c, 11) + b;
		e = Bits::RotateLeft32(e, 10);
		b = b + (data[9] + (c ^ d ^ e));
		b = Bits::RotateLeft32(b, 13) + a;
		d = Bits::RotateLeft32(d, 10);
		a = a + (data[10] + (b ^ c ^ d));
		a = Bits::RotateLeft32(a, 14) + e;
		c = Bits::RotateLeft32(c, 10);
		e = e + (data[11] + (a ^ b ^ c));
		e = Bits::RotateLeft32(e, 15) + d;
		b = Bits::RotateLeft32(b, 10);
		d = d + (data[12] + (e ^ a ^ b));
		d = Bits::RotateLeft32(d, 6) + c;
		a = Bits::RotateLeft32(a, 10);
		c = c + (data[13] + (d ^ e ^ a));
		c = Bits::RotateLeft32(c, 7) + b;
		e = Bits::RotateLeft32(e, 10);
		b = b + (data[14] + (c ^ d ^ e));
		b = Bits::RotateLeft32(b, 9) + a;
		d = Bits::RotateLeft32(d, 10);
		a = a + (data[15] + (b ^ c ^ d));
		a = Bits::RotateLeft32(a, 8) + e;
		c = Bits::RotateLeft32(c, 10);

		aa = aa + (data[5] + C1 + (bb ^ (cc | ~dd)));
		aa = Bits::RotateLeft32(aa, 8) + ee;
		cc = Bits::RotateLeft32(cc, 10);
		ee = ee + (data[14] + C1 + (aa ^ (bb | ~cc)));
		ee = Bits::RotateLeft32(ee, 9) + dd;
		bb = Bits::RotateLeft32(bb, 10);
		dd = dd + (data[7] + C1 + (ee ^ (aa | ~bb)));
		dd = Bits::RotateLeft32(dd, 9) + cc;
		aa = Bits::RotateLeft32(aa, 10);
		cc = cc + (data[0] + C1 + (dd ^ (ee | ~aa)));
		cc = Bits::RotateLeft32(cc, 11) + bb;
		ee = Bits::RotateLeft32(ee, 10);
		bb = bb + (data[9] + C1 + (cc ^ (dd | ~ee)));
		bb = Bits::RotateLeft32(bb, 13) + aa;
		dd = Bits::RotateLeft32(dd, 10);
		aa = aa + (data[2] + C1 + (bb ^ (cc | ~dd)));
		aa = Bits::RotateLeft32(aa, 15) + ee;
		cc = Bits::RotateLeft32(cc, 10);
		ee = ee + (data[11] + C1 + (aa ^ (bb | ~cc)));
		ee = Bits::RotateLeft32(ee, 15) + dd;
		bb = Bits::RotateLeft32(bb, 10);
		dd = dd + (data[4] + C1 + (ee ^ (aa | ~bb)));
		dd = Bits::RotateLeft32(dd, 5) + cc;
		aa = Bits::RotateLeft32(aa, 10);
		cc = cc + (data[13] + C1 + (dd ^ (ee | ~aa)));
		cc = Bits::RotateLeft32(cc, 7) + bb;
		ee = Bits::RotateLeft32(ee, 10);
		bb = bb + (data[6] + C1 + (cc ^ (dd | ~ee)));
		bb = Bits::RotateLeft32(bb, 7) + aa;
		dd = Bits::RotateLeft32(dd, 10);
		aa = aa + (data[15] + C1 + (bb ^ (cc | ~dd)));
		aa = Bits::RotateLeft32(aa, 8) + ee;
		cc = Bits::RotateLeft32(cc, 10);
		ee = ee + (data[8] + C1 + (aa ^ (bb | ~cc)));
		ee = Bits::RotateLeft32(ee, 11) + dd;
		bb = Bits::RotateLeft32(bb, 10);
		dd = dd + (data[1] + C1 + (ee ^ (aa | ~bb)));
		dd = Bits::RotateLeft32(dd, 14) + cc;
		aa = Bits::RotateLeft32(aa, 10);
		cc = cc + (data[10] + C1 + (dd ^ (ee | ~aa)));
		cc = Bits::RotateLeft32(cc, 14) + bb;
		ee = Bits::RotateLeft32(ee, 10);
		bb = bb + (data[3] + C1 + (cc ^ (dd | ~ee)));
		bb = Bits::RotateLeft32(bb, 12) + aa;
		dd = Bits::RotateLeft32(dd, 10);
		aa = aa + (data[12] + C1 + (bb ^ (cc | ~dd)));
		aa = Bits::RotateLeft32(aa, 6) + ee;
		cc = Bits::RotateLeft32(cc, 10);

		e = e + (data[7] + C2 + ((a & b) | (~a & c)));
		e = Bits::RotateLeft32(e, 7) + d;
		b = Bits::RotateLeft32(b, 10);
		d = d + (data[4] + C2 + ((e & a) | (~e & b)));
		d = Bits::RotateLeft32(d, 6) + c;
		a = Bits::RotateLeft32(a, 10);
		c = c + (data[13] + C2 + ((d & e) | (~d & a)));
		c = Bits::RotateLeft32(c, 8) + b;
		e = Bits::RotateLeft32(e, 10);
		b = b + (data[1] + C2 + ((c & d) | (~c & e)));
		b = Bits::RotateLeft32(b, 13) + a;
		d = Bits::RotateLeft32(d, 10);
		a = a + (data[10] + C2 + ((b & c) | (~b & d)));
		a = Bits::RotateLeft32(a, 11) + e;
		c = Bits::RotateLeft32(c, 10);
		e = e + (data[6] + C2 + ((a & b) | (~a & c)));
		e = Bits::RotateLeft32(e, 9) + d;
		b = Bits::RotateLeft32(b, 10);
		d = d + (data[15] + C2 + ((e & a) | (~e & b)));
		d = Bits::RotateLeft32(d, 7) + c;
		a = Bits::RotateLeft32(a, 10);
		c = c + (data[3] + C2 + ((d & e) | (~d & a)));
		c = Bits::RotateLeft32(c, 15) + b;
		e = Bits::RotateLeft32(e, 10);
		b = b + (data[12] + C2 + ((c & d) | (~c & e)));
		b = Bits::RotateLeft32(b, 7) + a;
		d = Bits::RotateLeft32(d, 10);
		a = a + (data[0] + C2 + ((b & c) | (~b & d)));
		a = Bits::RotateLeft32(a, 12) + e;
		c = Bits::RotateLeft32(c, 10);
		e = e + (data[9] + C2 + ((a & b) | (~a & c)));
		e = Bits::RotateLeft32(e, 15) + d;
		b = Bits::RotateLeft32(b, 10);
		d = d + (data[5] + C2 + ((e & a) | (~e & b)));
		d = Bits::RotateLeft32(d, 9) + c;
		a = Bits::RotateLeft32(a, 10);
		c = c + (data[2] + C2 + ((d & e) | (~d & a)));
		c = Bits::RotateLeft32(c, 11) + b;
		e = Bits::RotateLeft32(e, 10);
		b = b + (data[14] + C2 + ((c & d) | (~c & e)));
		b = Bits::RotateLeft32(b, 7) + a;
		d = Bits::RotateLeft32(d, 10);
		a = a + (data[11] + C2 + ((b & c) | (~b & d)));
		a = Bits::RotateLeft32(a, 13) + e;
		c = Bits::RotateLeft32(c, 10);
		e = e + (data[8] + C2 + ((a & b) | (~a & c)));
		e = Bits::RotateLeft32(e, 12) + d;
		b = Bits::RotateLeft32(b, 10);

		ee = ee + (data[6] + C3 + ((aa & cc) | (bb & ~cc)));
		ee = Bits::RotateLeft32(ee, 9) + dd;
		bb = Bits::RotateLeft32(bb, 10);
		dd = dd + (data[11] + C3 + ((ee & bb) | (aa & ~bb)));
		dd = Bits::RotateLeft32(dd, 13) + cc;
		aa = Bits::RotateLeft32(aa, 10);
		cc = cc + (data[3] + C3 + ((dd & aa) | (ee & ~aa)));
		cc = Bits::RotateLeft32(cc, 15) + bb;
		ee = Bits::RotateLeft32(ee, 10);
		bb = bb + (data[7] + C3 + ((cc & ee) | (dd & ~ee)));
		bb = Bits::RotateLeft32(bb, 7) + aa;
		dd = Bits::RotateLeft32(dd, 10);
		aa = aa + (data[0] + C3 + ((bb & dd) | (cc & ~dd)));
		aa = Bits::RotateLeft32(aa, 12) + ee;
		cc = Bits::RotateLeft32(cc, 10);
		ee = ee + (data[13] + C3 + ((aa & cc) | (bb & ~cc)));
		ee = Bits::RotateLeft32(ee, 8) + dd;
		bb = Bits::RotateLeft32(bb, 10);
		dd = dd + (data[5] + C3 + ((ee & bb) | (aa & ~bb)));
		dd = Bits::RotateLeft32(dd, 9) + cc;
		aa = Bits::RotateLeft32(aa, 10);
		cc = cc + (data[10] + C3 + ((dd & aa) | (ee & ~aa)));
		cc = Bits::RotateLeft32(cc, 11) + bb;
		ee = Bits::RotateLeft32(ee, 10);
		bb = bb + (data[14] + C3 + ((cc & ee) | (dd & ~ee)));
		bb = Bits::RotateLeft32(bb, 7) + aa;
		dd = Bits::RotateLeft32(dd, 10);
		aa = aa + (data[15] + C3 + ((bb & dd) | (cc & ~dd)));
		aa = Bits::RotateLeft32(aa, 7) + ee;
		cc = Bits::RotateLeft32(cc, 10);
		ee = ee + (data[8] + C3 + ((aa & cc) | (bb & ~cc)));
		ee = Bits::RotateLeft32(ee, 12) + dd;
		bb = Bits::RotateLeft32(bb, 10);
		dd = dd + (data[12] + C3 + ((ee & bb) | (aa & ~bb)));
		dd = Bits::RotateLeft32(dd, 7) + cc;
		aa = Bits::RotateLeft32(aa, 10);
		cc = cc + (data[4] + C3 + ((dd & aa) | (ee & ~aa)));
		cc = Bits::RotateLeft32(cc, 6) + bb;
		ee = Bits::RotateLeft32(ee, 10);
		bb = bb + (data[9] + C3 + ((cc & ee) | (dd & ~ee)));
		bb = Bits::RotateLeft32(bb, 15) + aa;
		dd = Bits::RotateLeft32(dd, 10);
		aa = aa + (data[1] + C3 + ((bb & dd) | (cc & ~dd)));
		aa = Bits::RotateLeft32(aa, 13) + ee;
		cc = Bits::RotateLeft32(cc, 10);
		ee = ee + (data[2] + C3 + ((aa & cc) | (bb & ~cc)));
		ee = Bits::RotateLeft32(ee, 11) + dd;
		bb = Bits::RotateLeft32(bb, 10);

		d = d + (data[3] + C4 + ((e | ~a) ^ b));
		d = Bits::RotateLeft32(d, 11) + c;
		a = Bits::RotateLeft32(a, 10);
		c = c + (data[10] + C4 + ((d | ~e) ^ a));
		c = Bits::RotateLeft32(c, 13) + b;
		e = Bits::RotateLeft32(e, 10);
		b = b + (data[14] + C4 + ((c | ~d) ^ e));
		b = Bits::RotateLeft32(b, 6) + a;
		d = Bits::RotateLeft32(d, 10);
		a = a + (data[4] + C4 + ((b | ~c) ^ d));
		a = Bits::RotateLeft32(a, 7) + e;
		c = Bits::RotateLeft32(c, 10);
		e = e + (data[9] + C4 + ((a | ~b) ^ c));
		e = Bits::RotateLeft32(e, 14) + d;
		b = Bits::RotateLeft32(b, 10);
		d = d + (data[15] + C4 + ((e | ~a) ^ b));
		d = Bits::RotateLeft32(d, 9) + c;
		a = Bits::RotateLeft32(a, 10);
		c = c + (data[8] + C4 + ((d | ~e) ^ a));
		c = Bits::RotateLeft32(c, 13) + b;
		e = Bits::RotateLeft32(e, 10);
		b = b + (data[1] + C4 + ((c | ~d) ^ e));
		b = Bits::RotateLeft32(b, 15) + a;
		d = Bits::RotateLeft32(d, 10);
		a = a + (data[2] + C4 + ((b | ~c) ^ d));
		a = Bits::RotateLeft32(a, 14) + e;
		c = Bits::RotateLeft32(c, 10);
		e = e + (data[7] + C4 + ((a | ~b) ^ c));
		e = Bits::RotateLeft32(e, 8) + d;
		b = Bits::RotateLeft32(b, 10);
		d = d + (data[0] + C4 + ((e | ~a) ^ b));
		d = Bits::RotateLeft32(d, 13) + c;
		a = Bits::RotateLeft32(a, 10);
		c = c + (data[6] + C4 + ((d | ~e) ^ a));
		c = Bits::RotateLeft32(c, 6) + b;
		e = Bits::RotateLeft32(e, 10);
		b = b + (data[13] + C4 + ((c | ~d) ^ e));
		b = Bits::RotateLeft32(b, 5) + a;
		d = Bits::RotateLeft32(d, 10);
		a = a + (data[11] + C4 + ((b | ~c) ^ d));
		a = Bits::RotateLeft32(a, 12) + e;
		c = Bits::RotateLeft32(c, 10);
		e = e + (data[5] + C4 + ((a | ~b) ^ c));
		e = Bits::RotateLeft32(e, 7) + d;
		b = Bits::RotateLeft32(b, 10);
		d = d + (data[12] + C4 + ((e | ~a) ^ b));
		d = Bits::RotateLeft32(d, 5) + c;
		a = Bits::RotateLeft32(a, 10);

		dd = dd + (data[15] + C5 + ((ee | ~aa) ^ bb));
		dd = Bits::RotateLeft32(dd, 9) + cc;
		aa = Bits::RotateLeft32(aa, 10);
		cc = cc + (data[5] + C5 + ((dd | ~ee) ^ aa));
		cc = Bits::RotateLeft32(cc, 7) + bb;
		ee = Bits::RotateLeft32(ee, 10);
		bb = bb + (data[1] + C5 + ((cc | ~dd) ^ ee));
		bb = Bits::RotateLeft32(bb, 15) + aa;
		dd = Bits::RotateLeft32(dd, 10);
		aa = aa + (data[3] + C5 + ((bb | ~cc) ^ dd));
		aa = Bits::RotateLeft32(aa, 11) + ee;
		cc = Bits::RotateLeft32(cc, 10);
		ee = ee + (data[7] + C5 + ((aa | ~bb) ^ cc));
		ee = Bits::RotateLeft32(ee, 8) + dd;
		bb = Bits::RotateLeft32(bb, 10);
		dd = dd + (data[14] + C5 + ((ee | ~aa) ^ bb));
		dd = Bits::RotateLeft32(dd, 6) + cc;
		aa = Bits::RotateLeft32(aa, 10);
		cc = cc + (data[6] + C5 + ((dd | ~ee) ^ aa));
		cc = Bits::RotateLeft32(cc, 6) + bb;
		ee = Bits::RotateLeft32(ee, 10);
		bb = bb + (data[9] + C5 + ((cc | ~dd) ^ ee));
		bb = Bits::RotateLeft32(bb, 14) + aa;
		dd = Bits::RotateLeft32(dd, 10);
		aa = aa + (data[11] + C5 + ((bb | ~cc) ^ dd));
		aa = Bits::RotateLeft32(aa, 12) + ee;
		cc = Bits::RotateLeft32(cc, 10);
		ee = ee + (data[8] + C5 + ((aa | ~bb) ^ cc));
		ee = Bits::RotateLeft32(ee, 13) + dd;
		bb = Bits::RotateLeft32(bb, 10);
		dd = dd + (data[12] + C5 + ((ee | ~aa) ^ bb));
		dd = Bits::RotateLeft32(dd, 5) + cc;
		aa = Bits::RotateLeft32(aa, 10);
		cc = cc + (data[2] + C5 + ((dd | ~ee) ^ aa));
		cc = Bits::RotateLeft32(cc, 14) + bb;
		ee = Bits::RotateLeft32(ee, 10);
		bb = bb + (data[10] + C5 + ((cc | ~dd) ^ ee));
		bb = Bits::RotateLeft32(bb, 13) + aa;
		dd = Bits::RotateLeft32(dd, 10);
		aa = aa + (data[0] + C5 + ((bb | ~cc) ^ dd));
		aa = Bits::RotateLeft32(aa, 13) + ee;
		cc = Bits::RotateLeft32(cc, 10);
		ee = ee + (data[4] + C5 + ((aa | ~bb) ^ cc));
		ee = Bits::RotateLeft32(ee, 7) + dd;
		bb = Bits::RotateLeft32(bb, 10);
		dd = dd + (data[13] + C5 + ((ee | ~aa) ^ bb));
		dd = Bits::RotateLeft32(dd, 5) + cc;
		aa = Bits::RotateLeft32(aa, 10);

		c = c + (data[1] + C6 + ((d & a) | (e & ~a)));
		c = Bits::RotateLeft32(c, 11) + b;
		e = Bits::RotateLeft32(e, 10);
		b = b + (data[9] + C6 + ((c & e) | (d & ~e)));
		b = Bits::RotateLeft32(b, 12) + a;
		d = Bits::RotateLeft32(d, 10);
		a = a + (data[11] + C6 + ((b & d) | (c & ~d)));
		a = Bits::RotateLeft32(a, 14) + e;
		c = Bits::RotateLeft32(c, 10);
		e = e + (data[10] + C6 + ((a & c) | (b & ~c)));
		e = Bits::RotateLeft32(e, 15) + d;
		b = Bits::RotateLeft32(b, 10);
		d = d + (data[0] + C6 + ((e & b) | (a & ~b)));
		d = Bits::RotateLeft32(d, 14) + c;
		a = Bits::RotateLeft32(a, 10);
		c = c + (data[8] + C6 + ((d & a) | (e & ~a)));
		c = Bits::RotateLeft32(c, 15) + b;
		e = Bits::RotateLeft32(e, 10);
		b = b + (data[12] + C6 + ((c & e) | (d & ~e)));
		b = Bits::RotateLeft32(b, 9) + a;
		d = Bits::RotateLeft32(d, 10);
		a = a + (data[4] + C6 + ((b & d) | (c & ~d)));
		a = Bits::RotateLeft32(a, 8) + e;
		c = Bits::RotateLeft32(c, 10);
		e = e + (data[13] + C6 + ((a & c) | (b & ~c)));
		e = Bits::RotateLeft32(e, 9) + d;
		b = Bits::RotateLeft32(b, 10);
		d = d + (data[3] + C6 + ((e & b) | (a & ~b)));
		d = Bits::RotateLeft32(d, 14) + c;
		a = Bits::RotateLeft32(a, 10);
		c = c + (data[7] + C6 + ((d & a) | (e & ~a)));
		c = Bits::RotateLeft32(c, 5) + b;
		e = Bits::RotateLeft32(e, 10);
		b = b + (data[15] + C6 + ((c & e) | (d & ~e)));
		b = Bits::RotateLeft32(b, 6) + a;
		d = Bits::RotateLeft32(d, 10);
		a = a + (data[14] + C6 + ((b & d) | (c & ~d)));
		a = Bits::RotateLeft32(a, 8) + e;
		c = Bits::RotateLeft32(c, 10);
		e = e + (data[5] + C6 + ((a & c) | (b & ~c)));
		e = Bits::RotateLeft32(e, 6) + d;
		b = Bits::RotateLeft32(b, 10);
		d = d + (data[6] + C6 + ((e & b) | (a & ~b)));
		d = Bits::RotateLeft32(d, 5) + c;
		a = Bits::RotateLeft32(a, 10);
		c = c + (data[2] + C6 + ((d & a) | (e & ~a)));
		c = Bits::RotateLeft32(c, 12) + b;
		e = Bits::RotateLeft32(e, 10);

		cc = cc + (data[8] + C7 + ((dd & ee) | (~dd & aa)));
		cc = Bits::RotateLeft32(cc, 15) + bb;
		ee = Bits::RotateLeft32(ee, 10);
		bb = bb + (data[6] + C7 + ((cc & dd) | (~cc & ee)));
		bb = Bits::RotateLeft32(bb, 5) + aa;
		dd = Bits::RotateLeft32(dd, 10);
		aa = aa + (data[4] + C7 + ((bb & cc) | (~bb & dd)));
		aa = Bits::RotateLeft32(aa, 8) + ee;
		cc = Bits::RotateLeft32(cc, 10);
		ee = ee + (data[1] + C7 + ((aa & bb) | (~aa & cc)));
		ee = Bits::RotateLeft32(ee, 11) + dd;
		bb = Bits::RotateLeft32(bb, 10);
		dd = dd + (data[3] + C7 + ((ee & aa) | (~ee & bb)));
		dd = Bits::RotateLeft32(dd, 14) + cc;
		aa = Bits::RotateLeft32(aa, 10);
		cc = cc + (data[11] + C7 + ((dd & ee) | (~dd & aa)));
		cc = Bits::RotateLeft32(cc, 14) + bb;
		ee = Bits::RotateLeft32(ee, 10);
		bb = bb + (data[15] + C7 + ((cc & dd) | (~cc & ee)));
		bb = Bits::RotateLeft32(bb, 6) + aa;
		dd = Bits::RotateLeft32(dd, 10);
		aa = aa + (data[0] + C7 + ((bb & cc) | (~bb & dd)));
		aa = Bits::RotateLeft32(aa, 14) + ee;
		cc = Bits::RotateLeft32(cc, 10);
		ee = ee + (data[5] + C7 + ((aa & bb) | (~aa & cc)));
		ee = Bits::RotateLeft32(ee, 6) + dd;
		bb = Bits::RotateLeft32(bb, 10);
		dd = dd + (data[12] + C7 + ((ee & aa) | (~ee & bb)));
		dd = Bits::RotateLeft32(dd, 9) + cc;
		aa = Bits::RotateLeft32(aa, 10);
		cc = cc + (data[2] + C7 + ((dd & ee) | (~dd & aa)));
		cc = Bits::RotateLeft32(cc, 12) + bb;
		ee = Bits::RotateLeft32(ee, 10);
		bb = bb + (data[13] + C7 + ((cc & dd) | (~cc & ee)));
		bb = Bits::RotateLeft32(bb, 9) + aa;
		dd = Bits::RotateLeft32(dd, 10);
		aa = aa + (data[9] + C7 + ((bb & cc) | (~bb & dd)));
		aa = Bits::RotateLeft32(aa, 12) + ee;
		cc = Bits::RotateLeft32(cc, 10);
		ee = ee + (data[7] + C7 + ((aa & bb) | (~aa & cc)));
		ee = Bits::RotateLeft32(ee, 5) + dd;
		bb = Bits::RotateLeft32(bb, 10);
		dd = dd + (data[10] + C7 + ((ee & aa) | (~ee & bb)));
		dd = Bits::RotateLeft32(dd, 15) + cc;
		aa = Bits::RotateLeft32(aa, 10);
		cc = cc + (data[14] + C7 + ((dd & ee) | (~dd & aa)));
		cc = Bits::RotateLeft32(cc, 8) + bb;
		ee = Bits::RotateLeft32(ee, 10);

		b = b + (data[4] + C8 + (c ^ (d | ~e)));
		b = Bits::RotateLeft32(b, 9) + a;
		d = Bits::RotateLeft32(d, 10);
		a = a + (data[0] + C8 + (b ^ (c | ~d)));
		a = Bits::RotateLeft32(a, 15) + e;
		c = Bits::RotateLeft32(c, 10);
		e = e + (data[5] + C8 + (a ^ (b | ~c)));
		e = Bits::RotateLeft32(e, 5) + d;
		b = Bits::RotateLeft32(b, 10);
		d = d + (data[9] + C8 + (e ^ (a | ~b)));
		d = Bits::RotateLeft32(d, 11) + c;
		a = Bits::RotateLeft32(a, 10);
		c = c + (data[7] + C8 + (d ^ (e | ~a)));
		c = Bits::RotateLeft32(c, 6) + b;
		e = Bits::RotateLeft32(e, 10);
		b = b + (data[12] + C8 + (c ^ (d | ~e)));
		b = Bits::RotateLeft32(b, 8) + a;
		d = Bits::RotateLeft32(d, 10);
		a = a + (data[2] + C8 + (b ^ (c | ~d)));
		a = Bits::RotateLeft32(a, 13) + e;
		c = Bits::RotateLeft32(c, 10);
		e = e + (data[10] + C8 + (a ^ (b | ~c)));
		e = Bits::RotateLeft32(e, 12) + d;
		b = Bits::RotateLeft32(b, 10);
		d = d + (data[14] + C8 + (e ^ (a | ~b)));
		d = Bits::RotateLeft32(d, 5) + c;
		a = Bits::RotateLeft32(a, 10);
		c = c + (data[1] + C8 + (d ^ (e | ~a)));
		c = Bits::RotateLeft32(c, 12) + b;
		e = Bits::RotateLeft32(e, 10);
		b = b + (data[3] + C8 + (c ^ (d | ~e)));
		b = Bits::RotateLeft32(b, 13) + a;
		d = Bits::RotateLeft32(d, 10);
		a = a + (data[8] + C8 + (b ^ (c | ~d)));
		a = Bits::RotateLeft32(a, 14) + e;
		c = Bits::RotateLeft32(c, 10);
		e = e + (data[11] + C8 + (a ^ (b | ~c)));
		e = Bits::RotateLeft32(e, 11) + d;
		b = Bits::RotateLeft32(b, 10);
		d = d + (data[6] + C8 + (e ^ (a | ~b)));
		d = Bits::RotateLeft32(d, 8) + c;
		a = Bits::RotateLeft32(a, 10);
		c = c + (data[15] + C8 + (d ^ (e | ~a)));
		c = Bits::RotateLeft32(c, 5) + b;
		e = Bits::RotateLeft32(e, 10);
		b = b + (data[13] + C8 + (c ^ (d | ~e)));
		b = Bits::RotateLeft32(b, 6) + a;
		d = Bits::RotateLeft32(d, 10);

		bb = bb + (data[12] + (cc ^ dd ^ ee));
		bb = Bits::RotateLeft32(bb, 8) + aa;
		dd = Bits::RotateLeft32(dd, 10);
		aa = aa + (data[15] + (bb ^ cc ^ dd));
		aa = Bits::RotateLeft32(aa, 5) + ee;
		cc = Bits::RotateLeft32(cc, 10);
		ee = ee + (data[10] + (aa ^ bb ^ cc));
		ee = Bits::RotateLeft32(ee, 12) + dd;
		bb = Bits::RotateLeft32(bb, 10);
		dd = dd + (data[4] + (ee ^ aa ^ bb));
		dd = Bits::RotateLeft32(dd, 9) + cc;
		aa = Bits::RotateLeft32(aa, 10);
		cc = cc + (data[1] + (dd ^ ee ^ aa));
		cc = Bits::RotateLeft32(cc, 12) + bb;
		ee = Bits::RotateLeft32(ee, 10);
		bb = bb + (data[5] + (cc ^ dd ^ ee));
		bb = Bits::RotateLeft32(bb, 5) + aa;
		dd = Bits::RotateLeft32(dd, 10);
		aa = aa + (data[8] + (bb ^ cc ^ dd));
		aa = Bits::RotateLeft32(aa, 14) + ee;
		cc = Bits::RotateLeft32(cc, 10);
		ee = ee + (data[7] + (aa ^ bb ^ cc));
		ee = Bits::RotateLeft32(ee, 6) + dd;
		bb = Bits::RotateLeft32(bb, 10);
		dd = dd + (data[6] + (ee ^ aa ^ bb));
		dd = Bits::RotateLeft32(dd, 8) + cc;
		aa = Bits::RotateLeft32(aa, 10);
		cc = cc + (data[2] + (dd ^ ee ^ aa));
		cc = Bits::RotateLeft32(cc, 13) + bb;
		ee = Bits::RotateLeft32(ee, 10);
		bb = bb + (data[13] + (cc ^ dd ^ ee));
		bb = Bits::RotateLeft32(bb, 6) + aa;
		dd = Bits::RotateLeft32(dd, 10);
		aa = aa + (data[14] + (bb ^ cc ^ dd));
		aa = Bits::RotateLeft32(aa, 5) + ee;
		cc = Bits::RotateLeft32(cc, 10);
		ee = ee + (data[0] + (aa ^ bb ^ cc));
		ee = Bits::RotateLeft32(ee, 15) + dd;
		bb = Bits::RotateLeft32(bb, 10);
		dd = dd + (data[3] + (ee ^ aa ^ bb));
		dd = Bits::RotateLeft32(dd, 13) + cc;
		aa = Bits::RotateLeft32(aa, 10);
		cc = cc + (data[9] + (dd ^ ee ^ aa));
		cc = Bits::RotateLeft32(cc, 11) + bb;
		ee = Bits::RotateLeft32(ee, 10);
		bb = bb + (data[11] + (cc ^ dd ^ ee));
		bb = Bits::RotateLeft32(bb, 11) + aa;
		dd = Bits::RotateLeft32(dd, 10);

		dd = dd + c + _state[1];
		_state[1] = _state[2] + d + ee;
		_state[2] = _state[3] + e + aa;
		_state[3] = _state[4] + a + bb;
		_state[4] = _state[0] + b + cc;
		_state[0] = dd;

		ArrayUtils::zeroFill(data);
	} // end function 

}; // end class RIPEMD160
