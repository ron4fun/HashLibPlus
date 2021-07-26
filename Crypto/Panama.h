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

#include "../Base/HashCryptoNotBuildIn.h"

class Panama : public BlockHash, public virtual IICryptoNotBuildIn, public virtual IITransformBlock
{
public:
	Panama()
		: BlockHash(32, 32)
	{
		_name = __func__;

		_tap = 0;
		_state.resize(17);
		_theta.resize(17);
		_gamma.resize(17);
		_pi.resize(17);
		_work_buffer.resize(17);

		_stages.resize(32);
		for (UInt32 i = 0; i < 32; i++)
			_stages[i] = HashLibUInt32Array(8);

	} // end constructor

	virtual IHash Clone() const
	{
		Panama HashInstance = Panama();
		HashInstance._state = _state;
		HashInstance._theta = _theta;
		HashInstance._gamma = _gamma;
		HashInstance._pi = _pi;

		HashInstance._stages = _stages;

		HashInstance._tap = _tap;
		HashInstance._buffer = _buffer.Clone();
		HashInstance._processed_bytes = _processed_bytes;

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<Panama>(HashInstance);
	}

	virtual void Initialize()
	{
		ArrayUtils::zeroFill(_state);

		for (UInt32 i = 0; i < 32; i++)
			ArrayUtils::zeroFill(_stages[i]);

		BlockHash::Initialize();
	} // end function Initialize

protected:
	virtual void Finish()
	{
		Int32 tap4, tap16, tap25;

		Int32 padding_size = 32 - (_processed_bytes & 31);

		HashLibByteArray pad = HashLibByteArray(padding_size);

		pad[0] = 0x01;
		TransformBytes(pad, 0, padding_size);

		HashLibUInt32Array theta = HashLibUInt32Array(17);

		UInt32* ptr_theta = &theta[0];

		for (UInt32 i = 0; i < 32; i++)
		{
			tap4 = (_tap + 4) & 0x1F;
			tap16 = (_tap + 16) & 0x1F;

			_tap = (_tap - 1) & 0x1F;
			tap25 = (_tap + 25) & 0x1F;

			GPT(ptr_theta);

			_stages[tap25][0] = _stages[tap25][0] ^ _stages[_tap][2];
			_stages[tap25][1] = _stages[tap25][1] ^ _stages[_tap][3];
			_stages[tap25][2] = _stages[tap25][2] ^ _stages[_tap][4];
			_stages[tap25][3] = _stages[tap25][3] ^ _stages[_tap][5];
			_stages[tap25][4] = _stages[tap25][4] ^ _stages[_tap][6];
			_stages[tap25][5] = _stages[tap25][5] ^ _stages[_tap][7];
			_stages[tap25][6] = _stages[tap25][6] ^ _stages[_tap][0];
			_stages[tap25][7] = _stages[tap25][7] ^ _stages[_tap][1];
			_stages[_tap][0] = _stages[_tap][0] ^ _state[1];
			_stages[_tap][1] = _stages[_tap][1] ^ _state[2];
			_stages[_tap][2] = _stages[_tap][2] ^ _state[3];
			_stages[_tap][3] = _stages[_tap][3] ^ _state[4];
			_stages[_tap][4] = _stages[_tap][4] ^ _state[5];
			_stages[_tap][5] = _stages[_tap][5] ^ _state[6];
			_stages[_tap][6] = _stages[_tap][6] ^ _state[7];
			_stages[_tap][7] = _stages[_tap][7] ^ _state[8];

			_state[0] = theta[0] ^ 0x01;
			_state[1] = theta[1] ^ _stages[tap4][0];
			_state[2] = theta[2] ^ _stages[tap4][1];
			_state[3] = theta[3] ^ _stages[tap4][2];
			_state[4] = theta[4] ^ _stages[tap4][3];
			_state[5] = theta[5] ^ _stages[tap4][4];
			_state[6] = theta[6] ^ _stages[tap4][5];
			_state[7] = theta[7] ^ _stages[tap4][6];
			_state[8] = theta[8] ^ _stages[tap4][7];
			_state[9] = theta[9] ^ _stages[tap16][0];
			_state[10] = theta[10] ^ _stages[tap16][1];
			_state[11] = theta[11] ^ _stages[tap16][2];
			_state[12] = theta[12] ^ _stages[tap16][3];
			_state[13] = theta[13] ^ _stages[tap16][4];
			_state[14] = theta[14] ^ _stages[tap16][5];
			_state[15] = theta[15] ^ _stages[tap16][6];
			_state[16] = theta[16] ^ _stages[tap16][7];

		} // end for

	} // end function Finish

	virtual HashLibByteArray GetResult()
	{
		HashLibByteArray result = HashLibByteArray(8 * sizeof(UInt32));

		Converters::le32_copy(&_state[0] + 9, 0, &result[0], 0, (Int32)result.size());

		return result;
	} // end function GetResult

	virtual void TransformBlock(const uint8_t* a_data,
		const Int32 a_data_length, const Int32 a_index)
	{
		UInt32 tap16, tap25;

		Converters::le32_copy(a_data, a_index, &_work_buffer[0], 0, 32);

		tap16 = (_tap + 16) & 0x1F;

		_tap = (_tap - 1) & 0x1F;
		tap25 = (_tap + 25) & 0x1F;

		GPT((UInt32*)&_theta[0]);

		_stages[tap25][0] = _stages[tap25][0] ^ _stages[_tap][2];
		_stages[tap25][1] = _stages[tap25][1] ^ _stages[_tap][3];
		_stages[tap25][2] = _stages[tap25][2] ^ _stages[_tap][4];
		_stages[tap25][3] = _stages[tap25][3] ^ _stages[_tap][5];
		_stages[tap25][4] = _stages[tap25][4] ^ _stages[_tap][6];
		_stages[tap25][5] = _stages[tap25][5] ^ _stages[_tap][7];
		_stages[tap25][6] = _stages[tap25][6] ^ _stages[_tap][0];
		_stages[tap25][7] = _stages[tap25][7] ^ _stages[_tap][1];
		_stages[_tap][0] = _stages[_tap][0] ^ _work_buffer[0];
		_stages[_tap][1] = _stages[_tap][1] ^ _work_buffer[1];
		_stages[_tap][2] = _stages[_tap][2] ^ _work_buffer[2];
		_stages[_tap][3] = _stages[_tap][3] ^ _work_buffer[3];
		_stages[_tap][4] = _stages[_tap][4] ^ _work_buffer[4];
		_stages[_tap][5] = _stages[_tap][5] ^ _work_buffer[5];
		_stages[_tap][6] = _stages[_tap][6] ^ _work_buffer[6];
		_stages[_tap][7] = _stages[_tap][7] ^ _work_buffer[7];

		_state[0] = _theta[0] ^ 0x01;
		_state[1] = _theta[1] ^ _work_buffer[0];
		_state[2] = _theta[2] ^ _work_buffer[1];
		_state[3] = _theta[3] ^ _work_buffer[2];
		_state[4] = _theta[4] ^ _work_buffer[3];
		_state[5] = _theta[5] ^ _work_buffer[4];
		_state[6] = _theta[6] ^ _work_buffer[5];
		_state[7] = _theta[7] ^ _work_buffer[6];
		_state[8] = _theta[8] ^ _work_buffer[7];
		_state[9] = _theta[9] ^ _stages[tap16][0];
		_state[10] = _theta[10] ^ _stages[tap16][1];
		_state[11] = _theta[11] ^ _stages[tap16][2];
		_state[12] = _theta[12] ^ _stages[tap16][3];
		_state[13] = _theta[13] ^ _stages[tap16][4];
		_state[14] = _theta[14] ^ _stages[tap16][5];
		_state[15] = _theta[15] ^ _stages[tap16][6];
		_state[16] = _theta[16] ^ _stages[tap16][7];

		ArrayUtils::zeroFill(_work_buffer);

	} // end function TransformBlock

private:
	inline void GPT(UInt32* a_theta)
	{
		_gamma[0] = _state[0] ^ (_state[1] | ~_state[2]);
		_gamma[1] = _state[1] ^ (_state[2] | ~_state[3]);
		_gamma[2] = _state[2] ^ (_state[3] | ~_state[4]);
		_gamma[3] = _state[3] ^ (_state[4] | ~_state[5]);
		_gamma[4] = _state[4] ^ (_state[5] | ~_state[6]);
		_gamma[5] = _state[5] ^ (_state[6] | ~_state[7]);
		_gamma[6] = _state[6] ^ (_state[7] | ~_state[8]);
		_gamma[7] = _state[7] ^ (_state[8] | ~_state[9]);
		_gamma[8] = _state[8] ^ (_state[9] | ~_state[10]);
		_gamma[9] = _state[9] ^ (_state[10] | ~_state[11]);
		_gamma[10] = _state[10] ^ (_state[11] | ~_state[12]);
		_gamma[11] = _state[11] ^ (_state[12] | ~_state[13]);
		_gamma[12] = _state[12] ^ (_state[13] | ~_state[14]);
		_gamma[13] = _state[13] ^ (_state[14] | ~_state[15]);
		_gamma[14] = _state[14] ^ (_state[15] | ~_state[16]);
		_gamma[15] = _state[15] ^ (_state[16] | ~_state[0]);
		_gamma[16] = _state[16] ^ (_state[0] | ~_state[1]);

		_pi[0] = _gamma[0];
		_pi[1] = Bits::RotateLeft32(_gamma[7], 1);
		_pi[2] = Bits::RotateLeft32(_gamma[14], 3);
		_pi[3] = Bits::RotateLeft32(_gamma[4], 6);
		_pi[4] = Bits::RotateLeft32(_gamma[11], 10);
		_pi[5] = Bits::RotateLeft32(_gamma[1], 15);
		_pi[6] = Bits::RotateLeft32(_gamma[8], 21);
		_pi[7] = Bits::RotateLeft32(_gamma[15], 28);
		_pi[8] = Bits::RotateLeft32(_gamma[5], 4);
		_pi[9] = Bits::RotateLeft32(_gamma[12], 13);
		_pi[10] = Bits::RotateLeft32(_gamma[2], 23);
		_pi[11] = Bits::RotateLeft32(_gamma[9], 2);
		_pi[12] = Bits::RotateLeft32(_gamma[16], 14);
		_pi[13] = Bits::RotateLeft32(_gamma[6], 27);
		_pi[14] = Bits::RotateLeft32(_gamma[13], 9);
		_pi[15] = Bits::RotateLeft32(_gamma[3], 24);
		_pi[16] = Bits::RotateLeft32(_gamma[10], 8);

		a_theta[0] = _pi[0] ^ _pi[1] ^ _pi[4];
		a_theta[1] = _pi[1] ^ _pi[2] ^ _pi[5];
		a_theta[2] = _pi[2] ^ _pi[3] ^ _pi[6];
		a_theta[3] = _pi[3] ^ _pi[4] ^ _pi[7];
		a_theta[4] = _pi[4] ^ _pi[5] ^ _pi[8];
		a_theta[5] = _pi[5] ^ _pi[6] ^ _pi[9];
		a_theta[6] = _pi[6] ^ _pi[7] ^ _pi[10];
		a_theta[7] = _pi[7] ^ _pi[8] ^ _pi[11];
		a_theta[8] = _pi[8] ^ _pi[9] ^ _pi[12];
		a_theta[9] = _pi[9] ^ _pi[10] ^ _pi[13];
		a_theta[10] = _pi[10] ^ _pi[11] ^ _pi[14];
		a_theta[11] = _pi[11] ^ _pi[12] ^ _pi[15];
		a_theta[12] = _pi[12] ^ _pi[13] ^ _pi[16];
		a_theta[13] = _pi[13] ^ _pi[14] ^ _pi[0];
		a_theta[14] = _pi[14] ^ _pi[15] ^ _pi[1];
		a_theta[15] = _pi[15] ^ _pi[16] ^ _pi[2];
		a_theta[16] = _pi[16] ^ _pi[0] ^ _pi[3];
	} // end function GPT

private:
	HashLibUInt32Array _state, _theta, _gamma, _pi, _work_buffer;

	HashLibMatrixUInt32Array _stages;

	Int32 _tap;

}; // end class Panama
