#pragma once

#include "../Base/Hash.h"
#include "../Interfaces/IHashInfo.h"

class FNV1a_64 : public Hash, public virtual IIBlockHash, 
	public virtual IIHash64, public virtual IITransformBlock
{
public:
	FNV1a_64()
		: Hash(8, 1)
	{
		_name = __func__;
	} // end constructor

	virtual IHash Clone() const
	{
		FNV1a_64 HashInstance = FNV1a_64();
		HashInstance._hash = _hash;

		HashInstance.SetBufferSize(GetBufferSize());

		return make_shared<FNV1a_64>(HashInstance);
	}

	virtual void Initialize()
	{
		_hash = 14695981039346656037;
	} // end function Initialize

	virtual IHashResult TransformFinal()
	{
		IHashResult result = make_shared<HashResult>(_hash);

		Initialize();

		return result;
	} // end function TransformFinal

	virtual void TransformBytes(const HashLibByteArray& a_data, const Int32 a_index, const Int32 a_length)
	{
		register uint32_t i = a_index, length = a_length;

		while (length > 0)
		{
			_hash = (_hash ^ a_data[i]) * 1099511628211;
			i++;
			length--;
		} // end while
	} // end function TransformBytes

private:
	UInt64 _hash;

}; // end class FNV1a_64
