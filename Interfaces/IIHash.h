#ifndef IHASH_H
#define IHASH_H

#include <fstream>
#include "Utils/HashLibTypes.h"
//#include "Interfaces/IHashResult.h"

class IIHash
{
public:
	virtual string GetName() const = 0;
	virtual Int32 GetBlockSize() const = 0;
	virtual Int32 GetHashSize() const = 0;
	virtual Int32 GetBufferSize() const = 0;
	virtual void SetBufferSize(const Int32 value) = 0;

	virtual IHash& Clone() const = 0;

	virtual IHashResult& ComputeString(const string& a_data) = 0;
	virtual IHashResult& ComputeBytes(const HashLibByteArray& a_data) = 0;
	virtual IHashResult& ComputeUntyped(const void* a_data, const Int64 a_length) = 0;
	virtual IHashResult& ComputeStream(ifstream& a_stream, const Int64 a_length = -1) = 0;
	virtual IHashResult& ComputeFile(const string& a_file_name,
		const Int64 a_from = 0, const Int64 a_length = -1) = 0;

	virtual void Initialize() = 0;

	virtual void TransformBytes(const HashLibByteArray& a_data, Int32 a_index, Int32 a_length) = 0;
	virtual void TransformBytes(const HashLibByteArray& a_data, const Int32 a_index) = 0;
	virtual void TransformBytes(const HashLibByteArray& a_data) = 0;

	virtual void TransformUntyped(const void* a_data, const Int64 a_length) = 0;

	virtual IHashResult& TransformFinal() = 0;

	virtual void TransformString(const string& a_data) = 0;
	virtual void TransformStream(ifstream& a_stream, const Int64 a_length = -1) = 0;
	virtual void TransformFile(const string& a_file_name,
		const Int64 a_from = 0, const Int64 a_length = -1) = 0;
};

#endif // !IHASH_H
