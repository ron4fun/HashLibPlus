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

#include <typeinfo>
#include "../Interfaces/IHash.h"
#include "HashResult.h"
#include "../Interfaces/IHash.h"
#include "..//Utils/HashLibTypes.h"
#include "../Utils/Utils.h"
#include "../Enum/HashSize.h"

class Hash : public virtual IIHash
{
private:
	static const char* IndexOutOfRange;
	static const char* InvalidBufferSize;
	static const char* UnAssignedStream;
	static const char* FileNotExist;
	static const char* CloneNotYetImplemented;
	static const char* DeleteNotYetImplemented;
protected:
	string _name;

public:
	Hash() 
		: _block_size(0), _hash_size(0), _buffer_size(BUFFER_SIZE)
	{}

	Hash(const Int32 a_hash_size, const Int32 a_block_size)
		: _block_size(a_block_size), _hash_size(a_hash_size), _buffer_size(BUFFER_SIZE)
	{
		_name = __func__;
	} // end constructor

	// Copy constructor
	Hash(const Hash& hash2)
	{
		_name = hash2._name;
		_buffer_size = hash2._buffer_size;
		_block_size = hash2._block_size;
		_hash_size = hash2._hash_size;
	}

	virtual string GetName() const  
	{
		return _name;
	} //

	virtual Int32 GetBufferSize() const 
	{
		return _buffer_size;
	} // end function GetBufferSize

	virtual void SetBufferSize(const Int32 value) 
	{
		if (value > 0)
		{
			_buffer_size = value;
		} // end if
		else
		{
			throw ArgumentHashLibException(InvalidBufferSize);
		} // end else
	} // end function SetBufferSize

	virtual Int32 GetBlockSize() const 
	{
		return _block_size;
	} // end function GetBlockSize

	virtual void SetBlockSize(const Int32 value)
	{
		_block_size = value;
	}

	virtual Int32 GetHashSize() const 
	{
		return _hash_size;
	} // end function GetHashSize

	virtual void SetHashSize(const Int32 value)
	{
		_hash_size = value;
	}

	virtual IHash Clone() const
	{
		throw NotImplementedHashLibException(Utils::string_format(CloneNotYetImplemented, GetName().c_str()));
	}

	virtual IHashResult ComputeString(const string& a_data) 
	{
		return ComputeBytes(Converters::ConvertStringToBytes(a_data));
	} // end function ComputeString

	virtual IHashResult ComputeUntyped(const void* a_data, const Int64 a_length) 
	{
		Initialize();
		TransformUntyped(a_data, a_length);
		return TransformFinal();
	} // end function ComputeUntyped

	virtual void TransformUntyped(const void* a_data, const Int64 a_length) 
	{
		byte* PtrBuffer, * PtrEnd;
		HashLibByteArray ArrBuffer;
		Int32 LBufferSize;

		PtrBuffer = (byte*)a_data;

		if (_buffer_size > a_length) // Sanity Check
			LBufferSize = BUFFER_SIZE;
		else
			LBufferSize = _buffer_size;

		if (PtrBuffer)
		{
			ArrBuffer.resize(LBufferSize);
			PtrEnd = (PtrBuffer)+a_length;

			while (PtrBuffer < PtrEnd)
			{
				if ((PtrEnd - PtrBuffer) >= LBufferSize)
				{
					memmove(&ArrBuffer[0], PtrBuffer, LBufferSize);
					TransformBytes(ArrBuffer);
					PtrBuffer += LBufferSize;
				} // end if
				else
				{
					ArrBuffer.resize(PtrEnd - PtrBuffer);
					memmove(&ArrBuffer[0], PtrBuffer, ArrBuffer.size());
					TransformBytes(ArrBuffer);
					break;
				} // end else
			} // end while

		} // end if

	} // end function TransformUntyped

	virtual IHashResult ComputeStream(ifstream& a_stream, const Int64 a_length = -1) 
	{
		Initialize();
		TransformStream(a_stream, a_length);
		return TransformFinal();
	} // end function ComputeStream

	virtual IHashResult ComputeFile(const string& a_file_name,
		const Int64 a_from = 0, const Int64 a_length = -1) 
	{
		Initialize();
		TransformFile(a_file_name, a_from, a_length);
		return TransformFinal();
	} // end function ComputeFile

	virtual IHashResult ComputeBytes(const HashLibByteArray& a_data) 
	{
		Initialize();
		TransformBytes(a_data);
		return TransformFinal();
	} // end function ComputeBytes

	virtual void TransformString(const string& a_data) 
	{
		TransformBytes(Converters::ConvertStringToBytes(a_data));
	} // end function TransformString

	virtual void TransformBytes(const HashLibByteArray& a_data) 
	{
		TransformBytes(a_data, 0, (Int32)a_data.size());
	} // end function TransformBytes

	virtual void TransformBytes(const HashLibByteArray& a_data, const Int32 a_index) 
	{
		Int32 Length = (Int32)a_data.size() - a_index;
		TransformBytes(a_data, a_index, Length);
	} // end function TransformBytes

	virtual void TransformBytes(const HashLibByteArray& a_data, const Int32 a_index, const Int32 a_length) = 0;

	virtual void TransformStream(ifstream& a_stream, const Int64 a_length = -1) 
	{
		Int32 readed = 0, LBufferSize;
		UInt64 size, new_size;
		Int64 total;

		total = 0;
		size = GetStreamSize(a_stream);

		if (a_stream)
		{
			if (a_length > -1)
			{
				if (UInt64(a_stream.tellg() + a_length) > size)
					throw IndexOutOfRangeHashLibException(IndexOutOfRange);
			} // end if

			if ((UInt64)a_stream.tellg() >= size)
				return;
		} // end if
		else
			throw ArgumentNullHashLibException(UnAssignedStream);


		if (size > BUFFER_SIZE)
		{
			if (a_length == -1) LBufferSize = BUFFER_SIZE;
			else
			{
				LBufferSize = (Int32)(a_length > BUFFER_SIZE ? BUFFER_SIZE : a_length);
			}
		}
		else
		{
			LBufferSize = (Int32)(a_length == -1 ? size : a_length);
		}

		HashLibByteArray data = HashLibByteArray(LBufferSize);

		if (LBufferSize == BUFFER_SIZE)
		{
			while (true)
			{
				a_stream.read((char*)& data[0], LBufferSize);

				readed = (Int32)a_stream.gcount();
				if (readed != BUFFER_SIZE)
				{
					data.resize(readed);

					TransformBytes(data, 0, readed);

					break;
				}

				if (readed == 0) break;

				total = total + readed;

				TransformBytes(data, 0, readed);

				if (a_length != -1 && a_length - total <= BUFFER_SIZE)
				{
					new_size = a_length - total;
					data.resize((Int32)new_size);

					a_stream.read((char*)& data[0], new_size);

					TransformBytes(data, 0, (Int32)new_size);
					break;
				}

			} // end while
		}
		else
		{
			a_stream.read((char*)& data[0], LBufferSize);

			TransformBytes(data, 0, LBufferSize);
		}
	} // end function TransformStream

	virtual void TransformFile(const string& a_file_name,
		const Int64 a_from, const Int64 a_length) 
	{
		ifstream ReadFile;
		ReadFile.open(a_file_name.c_str(), ios::in | ios::binary);

		if (!ReadFile.is_open())
			throw ArgumentHashLibException(FileNotExist);

		ReadFile.seekg(a_from, ios::beg);

		TransformStream(ReadFile, a_length);

		ReadFile.close();
	} // end function TransformFile

private:
	static streampos GetStreamSize(ifstream& a_stream)
	{
		streampos pos = a_stream.tellg();

		streampos fsize = pos;
		a_stream.seekg(pos, ios::end);
		fsize = a_stream.tellg() - fsize;

		a_stream.seekg(pos, ios::beg); // return cur to original pos

		return fsize;
	} // end function GetStreamSize

protected:
	Int32 _buffer_size;
	Int32 _block_size;
	Int32 _hash_size;

	static const Int32 BUFFER_SIZE = Int32(64 * 1024); // 64Kb
	
}; // end class Hash
