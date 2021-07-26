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

#include "../Interfaces/IBlake2BConfigurations/IBlake2BConfig.h"
#include "../Interfaces/IBlake2BConfigurations/IBlake2BTreeConfig.h"
#include "../Utils/Converters.h"
#include "../Enum/HashSize.h"
#include "../Utils/HashLibTypes.h"
#include "../Utils/ArrayUtils.h"
#include "../Utils/Utils.h"

class Blake2BErrorStrings
{
public:
	static const char* InvalidHashSize;
	static const char* InvalidKeyLength;
	static const char* InvalidPersonalizationLength;
	static const char* InvalidSaltLength;
	static const char* InvalidInnerHashSize;
	static const char* InvalidMaxDepth;
}; // !Blake2BErrorStrings

class Blake2BConfig : public virtual IIBlake2BConfig
{
public:
	Blake2BConfig(const HashSize& a_hash_size = HashSize::HashSize512)
	{
		ValidateHashSize(a_hash_size);
		_hash_size = a_hash_size;
	}

	Blake2BConfig(const Int32 a_hash_size)
	{
		ValidateHashSize(a_hash_size);
		_hash_size = a_hash_size;
	}
	
	static IBlake2BConfig CreateBlake2BConfig(const Int32 a_hash_size = HashSize::HashSize512)
	{
		return make_shared<Blake2BConfig>(a_hash_size);
	}

	~Blake2BConfig()
	{
		Clear();
	}

	static IBlake2BConfig GetDefaultConfig()
	{
		return make_shared<Blake2BConfig>();
	}

	virtual HashLibByteArray GetPersonalization() const
	{
		return _personalisation;
	}

	virtual void SetPersonalization(const HashLibByteArray& value)
	{
		ValidatePersonalisationLength(value);
		_personalisation = value;
	}

	virtual HashLibByteArray GetSalt() const
	{
		return _salt;
	}

	virtual void SetSalt(const HashLibByteArray& value)
	{
		ValidateSaltLength(value);
		_salt = value;
	}

	virtual HashLibByteArray GetKey() const
	{
		return _key;
	}

	virtual void SetKey(const HashLibByteArray& value)
	{
		ValidateKeyLength(value);
		_key = value;
	}

	virtual Int32 GetHashSize() const
	{
		return _hash_size;
	}

	virtual void SetHashSize(const Int32 value)
	{
		ValidateHashSize(value);
		_hash_size = value;
	}

	virtual IBlake2BConfig Clone() const
	{
		Blake2BConfig result = Blake2BConfig(GetHashSize());
		result._key = _key;
		result._personalisation = _personalisation;
		result._salt = _salt;

		return make_shared<Blake2BConfig>(result);
	}

	virtual void Clear()
	{
		ArrayUtils::zeroFill(_key);
		ArrayUtils::zeroFill(_salt);
		ArrayUtils::zeroFill(_personalisation);
	}

private:
	inline void ValidateHashSize(const Int32 a_hash_size)
	{
		if (a_hash_size < 1 || a_hash_size > 64)
			throw ArgumentOutOfRangeHashLibException(Utils::string_format(Blake2BErrorStrings::InvalidHashSize, a_hash_size));
	}

	inline void ValidateKeyLength(const HashLibByteArray& a_Key)
	{
		size_t KeyLength = a_Key.size();
		if (KeyLength > 64)
			throw ArgumentOutOfRangeHashLibException(Utils::string_format(Blake2BErrorStrings::InvalidKeyLength, KeyLength));
	}

	inline void ValidatePersonalisationLength(const HashLibByteArray& a_Personalisation)
	{
		size_t PersonalisationLength = a_Personalisation.size();
		if (PersonalisationLength != 0 && PersonalisationLength != 16)
			throw ArgumentOutOfRangeHashLibException(Utils::string_format(Blake2BErrorStrings::InvalidPersonalizationLength, PersonalisationLength));
	}

	inline void ValidateSaltLength(const HashLibByteArray& a_Salt)
	{
		size_t SaltLength = a_Salt.size();
		if (SaltLength != 0 && SaltLength != 16)
			throw ArgumentOutOfRangeHashLibException(Utils::string_format(Blake2BErrorStrings::InvalidSaltLength, SaltLength));
	}


private:
	Int32 _hash_size;
	HashLibByteArray _personalisation, _salt, _key;

}; // !Blake2BConfig

class Blake2BTreeConfig : public virtual IIBlake2BTreeConfig
{
public:
	Blake2BTreeConfig()
		: _fanOut(0), 
		_maxDepth(0), 
		_nodeDepth(0), 
		_innerHashSize(64),
		_leafSize(64),
		_nodeOffset(0),
		_isLastNode(false)
	{}

	static IBlake2BTreeConfig CreateBlake2BTreeConfig()
	{
		return make_shared<Blake2BTreeConfig>();
	}

	static IBlake2BTreeConfig GetSequentialTreeConfig()
	{
		Blake2BTreeConfig result = Blake2BTreeConfig();
		result._fanOut = 1;
		result._maxDepth = 1;
		result._leafSize = 0;
		result._nodeOffset = 0;
		result._nodeDepth = 0;
		result._innerHashSize = 0;
		result._isLastNode = false;

		return make_shared<Blake2BTreeConfig>(result);
	}

	static IBlake2BTreeConfig GetDefaultTreeConfig() 
	{
		return make_shared<Blake2BTreeConfig>();
	}

	virtual byte GetFanOut() const
	{
		return _fanOut;
	}

	virtual void SetFanOut(const byte value)
	{
		_fanOut = value;
	}

	virtual byte GetInnerHashSize() const
	{
		return _innerHashSize;
	}

	virtual void SetInnerHashSize(const byte value)
	{
		if (value > 64)
			throw ArgumentOutOfRangeHashLibException(Utils::string_format(Blake2BErrorStrings::InvalidInnerHashSize, value));

		_innerHashSize = value;
	}

	virtual byte GetMaxDepth() const
	{
		return _maxDepth;
	}

	virtual void SetMaxDepth(const byte value)
	{
		if (value < 1)
			throw ArgumentOutOfRangeHashLibException(Utils::string_format(Blake2BErrorStrings::InvalidMaxDepth, value));

		_maxDepth = value;
	}

	virtual byte GetNodeDepth() const
	{
		return _nodeDepth;
	}

	virtual void SetNodeDepth(const byte value)
	{
		_nodeDepth = value;
	}

	virtual UInt32 GetLeafSize() const
	{
		return _leafSize;
	}

	virtual void SetLeafSize(const UInt32 value)
	{
		_leafSize = value;
	}

	virtual UInt64 GetNodeOffset() const
	{
		return _nodeOffset;
	}

	virtual void SetNodeOffset(const UInt64 value)
	{
		_nodeOffset = value;
	}

	virtual bool GetIsLastNode() const
	{
		return _isLastNode;
	}

	virtual void SetIsLastNode(const bool value)
	{
		_isLastNode = value;
	}

	virtual IBlake2BTreeConfig Clone() const
	{
		Blake2BTreeConfig result = Blake2BTreeConfig();
		result._fanOut = _fanOut;
		result._innerHashSize = _innerHashSize;
		result._maxDepth = _maxDepth;
		result._nodeDepth = _nodeDepth;
		result._leafSize = _leafSize;
		result._nodeOffset = _nodeOffset;
		result._isLastNode = _isLastNode;

		return make_shared<Blake2BTreeConfig>(result);
	}

private:
	byte _fanOut, _maxDepth, _nodeDepth, _innerHashSize;
	UInt32 _leafSize;
	UInt64 _nodeOffset;
	bool _isLastNode;

}; // end class Blake2BTreeConfig

class Blake2BIvBuilder
{
public:
	static HashLibUInt64Array ConfigB(const IBlake2BConfig a_Config, IBlake2BTreeConfig a_TreeConfig)
	{
		bool isSequential;
		HashLibByteArray buffer;

		isSequential = a_TreeConfig == nullptr;
		if (isSequential)
			a_TreeConfig = Blake2BTreeConfig::GetSequentialTreeConfig();

		VerifyConfigB(a_Config, a_TreeConfig, isSequential);

		buffer.resize(64);

		buffer[0] = (byte)a_Config->GetHashSize();
		buffer[1] = (byte)a_Config->GetKey().size();

		if (a_TreeConfig != nullptr)
		{
			buffer[2] = (byte)a_TreeConfig->GetFanOut();
			buffer[3] = (byte)a_TreeConfig->GetMaxDepth();
			Converters::ReadUInt32AsBytesLE(a_TreeConfig->GetLeafSize(), buffer, 4);
			Converters::ReadUInt64AsBytesLE(a_TreeConfig->GetNodeOffset(), buffer, 8);
			buffer[16] = (byte)a_TreeConfig->GetNodeDepth();
			buffer[17] = (byte)a_TreeConfig->GetInnerHashSize();
		}

		if (!a_Config->GetSalt().empty())
			memmove(&buffer[32], &a_Config->GetSalt()[0], 16 * sizeof(byte));

		if (!a_Config->GetPersonalization().empty())
			memmove(&buffer[48], &a_Config->GetPersonalization()[0], 16 * sizeof(byte));

		HashLibUInt64Array result = HashLibUInt64Array(8);
		Converters::le64_copy(&buffer[0], 0, &result[0], 0, (Int32)buffer.size() * sizeof(byte));

		return result;
	}

private:
	static void VerifyConfigB(const IBlake2BConfig a_Config, const IBlake2BTreeConfig a_TreeConfig,
		const bool a_IsSequential)
	{
		// digest length
		if (a_Config->GetHashSize() < 1 || a_Config->GetHashSize() > 64)
			throw ArgumentOutOfRangeHashLibException(Utils::string_format(Blake2BErrorStrings::InvalidHashSize, a_Config->GetHashSize()));

		// Key length
		if (!a_Config->GetKey().empty())
		{
			size_t KeyLength = a_Config->GetKey().size();
			if (KeyLength > 64)
				throw ArgumentOutOfRangeHashLibException(Utils::string_format(Blake2BErrorStrings::InvalidKeyLength, KeyLength));
		}

		// Salt length
		if (!a_Config->GetSalt().empty())
		{
			size_t SaltLength = a_Config->GetSalt().size();
			if (SaltLength != 16)
				throw ArgumentOutOfRangeHashLibException(Utils::string_format(Blake2BErrorStrings::InvalidSaltLength, SaltLength));
		}

		// Personalisation length
		if (!a_Config->GetPersonalization().empty())
		{
			size_t PersonalizationLength = a_Config->GetPersonalization().size();
			if (PersonalizationLength != 16)
				throw ArgumentOutOfRangeHashLibException(Utils::string_format(Blake2BErrorStrings::InvalidPersonalizationLength, PersonalizationLength));
		}

		// Tree InnerHashSize
		if (a_TreeConfig)
		{
			if (a_IsSequential && a_TreeConfig->GetInnerHashSize() != 0)
			{
				throw ArgumentOutOfRangeHashLibException("a_TreeConfig->GetInnerHashSize()");
			}

			if (a_TreeConfig->GetInnerHashSize() > 64)
			{
				throw ArgumentOutOfRangeHashLibException(Utils::string_format(Blake2BErrorStrings::InvalidInnerHashSize, a_TreeConfig->GetInnerHashSize()));
			}
		}

	}

	static const char* InvalidHashSize;
	static const char* InvalidKeyLength;
	static const char* InvalidPersonalizationLength;
	static const char* InvalidSaltLength;
	static const char* TreeIncorrectInnerHashSize;

}; // end class Blake2BIvBuilder
