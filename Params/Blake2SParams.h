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

#include "../Interfaces/IBlake2SConfigurations/IBlake2SConfig.h"
#include "../Interfaces/IBlake2SConfigurations/IBlake2STreeConfig.h"
#include "../Utils/Converters.h"
#include "../Enum/HashSize.h"
#include "../Utils/HashLibTypes.h"
#include "../Utils/ArrayUtils.h"
#include "../Utils/Utils.h"

class Blake2SErrorStrings
{
public:
	static const char* InvalidHashSize;
	static const char*  InvalidNodeOffset;
	static const char* InvalidKeyLength;
	static const char* InvalidPersonalizationLength;
	static const char* InvalidSaltLength;
	static const char* InvalidInnerHashSize;
	static const char* InvalidMaxDepth;
}; // !Blake2SErrorStrings

class Blake2SConfig : public virtual IIBlake2SConfig
{
public:
	Blake2SConfig(const HashSize& a_hash_size = HashSize::HashSize256)
	{
		ValidateHashSize(a_hash_size);
		_hash_size = a_hash_size;
	}

	Blake2SConfig(const Int32 a_hash_size)
	{
		ValidateHashSize(a_hash_size);
		_hash_size = a_hash_size;
	}

	static IBlake2SConfig CreateBlake2SConfig(const Int32 a_hash_size = HashSize::HashSize256)
	{
		return make_shared<Blake2SConfig>(a_hash_size);
	}

	~Blake2SConfig()
	{
		Clear();
	}

	static IBlake2SConfig GetDefaultConfig()
	{
		return make_shared<Blake2SConfig>();
	}

	virtual HashLibByteArray GetPersonalization() const
	{
		return _personalisation;
	}

	virtual void SetPersonalization(const HashLibByteArray& value)
	{
		ValidatePersonalizationLength(value);
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

	virtual IBlake2SConfig Clone() const
	{
		Blake2SConfig result = Blake2SConfig(GetHashSize());
		result._key = _key;
		result._personalisation = _personalisation;
		result._salt = _salt;

		return make_shared<Blake2SConfig>(result);
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
		if (a_hash_size < 1 || a_hash_size > 32)
			throw ArgumentOutOfRangeHashLibException(Utils::string_format(Blake2SErrorStrings::InvalidHashSize, a_hash_size));
	}

	inline void ValidateKeyLength(const HashLibByteArray& a_Key)
	{
		size_t KeyLength = a_Key.size();
		if (KeyLength > 32)
			throw ArgumentOutOfRangeHashLibException(Utils::string_format(Blake2SErrorStrings::InvalidKeyLength, KeyLength));
	}

	inline void ValidatePersonalizationLength(const HashLibByteArray& a_Personalisation)
	{
		size_t PersonalisationLength = a_Personalisation.size();
		if (PersonalisationLength != 0 && PersonalisationLength != 8)
			throw ArgumentOutOfRangeHashLibException(Utils::string_format(Blake2SErrorStrings::InvalidPersonalizationLength, PersonalisationLength));
	}

	inline void ValidateSaltLength(const HashLibByteArray& a_Salt)
	{
		size_t SaltLength = a_Salt.size();
		if (SaltLength != 0 && SaltLength != 8)
			throw ArgumentOutOfRangeHashLibException(Utils::string_format(Blake2SErrorStrings::InvalidSaltLength, SaltLength));
	}

private:
	Int32 _hash_size;
	HashLibByteArray _personalisation, _salt, _key;

}; // !Blake2SConfig

class Blake2STreeConfig : public virtual IIBlake2STreeConfig
{
public:
	Blake2STreeConfig()
		: _fanOut(0),
		_maxDepth(0),
		_nodeDepth(0),
		_innerHashSize(32),
		_leafSize(32),
		_nodeOffset(0),
		_isLastNode(false)
	{}

	static IBlake2STreeConfig CreateBlake2STreeConfig()
	{
		return make_shared<Blake2STreeConfig>();
	}

	static IBlake2STreeConfig GetSequentialTreeConfig()
	{
		Blake2STreeConfig result = Blake2STreeConfig();
		result._fanOut = 1;
		result._maxDepth = 1;
		result._leafSize = 0;
		result._nodeOffset = 0;
		result._nodeDepth = 0;
		result._innerHashSize = 0;
		result._isLastNode = false;

		return make_shared<Blake2STreeConfig>(result);
	}

	static IBlake2STreeConfig GetDefaultTreeConfig()
	{
		return make_shared<Blake2STreeConfig>();
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
		if (value > 32)
			throw ArgumentOutOfRangeHashLibException(Utils::string_format(Blake2SErrorStrings::InvalidInnerHashSize, value));

		_innerHashSize = value;
	}

	virtual byte GetMaxDepth() const
	{
		return _maxDepth;
	}

	virtual void SetMaxDepth(const byte value)
	{
		if (value < 1)
			throw ArgumentOutOfRangeHashLibException(Utils::string_format(Blake2SErrorStrings::InvalidMaxDepth, value));

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
		if (value > ((UInt64)1 << 48) - 1)
			throw ArgumentOutOfRangeHashLibException(Utils::string_format(Blake2SErrorStrings::InvalidNodeOffset, value));

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

	virtual IBlake2STreeConfig Clone() const
	{
		Blake2STreeConfig result = Blake2STreeConfig();
		result._fanOut = _fanOut;
		result._innerHashSize = _innerHashSize;
		result._maxDepth = _maxDepth;
		result._nodeDepth = _nodeDepth;
		result._leafSize = _leafSize;
		result._nodeOffset = _nodeOffset;
		result._isLastNode = _isLastNode;

		return make_shared<Blake2STreeConfig>(result);
	}

private:
	byte _fanOut, _maxDepth, _nodeDepth, _innerHashSize;
	UInt32 _leafSize;
	UInt64 _nodeOffset;
	bool _isLastNode;

}; // end class Blake2STreeConfig

class Blake2SIvBuilder
{
public:
	static HashLibUInt32Array ConfigS(const IBlake2SConfig a_Config, IBlake2STreeConfig a_TreeConfig)
	{
		bool isSequential;
		HashLibByteArray buffer;

		isSequential = a_TreeConfig == nullptr;
		if (isSequential)
			a_TreeConfig = Blake2STreeConfig::GetSequentialTreeConfig();

		VerifyConfigS(a_Config, a_TreeConfig, isSequential);

		buffer.resize(32);

		buffer[0] = (byte)a_Config->GetHashSize();
		buffer[1] = (byte)a_Config->GetKey().size();

		if (a_TreeConfig != nullptr)
		{
			buffer[2] = a_TreeConfig->GetFanOut();
			buffer[3] = a_TreeConfig->GetMaxDepth();
			Converters::ReadUInt32AsBytesLE(a_TreeConfig->GetLeafSize(), buffer, 4);
			buffer[8] = (byte)a_TreeConfig->GetNodeOffset();
			buffer[9] = (byte)(a_TreeConfig->GetNodeOffset() >> 8);
			buffer[10] = (byte)(a_TreeConfig->GetNodeOffset() >> 16);
			buffer[11] = (byte)(a_TreeConfig->GetNodeOffset() >> 24);
			buffer[12] = (byte)(a_TreeConfig->GetNodeOffset() >> 32);
			buffer[13] = (byte)(a_TreeConfig->GetNodeOffset() >> 40);
			buffer[14] = a_TreeConfig->GetNodeDepth();
			buffer[15] = a_TreeConfig->GetInnerHashSize();
		}

		if (!a_Config->GetSalt().empty())
			memmove(&buffer[16], &a_Config->GetSalt()[0], 8 * sizeof(byte));

		if (!a_Config->GetPersonalization().empty())
			memmove(&buffer[24], &a_Config->GetPersonalization()[0], 8 * sizeof(byte));

		HashLibUInt32Array result = HashLibUInt32Array(8);
		Converters::le32_copy(&buffer[0], 0, &result[0], 0, (Int32)buffer.size() * sizeof(byte));

		return result;
	}

private:
	static void VerifyConfigS(const IBlake2SConfig a_Config, const IBlake2STreeConfig a_TreeConfig,
		const bool a_IsSequential)
	{
		// digest length
		if (a_Config->GetHashSize() < 1 || a_Config->GetHashSize() > 32)
			throw ArgumentOutOfRangeHashLibException(Utils::string_format(Blake2SErrorStrings::InvalidHashSize, a_Config->GetHashSize()));

		// Key length
		if (!a_Config->GetKey().empty())
		{
			size_t KeyLength = a_Config->GetKey().size();
			if (KeyLength > 32)
				throw ArgumentOutOfRangeHashLibException(Utils::string_format(Blake2SErrorStrings::InvalidKeyLength, KeyLength));
		}

		// Salt length
		if (!a_Config->GetSalt().empty())
		{
			size_t SaltLength = a_Config->GetSalt().size();
			if (SaltLength != 8)
				throw ArgumentOutOfRangeHashLibException(Utils::string_format(Blake2SErrorStrings::InvalidSaltLength, SaltLength));
		}

		// Personalisation length
		if (!a_Config->GetPersonalization().empty())
		{
			size_t PersonalizationLength = a_Config->GetPersonalization().size();
			if (PersonalizationLength != 8)
				throw ArgumentOutOfRangeHashLibException(Utils::string_format(Blake2SErrorStrings::InvalidPersonalizationLength, PersonalizationLength));
		}

		// Tree InnerHashSize
		if (a_TreeConfig)
		{
			if (a_IsSequential && a_TreeConfig->GetInnerHashSize() != 0)
			{
				throw ArgumentOutOfRangeHashLibException("a_TreeConfig->GetInnerHashSize()");
			}

			if (a_TreeConfig->GetInnerHashSize() > 32)
			{
				throw ArgumentOutOfRangeHashLibException(Utils::string_format(Blake2SErrorStrings::InvalidInnerHashSize, a_TreeConfig->GetInnerHashSize()));
			}
		}

	}

	static const char* InvalidHashSize;
	static const char* InvalidKeyLength;
	static const char* InvalidPersonalizationLength;
	static const char* InvalidSaltLength;
	static const char* TreeIncorrectInnerHashSize;

}; // end class Blake2SIvBuilder
