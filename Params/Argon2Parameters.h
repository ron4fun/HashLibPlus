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

#include "../Utils/ArrayUtils.h"
#include "../Interfaces/IHashInfo.h"

class Argon2Parameters : public virtual IIArgon2Parameters
{
private:
	HashLibByteArray _salt;
	HashLibByteArray _secret;
	HashLibByteArray _additional;

	Int32 _iterations;
	Int32 _memory;
	Int32 _lanes;
	Argon2Type _type;
	Argon2Version _version;

public:
	virtual HashLibByteArray GetSalt() const { return _salt; }
	virtual HashLibByteArray GetSecret() const { return _secret; }
	virtual HashLibByteArray GetAdditional() const { return _additional; }

	virtual Int32 GetIterations() const { return _iterations; }
	virtual Int32 GetMemory() const { return _memory; }
	virtual Int32 GetLanes() const { return _lanes; }
	virtual Argon2Type GetType() const { return _type; }
	virtual Argon2Version GetVersion() const { return _version; }

	Argon2Parameters() {}

	Argon2Parameters(const Argon2Parameters& value)
	{
		_salt = value._salt;
		_secret = value._secret;
		_additional = value._additional;

		_iterations = value._iterations;
		_memory = value._memory;
		_lanes = value._lanes;
		_type = value._type;
		_version = value._version;
	}

	Argon2Parameters(const Argon2Type& type, const HashLibByteArray& salt, const HashLibByteArray& secret,
		const HashLibByteArray& additional, const Int32 iterations, const Int32 memory, const Int32 lanes,
		const Argon2Version& version)
	{
		_salt = salt;
		_secret = secret;
		_additional = additional;

		_iterations = iterations;
		_memory = memory;
		_lanes = lanes;
		_type = type;
		_version = version;
	} //

	~Argon2Parameters()
	{
		Clear();
	} //

	virtual void Clear()
	{
		ArrayUtils::zeroFill(_salt);
		ArrayUtils::zeroFill(_secret);
		ArrayUtils::zeroFill(_additional);
	} //

	virtual IArgon2Parameters Clone() const
	{
		Argon2Parameters result = Argon2Parameters(GetType(), _salt, _secret, _additional, GetIterations(), GetMemory(), GetLanes(), GetVersion());
		return make_shared<Argon2Parameters>(result);
	} //
}; //

class Argon2ParametersBuilder
{
private:
	const Int32 DEFAULT_ITERATIONS = 3;
	const Int32 DEFAULT_MEMORY_COST = 12;
	const Int32 DEFAULT_LANES = 1;
	const Argon2Type DEFAULT_TYPE = Argon2Type::DataIndependentAddressing;
	const Argon2Version DEFAULT_VERSION = Argon2Version::Nineteen;

	HashLibByteArray _salt;
	HashLibByteArray _secret;
	HashLibByteArray _additional;
	Argon2Type _type;
	Argon2Version _version;
	Int32 _iterations;
	Int32 _memory;
	Int32 _lanes;

public:
	Argon2ParametersBuilder(const Argon2Type& a_Type)
	{
		_lanes = DEFAULT_LANES;
		_memory = 1 << DEFAULT_MEMORY_COST;
		_iterations = DEFAULT_ITERATIONS;
		_type = a_Type;
		_version = DEFAULT_VERSION;
	} //

	Argon2ParametersBuilder()
	{
		_type = DEFAULT_TYPE;
		_version = DEFAULT_VERSION;
		_iterations = DEFAULT_ITERATIONS;
		_memory = 1 << DEFAULT_MEMORY_COST;
		_lanes = DEFAULT_LANES;
	} //
	
	void operator=(const Argon2ParametersBuilder& value)
	{
		_salt = value._salt;
		_secret = value._secret;
		_additional = value._additional;

		_iterations = value._iterations;
		_memory = value._memory;
		_lanes = value._lanes;
		_type = value._type;
		_version = value._version;
	}

	~Argon2ParametersBuilder()
	{
		Clear();
	} //

	virtual IArgon2Parameters Build() const
	{
		Argon2Parameters result = Argon2Parameters(_type, _salt, _secret, _additional,
			_iterations, _memory, _lanes, _version);
		return make_shared<Argon2Parameters>(result);
	} //

	virtual void Clear()
	{
		ArrayUtils::zeroFill(_salt);
		ArrayUtils::zeroFill(_secret);
		ArrayUtils::zeroFill(_additional);
	} //

	virtual Argon2ParametersBuilder& WithSalt(const HashLibByteArray& salt)
	{
		_salt = salt;
		return *this;
	} //

	virtual Argon2ParametersBuilder& WithAdditional(const HashLibByteArray& additional)
	{
		_additional = additional;
		return *this;
	} //

	virtual Argon2ParametersBuilder& WithSecret(const HashLibByteArray& secret)
	{
		_secret = secret;
		return *this;
	} //

	virtual Argon2ParametersBuilder& WithIterations(const Int32 iterations)
	{
		_iterations = iterations;
		return *this;
	} //

	virtual Argon2ParametersBuilder& WithMemoryAsKiB(const Int32 memory)
	{
		_memory = memory;
		return *this;
	} //

	virtual Argon2ParametersBuilder& WithMemoryPowOfTwo(const Int32 memory)
	{
		_memory = 1 << memory;
		return *this;
	} //

	virtual Argon2ParametersBuilder& WithParallelism(const Int32 parallelism)
	{
		_lanes = parallelism;
		return *this;
	} //

	virtual Argon2ParametersBuilder& WithType(const Argon2Type& type)
	{
		_type = type;
		return *this;
	} //

	virtual Argon2ParametersBuilder& WithVersion(const Argon2Version& version)
	{
		_version = version;
		return *this;
	} //
	
}; //

class Argon2iParametersBuilder : public Argon2ParametersBuilder
{
public:
	Argon2iParametersBuilder()
		: Argon2ParametersBuilder(Argon2Type::DataIndependentAddressing)
	{} // end cctr
}; // end class Argon2iParametersBuilder

class Argon2dParametersBuilder : public Argon2ParametersBuilder
{
public:
	Argon2dParametersBuilder()
		: Argon2ParametersBuilder(Argon2Type::DataDependentAddressing)
	{} // end cctr
}; // end class Argon2dParametersBuilder

class Argon2idParametersBuilder : public Argon2ParametersBuilder
{
public:
	Argon2idParametersBuilder()
		: Argon2ParametersBuilder(Argon2Type::HybridAddressing)
	{} // end cctr
}; // end class Argon2idParametersBuilder
