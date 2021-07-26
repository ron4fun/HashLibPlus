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

#include "Blake2BParams.h"
#include "../Interfaces/IHashInfo.h"

/// <summary>
/// <b>Blake2XBConfig</b> is used to configure _hash function parameters and
/// keying.
/// </summary>
class Blake2XBConfig : public virtual IIBlake2XBConfig
{
private:
	IBlake2BConfig _config = nullptr;
	IBlake2BTreeConfig _treeConfig = nullptr;

public:
	Blake2XBConfig() {}

	Blake2XBConfig(const IBlake2BConfig config, const IBlake2BTreeConfig treeConfig)
	{
		_config = ::move(config);
		_treeConfig = ::move(treeConfig);
	}

	virtual IBlake2BConfig GetConfig() const
	{
		return _config->Clone();
	}

	virtual IBlake2BTreeConfig GetTreeConfig() const
	{
		return _treeConfig ? _treeConfig->Clone() : nullptr;
	} 

	virtual IBlake2BConfig GetConfig()
	{
		return _config;
	}

	virtual IBlake2BTreeConfig GetTreeConfig()
	{
		return _treeConfig;
	}

	virtual void SetConfig(const IBlake2BConfig value)
	{
		_config = ::move(value);
	}

	virtual void SetTreeConfig(const IBlake2BTreeConfig value) 
	{
		_treeConfig = ::move(value);
	}

	virtual IBlake2XBConfig Clone() const
	{
		return make_shared<Blake2XBConfig>(
			_config ? _config->Clone() : nullptr, 
			_treeConfig ? _treeConfig->Clone() : nullptr);
	}

	static IBlake2XBConfig CreateBlake2XBConfig(IBlake2BConfig config, IBlake2BTreeConfig treeConfig)
	{
		return make_shared<Blake2XBConfig>(config, treeConfig);
	}

}; // end class 
