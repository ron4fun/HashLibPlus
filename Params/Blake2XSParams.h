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

#include "Blake2SParams.h"
#include "../Interfaces/IHashInfo.h"

/// <summary>
/// <b>Blake2XSConfig</b> is used to configure _hash function parameters and
/// keying.
/// </summary>
class Blake2XSConfig : public virtual IIBlake2XSConfig
{
private:
	IBlake2SConfig _config = nullptr;
	IBlake2STreeConfig _treeConfig = nullptr;

public:
	Blake2XSConfig() {}

	Blake2XSConfig(const IBlake2SConfig config, const IBlake2STreeConfig treeConfig)
	{
		_config = ::move(config);
		_treeConfig = ::move(treeConfig);
	}

	virtual IBlake2SConfig GetConfig() const
	{
		return _config->Clone();
	}

	virtual IBlake2STreeConfig GetTreeConfig() const
	{
		return _treeConfig ? _treeConfig->Clone() : nullptr;
	}

	virtual IBlake2SConfig GetConfig()
	{
		return _config;
	}

	virtual IBlake2STreeConfig GetTreeConfig()
	{
		return _treeConfig;
	}

	virtual void SetConfig(const IBlake2SConfig value)
	{
		_config = ::move(value);
	}

	virtual void SetTreeConfig(const IBlake2STreeConfig value)
	{
		_treeConfig = ::move(value);
	}

	virtual IBlake2XSConfig Clone() const
	{
		return make_shared<Blake2XSConfig>(
			_config ? _config->Clone() : nullptr,
			_treeConfig ? _treeConfig->Clone() : nullptr);
	}

	static IBlake2XSConfig CreateBlake2XSConfig(IBlake2SConfig config, IBlake2STreeConfig treeConfig)
	{
		return make_shared<Blake2XSConfig>(config, treeConfig);
	}

}; // end class 
