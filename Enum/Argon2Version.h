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

/// <summary>
/// There are two versions, 16 and 19. 19 is 5%-15% slower but fixes a vulnerability
/// where an attacker could take advantage of short time spans where memory blocks
/// were not used to reduce the overall memory cost by up to a factor of about 3.5.
/// </summary>
enum Argon2Version
{
	/// <summary>
	/// For Argon2 versions 1.2.1 or earlier.
	/// </summary>
	Sixteen = 0x10,

	/// <summary>
	/// For Argon2 version 1.3.
	/// </summary>
	Nineteen = 0x13

}; // end enum Argon2Version
