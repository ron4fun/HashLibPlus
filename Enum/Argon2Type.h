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
/// Argon2 can _hash in three different ways, data-dependent, data-independent and hybrid.
/// </summary>
/// <remarks>
/// <para>
/// From the Argon2 paper:
/// </para>
/// <para>
/// Argon2 has three variants: Argon2d [data-dependent], Argon2i [data-independent] and Argon2id [hybrid of both].
/// Argon2d is faster and uses data-depending memory access, which makes it suitable
/// for crypto currencies and applications with no threats from side-channel timing
/// attacks. Argon2i uses data-independent memory access, which is preferred for
/// password hashing and password-based key derivation. Argon2i is slower as it
/// makes more passes over the memory to protect from tradeoff attacks.
/// </para>
/// <para>
///
/// </para>
/// </remarks>
enum Argon2Type
{
	/// <summary>
	/// Use data-dependent addressing. This is faster but susceptible to
	/// side-channel attacks.
	/// </summary>
	DataDependentAddressing = 0,

	/// <summary>
	/// Use data-independent addressing. This is slower and recommended for password
	/// hashing and password-based key derivation.
	/// </summary>
	DataIndependentAddressing = 1,

	/// <summary>
	/// Use a hybrid of data-dependent and data-independent addressing.
	/// </summary>
	HybridAddressing = 2

}; // end enum Argon2Type
