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

#include "Blake2BParams.h"

const char* Blake2BErrorStrings::InvalidHashSize = "HashSize must be restricted to one of the following [1 .. 64], \"%u\"";
const char* Blake2BErrorStrings::InvalidKeyLength = "Key length must not be greater than 64, \"%u\"";
const char* Blake2BErrorStrings::InvalidPersonalizationLength = "Personalization length must be equal to 16, \"%u\"";
const char* Blake2BErrorStrings::InvalidSaltLength = "Salt length must be equal to 16, \"%u\"";
const char* Blake2BErrorStrings::InvalidInnerHashSize = "TreeConfig InnerHashSize must be between [0 .. 64], \"%u\"";
const char* Blake2BErrorStrings::InvalidMaxDepth = "MaxDepth must be between [1 .. 255], \"%u\"";