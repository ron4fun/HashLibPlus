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

#include "Blake2SParams.h"

const char* Blake2SErrorStrings::InvalidHashSize = "HashSize must be restricted to one of the following [1 .. 32], \"%u\"";
const char* Blake2SErrorStrings::InvalidKeyLength = "Key length must not be greater than 32, \"%u\"";
const char* Blake2SErrorStrings::InvalidPersonalizationLength = "Personalization length must be equal to 8, \"%u\"";
const char* Blake2SErrorStrings::InvalidSaltLength = "Salt length must be equal to 8, \"%u\"";
const char* Blake2SErrorStrings::InvalidInnerHashSize = "TreeConfig InnerHashSize must be between [0 .. 32], \"%u\"";
const char* Blake2SErrorStrings::InvalidMaxDepth = "MaxDepth must be between [1 .. 255], \"%u\"";
const char* Blake2SErrorStrings::InvalidNodeOffset = "NodeOffset must be between [0 .. (2^48-1)], \"%u\"";