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

#include "Blake2B.h"

const char* Blake2B::InvalidConfigLength = "Config length must be 8 words";

const char* Blake2XB::InvalidXofSize = "XOFSizeInBits must be multiples of 8 and be between %u and %u bytes.";
const char* Blake2XB::InvalidOutputLength = "Output length is above the digest length";
const char* Blake2XB::OutputBufferTooShort = "Output buffer too short";
const char* Blake2XB::MaximumOutputLengthExceeded = "Maximum length is 2^32 blocks of 64 bytes";
const char* Blake2XB::WritetoXofAfterReadError = "\"%s\" write to Xof after read not allowed";