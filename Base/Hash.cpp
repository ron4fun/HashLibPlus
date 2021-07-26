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

#include "Hash.h"

const char* Hash::IndexOutOfRange = "Current index is out of range";
const char* Hash::InvalidBufferSize = "\"BufferSize\" must be greater than zero";
const char* Hash::UnAssignedStream = "Input stream is unassigned";
const char* Hash::FileNotExist = "Specified file not found";
const char* Hash::CloneNotYetImplemented = "Clone not yet implemented for \"%s\"";
const char* Hash::DeleteNotYetImplemented = "Delete not yet implemented for \"%s\"";