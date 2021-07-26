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

#include <typeinfo>
#include "../Utils/HashLibTypes.h"

template <typename T>
class Nullable
{
public:
	Nullable()
	{} // end constructor

	Nullable(const T aValue)
	{
		SetValue(aValue);
	} // end constructor

	Nullable(const T aValue, const T aDefault)
	{
		SetValue(aValue);
		SetDefault(aDefault);
	} // end constructor

	inline void ClearValue()
	{
		_initValue = "";
	} // end function ClearValue

	inline void SetDefault(const T aDefault)
	{
		_default = aDefault;
		_initDefault = "I";
		if (GetIsNull())
			_value = aDefault;
	} // end function SetDefault

	explicit operator T() const
	{
		return _value;
	} // end operator T()

	operator Nullable<T>() const
	{
		return *this;
	} // end operator Nullable<T>()

	Nullable<T> operator+(const Nullable<T>& aValue)
	{
		Nullable<T> result = Nullable<T>();

		if (GetIsNull() || aValue.GetIsNull())
		{
			result.ClearValue();
			return result;
		} // end if		
		else
		{
			if (typeid(T) == typeid(Int32))
				return result.SetValue(NewAddInt(GetValue(), aValue.GetValue()));
			if (typeid(T) == typeid(float))
				return result.SetValue(AddFloat(GetValue(), aValue.GetValue()));
			if (typeid(T) == typeid(string))
				return result.SetValue(AddString(GetValue(), aValue.GetValue()));
			if (typeid(T) == typeid(Int64))
				return result.SetValue(AddInt64(GetValue(), aValue.GetValue()));
		}
		throw UnsupportedTypeHashLibException(UnsupportedType);
	} // end function operator+

	inline T GetValue()
	{
		CheckType();
		CheckValue();
		return _value;
	} // end function GetValue

private:
	static T CastBack(const Nullable<T>& aValue)
	{
		return T(aValue);
	} // end function CastBack

	static T AddFloat(const Nullable<T>& aFloat, const Nullable<T>& bFloat)
	{
		double _Value = double(aFloat) + double(bFloat);
		return CastBack(_Value);
	} // end function AddFloat

	static T AddString(const Nullable<T>& aString, const Nullable<T>& bString)
	{
		string _Value = string(aString) + string(bString);
		return CastBack(_Value);
	} // end function AddString

	static T AddInt64(const Nullable<T>& aInt64, const Nullable<T>& bInt64)
	{
		Int64 _Value = Int64(aInt64) + Int64(bInt64);
		return CastBack(_Value);
	} // end function AddInt64

	static T NewAddInt(const Nullable<T>& aInt, const Nullable<T>& bInt)
	{
		Int32 _Value = Int32(aInt) + Int32(bInt);
		return CastBack(_Value);
	} // end function NewAddInt

	inline void SetValue(const T aValue)
	{
		_initValue = "I";
		_value = aValue;
	} // end function SetValue

	inline void CheckValue()
	{
		if (GetIsNull())
		{
			if (GetHasDefault())
				_value = _default;
			else
				throw NullReferenceHashLibException(GetNullValue);
		} // end if
	} // end function CheckValue

	inline void CheckType() const
	{
		if (typeid(T) == typeid(int));
		else if (typeid(T) == typeid(char));
		else if (typeid(T) == typeid(Int16));
		else if (typeid(T) == typeid(Int32));
		else if (typeid(T) == typeid(Int64));
		else if (typeid(T) == typeid(byte));
		else if (typeid(T) == typeid(UInt16));
		else if (typeid(T) == typeid(UInt32));
		else if (typeid(T) == typeid(UInt64));
		else if (typeid(T) == typeid(float));
		else if (typeid(T) == typeid(double));
		else if (typeid(T) == typeid(string));
		else throw UnsupportedTypeHashLibException(UnsupportedType);
	} // end function CheckType

	inline bool GetIsNull() const
	{
		return _initValue != "I";
	} // end function GetIsNull

	inline bool GetHasValue() const
	{
		return !GetIsNull();
	} // end function GetHasValue

	inline bool GetHasDefault() const
	{
		return _initDefault == "I";
	} // end function GetHasDefault

private:
	T _value;
	string _initValue;
	T _default;
	string _initDefault;

	//static const char *CannotAssignPointerToNullable;
	static const char* UnsupportedType;
	static const char* GetNullValue;
}; // end class Nullable

//template <typename T>
//const char *Nullable<T>::CannotAssignPointerToNullable = "Cannot assign non-null pointer to nullable type.";
template <typename T>
const char* Nullable<T>::UnsupportedType = "Unsupported Type: Only supports integers, floats and strings.";
template <typename T>
const char* Nullable<T>::GetNullValue = "Attempted to get a null value.";

/// <summary>
/// Represents a Nullable Integer.
/// </summary>
typedef Nullable<Int32> NullableInteger;
