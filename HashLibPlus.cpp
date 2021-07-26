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

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <iostream>
#include <fstream>
#include <chrono>
#include <random>
#include <iomanip>

#include "Base/HashFactory.h"

using namespace std;

string Calculate(IHash hash, Int32 size = 65536)
{
	const UInt32 THREE_SECONDS_IN_MILLISECONDS = 3000;

	string newName = hash->GetName();

	HashLibByteArray data(size);
	
	//
	random_device rd;
	mt19937 mt(rd());
	uniform_real_distribution<double> dist(1.0, size);

	//
	for (Int32 i = 0; i < size; i++)
		data[i] = (byte)dist(mt);

	double maxRate = 0.0;
	double totalMilliSeconds = 0.0;

	for (Int32 i = 0; i < 3; i++)
	{
		Int64 total = 0;

		while (totalMilliSeconds < THREE_SECONDS_IN_MILLISECONDS)
		{
			// Start timer
			auto t1 = chrono::high_resolution_clock::now();

			hash->ComputeBytes(data);
			total = total + data.size();

			auto t2 = chrono::high_resolution_clock::now();

			// Get the elapsed time as a TimeSpan value.
			chrono::duration<double, milli> time_lapse(t2 - t1);

			totalMilliSeconds = totalMilliSeconds + time_lapse.count();
		}

		maxRate = max(total / (totalMilliSeconds / 1000) / 1024 / 1024, maxRate);
	}
	
	char output[100]; // = "%s Throughput: %.2lf MB/s with Blocks of %d KB";

	snprintf(output, sizeof(output),
		"%s Throughout: %.2lf MB/s with Blocks of %d KB", 
		newName.c_str(), maxRate, size / 1024);

	return output;
} // !Calculate

void DoBenchmark(HashLibStringArray& stringList)
{
	stringList.clear(); //

	//
	stringList.push_back(Calculate(HashFactory::Checksum::CreateAdler32()));

	stringList.push_back(Calculate(HashFactory::Checksum::CreateCRC(CRCStandard::CRC32)));

	stringList.push_back(Calculate(HashFactory::Checksum::CreateCRC32_PKZIP()));

	stringList.push_back(Calculate(HashFactory::Hash32::CreateMurmurHash3_x86_32()));

	stringList.push_back(Calculate(HashFactory::Hash32::CreateXXHash32()));

	stringList.push_back(Calculate(HashFactory::Hash64::CreateSipHash64_2_4()));

	stringList.push_back(Calculate(HashFactory::Hash64::CreateXXHash64()));

	stringList.push_back(Calculate(HashFactory::Hash128::CreateMurmurHash3_x86_128()));

	stringList.push_back(Calculate(HashFactory::Hash128::CreateMurmurHash3_x64_128()));

	stringList.push_back(Calculate(HashFactory::Crypto::CreateMD5()));

	stringList.push_back(Calculate(HashFactory::Crypto::CreateSHA1()));

	stringList.push_back(Calculate(HashFactory::Crypto::CreateSHA2_256()));

	stringList.push_back(Calculate(HashFactory::Crypto::CreateSHA2_512()));

	stringList.push_back(Calculate(HashFactory::Crypto::CreateSHA3_256()));

	stringList.push_back(Calculate(HashFactory::Crypto::CreateSHA3_512()));

	stringList.push_back(Calculate(HashFactory::Crypto::CreateBlake2B_256()));

	stringList.push_back(Calculate(HashFactory::Crypto::CreateBlake2B_512()));

	stringList.push_back(Calculate(HashFactory::Crypto::CreateBlake2S_128()));

	stringList.push_back(Calculate(HashFactory::Crypto::CreateBlake2S_256()));

} // !DoBenchmark

int main()
{
	HashLibStringArray stringList;

	cout << "Please be patient, this might take some time" << endl << endl;

	try
	{
		DoBenchmark(stringList);

		for (auto i = 0; i < stringList.size(); i++)
			cout << stringList[i] << endl;

		cout << endl << "Performance Benchmark Finished" << endl << endl;

		system("PAUSE");
	}
	catch (exception& e)
	{
		cout << endl << "An error occurred: " << e.what() << endl << endl;
	}
	
	return 0;
}
