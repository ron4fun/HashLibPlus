HashLibPlus [![License](http://img.shields.io/badge/license-MPL2-blue.svg)](https://github.com/Ron4fun/HashLibPlus/blob/master/LICENSE)
====

HashLibPlus is a recommended C++11 hashing library that provides a fluent interface for computing hashes and checksums of strings, files, streams, bytearrays and untyped data to mention but a few.

It also supports **Incremental Hashing**, **Cloning**, **NullDigest**.

Available Algorithms
----------------------------------------

 ### Hashes
----------------------------------------
##### Cyclic Redundancy Checks

* `All CRC Variants from CRC3 to CRC64` :heavy_check_mark:

##### Checksums

* `Adler32` :heavy_check_mark:

##### Non-Cryptographic Hash Functions 
----------------------------------------

###### 32 bit hashes

* `AP` `BKDR` `Bernstein` `Bernstein1` `DEK` `DJB` `ELF` `FNV` :heavy_check_mark:

* `FNV1a` `JS` `Jenkins3` `Murmur2` `MurmurHash3_x86_32` `OneAtTime` :heavy_check_mark:

*  `PJW` `RS` `Rotating` `SDBM` `ShiftAndXor` `SuperFast` `XXHash32` :heavy_check_mark:

###### 64 bit hashes

* `FNV64` `FNV1a64` `Murmur2_64` `SipHash2_4` `XXHash64` :heavy_check_mark:

###### 128 bit hashes

* `MurmurHash3_x86_128` `MurmurHash3_x64_128` :heavy_check_mark:

##### Cryptographic Hash Functions 
----------------------------------------

 * `MD2` :heavy_check_mark:

 * `MD4` :heavy_check_mark:

 * `MD5` :heavy_check_mark:

 * `SHA-0` :heavy_check_mark:

 * `SHA-1` :heavy_check_mark:

 * `SHA-2 (224, 256, 384, 512, 512-224, 512-256)` :heavy_check_mark:

 * `GOST 34.11-94` :heavy_check_mark:

 * `GOST R 34.11-2012 (AKA Streebog) (256, 512)` :heavy_check_mark:
 
 * `Grindahl (256, 512)` :heavy_check_mark:
 
 * `HAS160` :heavy_check_mark:

 * `RIPEMD (128, 256, 256, 320)` :heavy_check_mark:

 * `Tiger (128, 160, 192 (Rounds 3, 4, 5))` :heavy_check_mark:

 * `Tiger2 (128, 160, 192 (Rounds 3, 4, 5))` :heavy_check_mark:
 
 * `Snefru (128, 256)` :heavy_check_mark:
 
 * `Haval (128, 160, 192, 224, 256 (Rounds 3, 4, 5))` :heavy_check_mark:
 
 * `Panama` :heavy_check_mark:
 
 * `RadioGatun (RadioGatun32, RadioGatun64)` :heavy_check_mark:

 * `WhirlPool` :heavy_check_mark:

 * `Blake2B (160, 256, 384, 512)` :heavy_check_mark:
 
 * `Blake2S (128, 160, 224, 256)` :heavy_check_mark:

 * `SHA-3 (224, 256, 384, 512)` :heavy_check_mark:
 
 * `Keccak (224, 256, 288, 384, 512)` :heavy_check_mark:
 
 * `Blake2BP` :heavy_check_mark:

 * `Blake2SP` :heavy_check_mark:

 * `Blake3` :heavy_check_mark:

### Key Derivation Functions
----------------------------------------

###### Password Hashing Schemes (Password Based Key Derivation Functions)

----------------------------------------

* `PBKDF2` :heavy_check_mark:
 
* `Argon2 (2i, 2d and 2id variants)` :heavy_check_mark:

* `Scrypt` :heavy_check_mark:

### MAC
----------------------------------------

* `HMAC (all supported hashes)` :heavy_check_mark:

* `KMAC (KMAC128, KMAC256)` :heavy_check_mark:

* `Blake2MAC (Blake2BMAC, Blake2SMAC)` :heavy_check_mark:

### XOF (Extendable Output Function)
----------------------------------------

* `Shake (Shake-128, Shake-256)` :heavy_check_mark:

* `CShake (CShake-128, CShake-256)` :heavy_check_mark:

* `Blake2X (Blake2XS, Blake2XB)` :heavy_check_mark:

* `KMACXOF (KMAC128XOF, KMAC256XOF)` :heavy_check_mark:

* `Blake3XOF` :heavy_check_mark:

### Usage Examples
----------------------------------------


```c++
#include "Base/HashFactory.h"

int main() 
{
    // Chaining mode
    string result = HashFactory::Crypto::CreateMD5()
    			->ComputeString("Hello C#")->ToString();

    // Incremental mode
    IHash hash = HashFactory::Crypto::CreateMD5();
    hash->Initialize();
    hash->TransformString("Hello");
    hash->TransformString(" C#");
    string result_2 = hash->TransformFinal()->ToString();

    bool check = result == result_2; // True

	return 0;
}
```

How to build library
----------------------------------------
### CMake
----------------------------------------
To build this library you should have [CMake](https://cmake.org) installed and configured on your local machine to work with *C++* compiler such as **gcc**, **g++** and **clang**. If you already have visual studio installed on your local machine, cmake kind of automatically links with the compiler and therefore builds a visual studio project of the library for you. Goodluck! ;)

*CMake version 2.30.3*, was specifically used to compile this library.

**Note: Download the [catch2](https://github.com/catchorg/Catch2) library from github and put inside the folder `Catch2-2.13.6` in the `HashLibPlus.Tests` directory, before running `cmake` command. I emptied the folder because of project size.** 

```
	> cmake --version
```

This command displays your cmake current version.


```
	> cmake -S {src_dir} -B {build_dir}
```

This command is to build the library for compilation, where *{src_dir}* is the path to the project main directory. And *{build_src}* is the directory path where the project built files are stored.


How to run test
----------------------------------------
[catch2](https://github.com/catchorg/Catch2) library is the test framework used for this library because of its flexible nature.

To run the unitests which are stored in the *HashLibPlus.Tests* directory. Once the project is built with *cmake*, you can always compile the code which outputs two executables.

### HashLibPlus.exe
----------------------------------------
This displays a benchmark test analysis of the compiled code speed with regards to your C.P.U capability. 

### HashLibPlus.Test.exe
----------------------------------------
This executable hooks into [catch2](https://github.com/catchorg/Catch2) process to allow for detail test output result, and other command line options that *catch2* supports for those that wish to pass values to *catch2* interface.

More on this library
----------------------------------------
Depending on how experienced you are with *CMake* or *catch2*, you are always free to make pull requests and most especially plug in your favourite *hash* into the library which might not be available now. Bye!

### Other Implementations
----------------------------------------

If you want implementations in other languages, you can check out these

* [HashLib4Pascal](https://github.com/Xor-el/HashLib4Pascal) by Ugochukwu Mmaduekwe

### Tip Jar
----------------------------------------

* :dollar: **Bitcoin**: `1Mcci95WffSJnV6PsYG7KD1af1gDfUvLe6`
