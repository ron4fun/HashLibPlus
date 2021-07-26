#define CATCH_CONFIG_RUNNER
#include "Catch2-2.13.6/single_include/catch2/catch.hpp"

// Checksum hashes
#include "Checksum/Test_Adler32.h"
#include "Checksum/Test_CRC.h"
#include "Checksum/Test_Crc32PKZip.h"
#include "Checksum/Test_Crc32Castagnoli.h"

// Crypto hashes
#include "Crypto/Test_HAS160.h"
#include "Crypto/Test_Gost.h"
#include "Crypto/Test_GOST3411_2012_256.h"
#include "Crypto/Test_GOST3411_2012_512.h"
#include "Crypto/Test_Panama.h"
#include "Crypto/Test_WhirlPool.h"

#include "Crypto/Test_Blake2S.h"
#include "Crypto/Test_Blake2SP.h"
#include "Crypto/Test_Blake2B.h"
#include "Crypto/Test_Blake2BP.h"
#include "Crypto/Test_Blake3.h"

#include "Crypto/Test_Snefru_8_128.h"
#include "Crypto/Test_Snefru_8_256.h"

#include "Crypto/Test_Grindahl256.h"
#include "Crypto/Test_Grindahl512.h"

#include "Crypto/Test_RadioGatun32.h"
#include "Crypto/Test_RadioGatun64.h"

#include "Crypto/Test_Keccak_224.h"
#include "Crypto/Test_Keccak_256.h"
#include "Crypto/Test_Keccak_288.h"
#include "Crypto/Test_Keccak_384.h"
#include "Crypto/Test_Keccak_512.h"

#include "Crypto/Test_Haval_3_128.h"
#include "Crypto/Test_Haval_3_160.h"
#include "Crypto/Test_Haval_3_192.h"
#include "Crypto/Test_Haval_3_224.h"
#include "Crypto/Test_Haval_3_256.h"
#include "Crypto/Test_Haval_4_128.h"
#include "Crypto/Test_Haval_4_160.h"
#include "Crypto/Test_Haval_4_192.h"
#include "Crypto/Test_Haval_4_224.h"
#include "Crypto/Test_Haval_4_256.h"
#include "Crypto/Test_Haval_5_128.h"
#include "Crypto/Test_Haval_5_160.h"
#include "Crypto/Test_Haval_5_192.h"
#include "Crypto/Test_Haval_5_224.h"
#include "Crypto/Test_Haval_5_256.h"

#include "Crypto/Test_SHA0.h"
#include "Crypto/Test_SHA1.h"
#include "Crypto/Test_SHA2_224.h"
#include "Crypto/Test_SHA2_256.h"
#include "Crypto/Test_SHA2_384.h"
#include "Crypto/Test_SHA2_512.h"
#include "Crypto/Test_SHA2_512_224.h"
#include "Crypto/Test_SHA2_512_256.h"
#include "Crypto/Test_SHA3_224.h"
#include "Crypto/Test_SHA3_256.h"
#include "Crypto/Test_SHA3_384.h"
#include "Crypto/Test_SHA3_512.h"

#include "Crypto/Test_MD5.h"
#include "Crypto/Test_MD4.h"
#include "Crypto/Test_MD2.h"

#include "Crypto/Test_RIPEMD.h"
#include "Crypto/Test_RIPEMD128.h"
#include "Crypto/Test_RIPEMD160.h"
#include "Crypto/Test_RIPEMD256.h"
#include "Crypto/Test_RIPEMD320.h"

#include "Crypto/Test_Tiger_3_128.h"
#include "Crypto/Test_Tiger_3_160.h"
#include "Crypto/Test_Tiger_3_192.h"
#include "Crypto/Test_Tiger_4_128.h"
#include "Crypto/Test_Tiger_4_160.h"
#include "Crypto/Test_Tiger_4_192.h"
#include "Crypto/Test_Tiger_5_128.h"
#include "Crypto/Test_Tiger_5_160.h"
#include "Crypto/Test_Tiger_5_192.h"

#include "Crypto/Test_Tiger2_3_128.h"
#include "Crypto/Test_Tiger2_3_160.h"
#include "Crypto/Test_Tiger2_3_192.h"
#include "Crypto/Test_Tiger2_4_128.h"
#include "Crypto/Test_Tiger2_4_160.h"
#include "Crypto/Test_Tiger2_4_192.h"
#include "Crypto/Test_Tiger2_5_128.h"
#include "Crypto/Test_Tiger2_5_160.h"
#include "Crypto/Test_Tiger2_5_192.h"

// Hash32 hashes
#include "Hash32/Test_AP.h"
#include "Hash32/Test_Bernstein.h"
#include "Hash32/Test_Bernstein1.h"
#include "Hash32/Test_BKDR.h"
#include "Hash32/Test_DEK.h"
#include "Hash32/Test_DJB.h"
#include "Hash32/Test_ELF.h"
#include "Hash32/Test_FNV.h"
#include "Hash32/Test_FNV1a.h"
#include "Hash32/Test_Jenkins3.h"
#include "Hash32/Test_JS.h"
#include "Hash32/Test_Murmur2.h"
#include "Hash32/Test_MurmurHash3_x86_32.h"
#include "Hash32/Test_OneAtTime.h"
#include "Hash32/Test_PJW.h"
#include "Hash32/Test_Rotating.h"
#include "Hash32/Test_RS.h"
#include "Hash32/Test_SDBM.h"
#include "Hash32/Test_ShiftAndXor.h"
#include "Hash32/Test_SuperFast.h"
#include "Hash32/Test_XXHash32.h"

// Hash64 hashes
#include "Hash64/Test_FNV64.h"
#include "Hash64/Test_FNV1a.h"
#include "Hash64/Test_Murmur2_64.h"
#include "Hash64/Test_SipHash64_2_4.h"
#include "Hash64/Test_XXHash64.h"

// Hash128 hashes
#include "Hash128/Test_MurmurHash3_x86_128.h"
#include "Hash128/Test_MurmurHash3_x64_128.h"
#include "Hash128/Test_SipHash128_2_4.h"

// NullDigest
#include "NullDigest/Test_NullDigest.h"

// KDF
#include "KDF/Test_PBKDF2_HMAC.h"
#include "KDF/Test_PBKDF_Scrypt.h"
#include "KDF/Test_PBKDF_Blake3.h"
#include "KDF/Test_PBKDFArgon2.h"

// XOF
#include "XOF/Test_Shake_128.h"
#include "XOF/Test_Shake_256.h"
#include "XOF/Test_CShake_128.h"
#include "XOF/Test_CShake_256.h"
#include "XOF/Test_KMAC128XOF.h"
#include "XOF/Test_KMAC256XOF.h"
#include "XOF/Test_Blake2XB.h"
#include "XOF/Test_Blake2XS.h"
#include "XOF/Test_Blake3XOF.h"

// MAC
#include "MAC/Test_MD5_HMAC.h"
#include "MAC/Test_KMAC128.h"
#include "MAC/Test_KMAC256.h"
#include "MAC/Test_Blake2BMAC.h"
#include "MAC/Test_Blake2SMAC.h"

int main( int argc, char* argv[] )
{
  Catch::Session session; // There must be exactly one instance
  
  int height = 0; // Some user variable you want to be able to set
  
  // Build a new parser on top of Catch's
  using namespace Catch::clara;
  auto cli 
    = session.cli() // Get Catch's composite command line parser
    | Opt( height, "height" ) // bind variable to a new option, with a hint string
        ["-g"]["--height"]    // the option names it will respond to
        ("how high?");        // description string for the help output
        
  // Now pass the new composite back to Catch so it uses that
  session.cli( cli ); 
  
  // Let Catch (using Clara) parse the command line
  int returnCode = session.applyCommandLine( argc, argv );
  if( returnCode != 0 ) // Indicates a command line error
      return returnCode;

  // if set on the command line then 'height' is now set at this point
  if( height > 0 )
      std::cout << "height: " << height << std::endl;

  return session.run();
}
