#include <iostream>
#include <string>
using namespace std;

/* Set _setmode()*/ 
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif

/* Convert string*/ 
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8;
wstring string_to_wstring (const std::string& str);
string wstring_to_string (const std::wstring& str);

#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;
using CryptoPP::BufferedTransformation;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::Redirector; // string to bytes

int main()
{
    #ifdef __linux__
	setlocale(LC_ALL,"");
	#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
 	_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif

  wstring wskey;
  wcout<<"Please input key: ";
  getline(wcin,wskey);//wcin.ignore();

  string inkey;
  inkey= wstring_to_string(wskey); 
  //Print 8 bytes
  CryptoPP::byte key[9];
  StringSource(inkey,true,new CryptoPP::ArraySink(key,sizeof(key)-1));
  wcout << "Get 8byte: " << key << endl;
  
  //String to hex
  string hexstring;
  StringSource(inkey,true,new HexEncoder(new StringSink(hexstring)));
  wcout << "Hex Ciphertext: " << string_to_wstring(hexstring) << endl;
  
  //Hex to string
  string hexDecode;
  StringSource(hexstring,true,new HexDecoder(new StringSink(hexDecode)));
  wcout << "Plaintext From Hex: " << string_to_wstring(hexDecode) <<endl;
  
  //String to b64
  string b64Encode;
  StringSource(inkey,true,new Base64Encoder(new StringSink(b64Encode)));
  wcout << "B64Cipher: " << string_to_wstring(b64Encode) << endl;
  ./
  //b64 to plaintext 
  string b64Decode;
  StringSource(b64Encode,true,new Base64Decoder(new StringSink(b64Decode)));
  wcout << "PlantextFromB64: " << string_to_wstring(b64Decode);
}

/* convert string to wstring */
wstring string_to_wstring (const std::string& str)
{
    wstring_convert<codecvt_utf8<wchar_t> > towstring;
    return towstring.from_bytes(str);
}

/* convert wstring to string */
string wstring_to_string (const std::wstring& str)
{
    wstring_convert<codecvt_utf8<wchar_t> > tostring;
    return tostring.to_bytes(str);
}