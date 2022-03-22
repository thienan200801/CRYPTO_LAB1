#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;
using CryptoPP::BufferedTransformation;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

#include <iostream>
using std::wcin;
using std::wcout;
using std::cerr;
using std::endl;

#include <string>
using std::string;
using std::wstring;

#include <cstdlib>
using std::exit;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

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

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/ccm.h"
using CryptoPP::CBC_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;
using CryptoPP::CTR_Mode;
#include "cryptopp/xts.h"
#include "cryptopp/gcm.h"
#include "assert.h"

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

using namespace CryptoPP;

int main(int argc, char* argv[])
{
    #ifdef __linux__
	setlocale(LC_ALL,"");
	#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
 	_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif

    byte key[32];
	byte iv[AES::BLOCKSIZE];
    wcout<<"Please key: ";
	wstring wskey;
	fflush(stdin);
	getline(wcin,wskey);
	string skey = wstring_to_string(wskey);
	StringSource(skey,true,new HexDecoder (new CryptoPP::ArraySink(key,sizeof(key))));
	wcout<<"Please iv: ";
	wstring wiv;
	fflush(stdin);
	getline(wcin,wiv);
	string siv = wstring_to_string(wiv);
	StringSource(siv,true,new HexDecoder (new CryptoPP::ArraySink(iv,sizeof(iv))));
    wcout<<"Please cipher: ";
	wstring wci;
	fflush(stdin);
	getline(wcin,wci);
	string sci = wstring_to_string(wci);
    string cipher, recovered;
    StringSource(sci,true,new Base64Decoder(new StringSink(cipher)));

    try
	    {
		   CBC_Mode< AES >::Decryption d;
		   d.SetKeyWithIV(key, sizeof(key),iv);
		   StringSource s(cipher, true, 
			   new StreamTransformationFilter(d,
				   new StringSink(recovered)
			   ) 
		   ); 
		wcout << "recovered text: " << string_to_wstring(recovered) << endl;
	    }
	    catch(const CryptoPP::Exception& e)
	    {
		    cerr << e.what() << endl;
		    exit(1);
	    }	
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