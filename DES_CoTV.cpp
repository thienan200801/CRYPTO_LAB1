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

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::Redirector; // string to bytes

#include "cryptopp/des.h"
using CryptoPP::DES;

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
	// Giao diện input
	int ci;
	wcout<<"Chon nguon plant: 1.Screen 2.File\n";
	wcin>>ci;
	fflush(stdin);
	wstring wplain;
	string plain;
	switch (ci)
	{
	case 1:
	{	// Lấy input từ màng hình
        wcout<<"Please input : ";
        getline(wcin,wplain);
		fflush(stdin);
        plain = wstring_to_string(wplain);
		wcout<<wplain<<endl;
	}break;
	case 2:
	 {   // LấY input từ file
	    FileSource file("plain.txt",true,new StringSink(plain));
	 }break;
	default:
	{}break;
	}
	// Lấy mode (từ màng hình)
	wcout<<"Please mode: 1.ECB 2.CBC 3.OFB 4.CFB 5.CTR 6.XTS 7.CCM 8.GCM\n";
	int im;
	wcin>>im;
	// Giao diện key, iv
	wcout<<"Chon nguon key va iv: 1.Random 2.Screen 3.File\n";
	int ikv;
	wcin>>ikv;
	byte key[DES::DEFAULT_KEYLENGTH];
	byte iv[DES::BLOCKSIZE];
	switch (ikv)
	{
	case 1:
	{    // iv, key tự sinh
		AutoSeededRandomPool prng;
		prng.GenerateBlock(key, sizeof(key));
		prng.GenerateBlock(iv, sizeof(iv));
	}break;
	case 2:
	{    // iv, key từ màng hình
	    wcout<<"Please key: ";
		wstring wskey;
		fflush(stdin);
	    getline(wcin,wskey);
	    string skey = wstring_to_string(wskey);
	    StringSource(skey,true,new CryptoPP::ArraySink(key,sizeof(key)));
		wcout<<"Please iv: ";
		wstring wiv;
		fflush(stdin);
	    getline(wcin,wiv);
	    string siv = wstring_to_string(wiv);
	    StringSource(siv,true,new CryptoPP::ArraySink(iv,sizeof(iv)));
	}break;
	case 3:
	{   // iv, key từ file
	    FileSource fs("DES_key.key", false);
	    CryptoPP::ArraySink copykey(key, sizeof(key));
	    fs.Detach(new Redirector(copykey));
	    fs.Pump(sizeof(key));
	    FileSource fss("DES_iv.bin", false);
	    CryptoPP::ArraySink copyiv(iv, sizeof(iv));
	    fss.Detach(new Redirector(copyiv));
	    fss.Pump(sizeof(iv));
	}break;
	default:
	{}break;
	}
	string cipher, encoded, recovered;
	// Pretty print key
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded) << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "iv: " << string_to_wstring(encoded) << endl;

	switch (im)
	{
	case 1:
	{    try
		{
		    ECB_Mode< DES >::Encryption e;
		    e.SetKey(key, sizeof(key));
		    StringSource s(plain, true, 
			   new StreamTransformationFilter(e,
				    new StringSink(cipher)
			   ) 
		    );
		}
		catch(const CryptoPP::Exception& e)
		{
			cerr << e.what() << endl;
		    exit(1);
		}
		// Pretty print
	    encoded.clear();
	    StringSource(cipher, true,
	    new HexEncoder(
			new StringSink(encoded)
		    ) // HexEncoder
	    ); // StringSource
	    wcout << "cipher text: " << string_to_wstring(encoded) << endl;
		try
	    {
		   ECB_Mode< DES >::Decryption d;
		   d.SetKey(key, sizeof(key));
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
	}break;
	case 2:
	{
		try
		{
		    CBC_Mode< DES >::Encryption e;
		    e.SetKeyWithIV(key, sizeof(key),iv);
		    StringSource s(plain, true, 
			   new StreamTransformationFilter(e,
				    new StringSink(cipher)
			   ) 
		    );
		}
		catch(const CryptoPP::Exception& e)
		{
			cerr << e.what() << endl;
		    exit(1);
		}
		// Pretty print
	    encoded.clear();
	    StringSource(cipher, true,
	    new HexEncoder(
			new StringSink(encoded)
		    ) // HexEncoder
	    ); // StringSource
	    wcout << "cipher text: " << string_to_wstring(encoded) << endl;
		try
	    {
		   CBC_Mode< DES >::Decryption d;
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
	}break;
	case 3:
	{
		try
		{
		    CFB_Mode< DES >::Encryption e;
		    e.SetKeyWithIV(key, sizeof(key),iv);
		    StringSource s(plain, true, 
			   new StreamTransformationFilter(e,
				    new StringSink(cipher)
			   ) 
		    );
		}
		catch(const CryptoPP::Exception& e)
		{
			cerr << e.what() << endl;
		    exit(1);
		}
		// Pretty print
	    encoded.clear();
	    StringSource(cipher, true,
	    new HexEncoder(
			new StringSink(encoded)
		    ) // HexEncoder
	    ); // StringSource
	    wcout << "cipher text: " << string_to_wstring(encoded) << endl;
		try
	    {
		   CFB_Mode< DES >::Decryption d;
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
	}break;
	case 4:
	{
		try
		{
		    OFB_Mode< DES >::Encryption e;
		    e.SetKeyWithIV(key, sizeof(key),iv);
		    StringSource s(plain, true, 
			   new StreamTransformationFilter(e,
				    new StringSink(cipher)
			   ) 
		    );
		}
		catch(const CryptoPP::Exception& e)
		{
			cerr << e.what() << endl;
		    exit(1);
		}
		// Pretty print
	    encoded.clear();
	    StringSource(cipher, true,
	    new HexEncoder(
			new StringSink(encoded)
		    ) // HexEncoder
	    ); // StringSource
	    wcout << "cipher text: " << string_to_wstring(encoded) << endl;
		try
	    {
		   OFB_Mode< DES >::Decryption d;
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
	}break;
	case 5:
	{
		try
		{
		    CTR_Mode< DES >::Encryption e;
		    e.SetKeyWithIV(key, sizeof(key),iv);
		    StringSource s(plain, true, 
			   new StreamTransformationFilter(e,
				    new StringSink(cipher)
			   ) 
		    );
		}
		catch(const CryptoPP::Exception& e)
		{
			cerr << e.what() << endl;
		    exit(1);
		}
		// Pretty print
	    encoded.clear();
	    StringSource(cipher, true,
	    new HexEncoder(
			new StringSink(encoded)
		    ) // HexEncoder
	    ); // StringSource
	    wcout << "cipher text: " << string_to_wstring(encoded) << endl;
		try
	    {
		   CTR_Mode< DES >::Decryption d;
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
	}break;
	case 6:
	{
		try
		{
		    XTS_Mode< DES >::Encryption e;
		    e.SetKeyWithIV(key, sizeof(key),iv);
		    StringSource s(plain, true, 
			   new StreamTransformationFilter(e,
				    new StringSink(cipher)
			   ) 
		    );
		}
		catch(const CryptoPP::Exception& e)
		{
			cerr << e.what() << endl;
		    exit(1);
		}
		// Pretty print
	    encoded.clear();
	    StringSource(cipher, true,
	    new HexEncoder(
			new StringSink(encoded)
		    ) // HexEncoder
	    ); // StringSource
	    wcout << "cipher text: " << string_to_wstring(encoded) << endl;
		try
	    {
		   XTS_Mode< DES >::Decryption d;
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
	}break;
	case 7:
	{
		try
		{
		    CCM< DES, 12 >::Encryption e;
		    e.SetKeyWithIV(key, sizeof(key),iv);
		    e.SpecifyDataLengths( 0, plain.size(), 0 );
		    StringSource s(plain, true, 
			   new AuthenticatedEncryptionFilter(e,
				    new StringSink(cipher)
			   ) 
		    );
		}
		catch(const CryptoPP::Exception& e)
		{
			cerr << e.what() << endl;
		    exit(1);
		}
		// Pretty print
	    encoded.clear();
	    StringSource(cipher, true,
	    new HexEncoder(
			new StringSink(encoded)
		    ) // HexEncoder
	    ); // StringSource
	    wcout << "cipher text: " << string_to_wstring(encoded) << endl;
		try
	    {
		   CCM< DES, 12 >::Decryption d;
		   d.SetKeyWithIV(key, sizeof(key),iv);
		   d.SpecifyDataLengths( 0, cipher.size()- 12, 0 );
		   AuthenticatedDecryptionFilter df( d,
           new StringSink( recovered));
		   StringSource s(cipher, true, 
			   new Redirector(df));
		wcout << "recovered text: " << string_to_wstring(recovered) << endl;
	    }
	    catch(const CryptoPP::Exception& e)
	    {
		    cerr << e.what() << endl;
		    exit(1);
	    }
	}break;
	case 8:
	{
		try
		{
		    GCM< DES >::Encryption e;
		    e.SetKeyWithIV(key, sizeof(key),iv);
		    StringSource s(plain, true, 
			   new AuthenticatedEncryptionFilter(e,
				    new StringSink(cipher)
			   ) 
		    );
		}
		catch(const CryptoPP::Exception& e)
		{
			cerr << e.what() << endl;
		    exit(1);
		}
		// Pretty print
	    encoded.clear();
	    StringSource(cipher, true,
	    new HexEncoder(
			new StringSink(encoded)
		    ) // HexEncoder
	    ); // StringSource
	    wcout << "cipher text: " << string_to_wstring(encoded) << endl;
		try
	    {
		   GCM< DES >::Decryption d;
		   d.SetKeyWithIV(key, sizeof(key),iv);
		   StringSource s(cipher, true, 
			new AuthenticatedDecryptionFilter(d,
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
	}break;
	default:
		break;
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
