#include<iostream>
using std::wcin;
using std::wcout;
using std::cerr;
using std::endl;

#include <string>
using std::string;
using std::wstring;

/* Convert string*/ 
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;
//Function definition
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

/* Set _setmode()*/ 
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif


/*External library*/
#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;
using CryptoPP::BufferedTransformation;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

#include <cstdlib>
using std::exit;


#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;


#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::Redirector; // string to bytes

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/modes.h"			// ECB, CBC, OFB, CFB, CTR
using CryptoPP::ECB_Mode;
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::OFB_Mode;
using CryptoPP::CTR_Mode;

#include "cryptopp/xts.h"          // XTS
using CryptoPP::XTS_Mode;

#include "cryptopp/gcm.h"          // GCM
using CryptoPP::GCM;

#include "cryptopp/ccm.h"          // CCM
using CryptoPP::CCM;

// comparision
#include "assert.h"

/* Set _setmode()*/ 
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif

string plain, cipher, encoded, recovered;
byte key[32];
byte iv[AES::BLOCKSIZE];

void Getinput()
{
    // Giao diện input
	int ci;
	wcout<<"Chon nguon : 1.Screen 2.File\n";
	wcin>>ci;
	fflush(stdin);
	wstring wplain;
	switch (ci)
	{
	case 1:
	{	// Lấy input từ màng hình ( nếu encrypt thì nhập bình thường còn decrypt thì nhập dạng b64)
        wcout<<"Please input : ";
        getline(wcin,wplain);          // First getline
		fflush(stdin);
        plain = wstring_to_string(wplain);
	}break;
	case 2:
	 {   // LấY input từ file
        string filename;
		wstring wf;
        wcout<<"PLease filename: ";
		wcin>>wf;
		filename = wstring_to_string(wf);
	    FileSource file(filename.c_str(), true, new StringSink(plain));
	 }break;
	default:
	{}break;
	}
}

void GetMaterial(int c=0)
{
    switch (c)
    {
    case 0:
    {
        wcout<<"Chon nguon key va iv: 1.Random 2.Screen 3.File\n";
        int ikv;
	    wcin>>ikv;
        switch (ikv)
        {
        case 1: 
        {
            // iv, key tự sinh
            AutoSeededRandomPool prng;
		    prng.GenerateBlock(key, sizeof(key));
		    prng.GenerateBlock(iv, sizeof(iv));
        }break;
        case 2:
        {
            // iv, key từ màng hình
	        wcout<<"Please key: ";
		    wstring wskey;
		    fflush(stdin);
	        getline(wcin,wskey);         // Second getline
	        string skey = wstring_to_string(wskey);
	        StringSource(skey,true,new HexDecoder( new CryptoPP::ArraySink(key,sizeof(key))));
		    wcout<<"Please iv: ";
		    wstring wiv;
		    fflush(stdin);
	        getline(wcin,wiv);         // Third getline
	        string siv = wstring_to_string(wiv);
	        StringSource(siv,true,new HexDecoder( new CryptoPP::ArraySink(iv,sizeof(iv))));
        }break;
        case 3:
        {
            // iv, key từ file
            wcout<<"Please key filename: ";
            string filekey;
			wstring wk;
            wcin>>wk;
			filekey = wstring_to_string(wk);
	        FileSource fs(filekey.c_str(), false);
	        CryptoPP::ArraySink copykey(key, sizeof(key));
	        fs.Detach(new Redirector(copykey));
	        fs.Pump(sizeof(key));
			StringSource(key,true,new HexDecoder( new CryptoPP::ArraySink(key,sizeof(key))));
			
            wcout<<"Please iv filename: ";
            string fileiv;
			wstring wi;
            wcin>>wi;
			fileiv = wstring_to_string(wi);
	        FileSource fss(fileiv.c_str(), false);
	        CryptoPP::ArraySink copyiv(iv, sizeof(iv));
	        fss.Detach(new Redirector(copyiv));
	        fss.Pump(sizeof(iv));
			StringSource(iv,true,new HexDecoder( new CryptoPP::ArraySink(iv,sizeof(iv))));
        }
        default:
            break;
        }
    }break;
    case 1:
    {
        wcout<<"Chon nguon key : 1.Random 2.Screen 3.File\n";
        int ikv;
	    wcin>>ikv;
        switch (ikv)
        {
        case 1: 
        {
            // key tự sinh
            AutoSeededRandomPool prng;
		    prng.GenerateBlock(key, sizeof(key));
        }break;
        case 2:
        {
            // key từ màng hình
	        wcout<<"Please key: ";
		    wstring wskey;
		    fflush(stdin);
	        getline(wcin,wskey);         // Second getline
	        string skey = wstring_to_string(wskey);
	        StringSource(skey,true,new HexDecoder( new CryptoPP::ArraySink(key,sizeof(key))));
        }break;
        case 3:
        {
            // key từ file
            wcout<<"Please key filename: ";
            string filekey;
			wstring wk;
            wcin>> wk;
			filekey = wstring_to_string(wk);
	        FileSource fs(filekey.c_str(), false);
	        CryptoPP::ArraySink copykey(key, sizeof(key));
	        fs.Detach(new Redirector(copykey));
	        fs.Pump(sizeof(key));
			StringSource(key,true,new HexDecoder( new CryptoPP::ArraySink(key,sizeof(key))));
        }
        default:
            break;
        }   
    }break;
    default:
        break;
    }
}

void Display(int i=0)
{
	if(i==0)
	{
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
	}
	else 
	{
		encoded.clear();
	    StringSource(key, sizeof(key), true,
		    new HexEncoder(
			    new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded) << endl;
	}
}

int ia;
void M_ECB();
void M_CBC();
void M_OFB();
void M_CFB();
void M_CTR();
void M_XTS();
void M_CCM();
void M_GCM();

int main(int argc, char* argv[])
{
    #ifdef __linux__
	setlocale(LC_ALL,"");
	#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
 	_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif
    // Lấy mode (từ màng hình)
	wcout<<"Please mode: 1.ECB 2.CBC 3.OFB 4.CFB 5.CTR 6.XTS 7.CCM 8.GCM\n";
	int im;
	wcin>>im;
    // Lấy hoạt động (từ màng hình)
    wcout<<"Please action: 1.Encypt 2.Decrypt\n";
    wcin>>ia;
    // Gọi model 
    switch (im)
    {
        case 1:
        {
            M_ECB();
        }break;
        case 2:
        {
            M_CBC();
        }break;
        case 3:
        {
            M_OFB();
        }break;
        case 4:
        {
            M_CFB();
        }break;
        case 5:
        {
            M_CTR();
        }break;
        case 6:
        {
            M_XTS();
        }break;
        case 7:
        {
            M_CCM();
        }break;
        case 8:
        {
            M_GCM();
        }break;
        default:
        {}break;
    }

}

// ECB 
void M_ECB()
{
    Getinput();
    GetMaterial(1);
	Display(1);
    switch (ia)
    {
    case 1:
    {
        try
		{
		    ECB_Mode< AES >::Encryption e;
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
	    new Base64Encoder(
			new StringSink(encoded)
		    ) // B64Encoder
	    ); // StringSource
	    wcout << "cipher text: " << string_to_wstring(encoded) << endl;
    }break;
    case 2:
    {
        try 
        {
        StringSource(plain,true,new Base64Decoder(new StringSink(cipher)));
        ECB_Mode< AES >::Decryption d;
		   d.SetKey(key, sizeof(key));
		   StringSource s(cipher, true, 
			   new StreamTransformationFilter(d,
				   new StringSink(recovered)
			   ) 
		   ); 
	    }
	    catch(const CryptoPP::Exception& e)
	    {
		    cerr << e.what() << endl;
		    exit(1);
	    }
        // Pretty print
        wcout << "recovered text: " << string_to_wstring(recovered) << endl;
    }break;
    default:
        break;
    }
}

// CBC
void M_CBC()
{
    Getinput();
    GetMaterial();
	Display();
    switch (ia)
    {
    case 1:
    {
        try
		{
		    CBC_Mode< AES >::Encryption e;
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
	    new Base64Encoder(
			new StringSink(encoded)
		    ) // B64Encoder
	    ); // StringSource
	    wcout << "cipher text: " << string_to_wstring(encoded) << endl;
    }break;
    case 2:
    {
        try 
        {
            StringSource(plain,true,new Base64Decoder(new StringSink(cipher)));
            CBC_Mode< AES >::Decryption d;
		    d.SetKeyWithIV(key, sizeof(key),iv);
		    StringSource s(cipher, true, 
			   new StreamTransformationFilter(d,
				   new StringSink(recovered)
			   ) 
		   ); 
	    }
	    catch(const CryptoPP::Exception& e)
	    {
		    cerr << e.what() << endl;
		    exit(1);
	    }
        // Pretty print
        wcout << "recovered text: " << string_to_wstring(recovered) << endl;
    }break;
    default:
        break;
    }
}

// OFB
void M_OFB()
{
    Getinput();
    GetMaterial();
	Display();
    switch (ia)
    {
    case 1:
    {
        try
		{
		    OFB_Mode< AES >::Encryption e;
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
	    new Base64Encoder(
			new StringSink(encoded)
		    ) // B64Encoder
	    ); // StringSource
	    wcout << "cipher text: " << string_to_wstring(encoded) << endl;
    }break;
    case 2:
    {
        try
	    {
           StringSource(plain,true,new Base64Decoder(new StringSink(cipher)));
		   OFB_Mode< AES >::Decryption d;
		   d.SetKeyWithIV(key, sizeof(key),iv);
		   StringSource s(cipher, true, 
			   new StreamTransformationFilter(d,
				   new StringSink(recovered)
			   ) 
		   ); 
	    }
	    catch(const CryptoPP::Exception& e)
	    {
		    cerr << e.what() << endl;
		    exit(1);
	    }
        wcout << "recovered text: " << string_to_wstring(recovered) << endl;
    }break;
    default:
        break;
    }
}

// CFB
void M_CFB()
{
    Getinput();
    GetMaterial();
	Display();
    switch (ia)
    {
    case 1:
    {
        try
		{
		    CFB_Mode< AES >::Encryption e;
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
	    new Base64Encoder(
			new StringSink(encoded)
		    ) // B64Encoder
	    ); // StringSource
	    wcout << "cipher text: " << string_to_wstring(encoded) << endl;
    }break;
    case 2:
    {
        try
	    {
           StringSource(plain,true,new Base64Decoder(new StringSink(cipher)));
		   CFB_Mode< AES >::Decryption d;
		   d.SetKeyWithIV(key, sizeof(key),iv);
		   StringSource s(cipher, true, 
			   new StreamTransformationFilter(d,
				   new StringSink(recovered)
			   ) 
		   ); 
	    }
	    catch(const CryptoPP::Exception& e)
	    {
		    cerr << e.what() << endl;
		    exit(1);
	    }
        wcout << "recovered text: " << string_to_wstring(recovered) << endl;
    }break;
    default:
        break;
    }
}

//CTR
void M_CTR()
{
    Getinput();
    GetMaterial();
	Display();
    switch (ia)
    {
    case 1:
    {
        try
		{
		    CTR_Mode< AES >::Encryption e;
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
	    new Base64Encoder(
			new StringSink(encoded)
		    ) // B64Encoder
	    ); // StringSource
	    wcout << "cipher text: " << string_to_wstring(encoded) << endl;
    }break;
    case 2:
    {
        try
	    {
           StringSource(plain,true,new Base64Decoder(new StringSink(cipher)));
		   CTR_Mode< AES >::Decryption d;
		   d.SetKeyWithIV(key, sizeof(key),iv);
		   StringSource s(cipher, true, 
			   new StreamTransformationFilter(d,
				   new StringSink(recovered)
			   ) 
		   ); 
	    }
	    catch(const CryptoPP::Exception& e)
	    {
		    cerr << e.what() << endl;
		    exit(1);
	    }
        wcout << "recovered text: " << string_to_wstring(recovered) << endl;
    }
    default:
        break;
    }
}

// XTS
void M_XTS()
{
    Getinput();
    GetMaterial();
	Display();
    switch (ia)
    {
    case 1:
    {
        try
		{
		    XTS_Mode< AES >::Encryption e;
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
	    new Base64Encoder(
			new StringSink(encoded)
		    ) // B64Encoder
	    ); // StringSource
        wcout << "cipher text: " << string_to_wstring(encoded) << endl;
    }break;
    case 2:
    {
        try
	    {
           StringSource(plain,true,new Base64Decoder(new StringSink(cipher)));
		   XTS_Mode< AES >::Decryption d;
		   d.SetKeyWithIV(key, sizeof(key),iv);
		   StringSource s(cipher, true, 
			   new StreamTransformationFilter(d,
				   new StringSink(recovered)
			   ) 
		   ); 
	    }
	    catch(const CryptoPP::Exception& e)
	    {
		    cerr << e.what() << endl;
		    exit(1);
	    }
        wcout << "recovered text: " << string_to_wstring(recovered) << endl;
    }break;
    default:
        break;
    }
}

// CCM
void M_CCM()
{
    Getinput();
    GetMaterial();
	Display();
    switch (ia)
    {
    case 1:
    {
        try
        {
			CCM< AES, 12 >::Encryption e;
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
	    new Base64Encoder(
			new StringSink(encoded)
		    ) // B64Encoder
	    ); // StringSource
	    wcout << "cipher text: " << string_to_wstring(encoded) << endl;
    }break;
    case 2:
    {
        try
	    {
           StringSource(plain,true,new Base64Decoder(new StringSink(cipher)));
		   CCM< AES, 12 >::Decryption d;
		   d.SetKeyWithIV(key, sizeof(key),iv);
		   d.SpecifyDataLengths( 0, cipher.size() - 12, 0 );
		   AuthenticatedDecryptionFilter df( d,
           new StringSink( recovered));
		   StringSource s(cipher, true, 
			   new Redirector(df));
	    }
	    catch(const CryptoPP::Exception& e)
	    {
		    cerr << e.what() << endl;
		    exit(1);
	    }
        wcout << "recovered text: " << string_to_wstring(recovered) << endl;
    }break;
    default:
        break;
    }
}

// GCM
void M_GCM()
{
    Getinput();
    GetMaterial();
	Display();
    switch (ia)
    {
    case 1:
    {
        try
		{
		    GCM< AES >::Encryption e;
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
	    new Base64Encoder(
			new StringSink(encoded)
		    ) // B64Encoder
	    ); // StringSource
	    wcout << "cipher text: " << string_to_wstring(encoded) << endl;
    }break;
    case 2:
    {
        try
	    {
		   StringSource(plain,true,new Base64Decoder(new StringSink(cipher)));
		   GCM< AES >::Decryption d;
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