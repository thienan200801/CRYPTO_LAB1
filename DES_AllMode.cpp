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

using CryptoPP::Redirector; // string to bytes

#include "cryptopp/des.h"
using CryptoPP::DES;

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

string plain, cipher, encoded, recovered;    // global variable
byte key[DES::DEFAULT_KEYLENGTH];             
byte iv[DES::BLOCKSIZE];  

// Get plaintext or ciphertext
void Getinput()
{
    // Giao di???n input
	int ci;
	wcout<<"Chon nguon : 1.Screen 2.File\n";
	wcin>>ci;
	fflush(stdin);
	wstring wplain;
	switch (ci)
	{
	case 1:
	{	// L???y input t??? m??ng h??nh ( n???u encrypt th?? nh???p b??nh th?????ng c??n decrypt th?? nh???p d???ng b64)
        wcout<<"Please input : ";
        getline(wcin,wplain);          // First getline
		fflush(stdin);
        plain = wstring_to_string(wplain);
	}break;
	case 2:
	 {   // L???y input t??? file
        string filename;
		wstring wf;
        wcout<<"PLease filename: ";  //get filename to string
		wcin>>wf;
		filename = wstring_to_string(wf);
	    FileSource file(filename.c_str(), true, new StringSink(plain));  // put cipher or plain in plain variable
	 }break;
	default:
	{}break;
	}
}

// Get key, iv, nan
void GetMaterial(int c=0)
{
    switch (c)
    {
    case 0:  // Cho c??c mode c?? d??ng iv v?? key: CBC, OFB, CFB, CTR, CCM, GCM
    {
		// Giao di???n 
        wcout<<"Chon nguon key va iv/nan: 1.Random 2.Screen 3.File\n";
        int ikv;
	    wcin>>ikv;
        switch (ikv)
        {
        case 1: 
        {
            // iv/nan, key t??? sinh
            AutoSeededRandomPool prng;
		    prng.GenerateBlock(key, sizeof(key));
		    prng.GenerateBlock(iv, sizeof(iv));
        }break;
        case 2:
        {
            // iv, key t??? m??ng h??nh
	        wcout<<"Please key: ";        // key nh???p t??? m??ng h??nh s??? ??? d???ng hex
		    wstring wskey;
	        wcin>>wskey;         
	        string skey = wstring_to_string(wskey);
	        StringSource(skey,true,new HexDecoder( new CryptoPP::ArraySink(key,sizeof(key))));
			
			wcout<<"Please iv/nan: ";         // iv/nan nh???p t??? m??ng h??nh s??? ??? d???ng hex 
		    wstring wiv;
	        wcin>>wiv;       
	        string siv = wstring_to_string(wiv);
	        StringSource(siv,true,new HexDecoder( new CryptoPP::ArraySink(iv,sizeof(iv))));
        }break;
        case 3:
        {
            // iv, key t??? file
			// get key 
            wcout<<"Please key filename: ";         // L???y t??n file ch???a key
            string filekey, hexkey;
			wstring wk;
            wcin>>wk;
			filekey = wstring_to_string(wk);
			// key ???????c l??u ??? d???ng hex trong file n??n c???n decode tr?????c khi g??n v??o key variable
	        FileSource fs(filekey.c_str(), true,new HexDecoder( new CryptoPP::ArraySink(key, sizeof(key))));;
			
			// get iv
            wcout<<"Please iv/nan filename: ";          // L???y t??n file ch???a iv
            string fileiv;
			wstring wi;
            wcin>>wi;
			fileiv = wstring_to_string(wi);
			// iv ???????c l??u ??? d???ng hex trong file n??n c???n decode tr?????c khi g??n v??o iv variable
			FileSource fss(fileiv.c_str(), true,new HexDecoder( new CryptoPP::ArraySink(iv, sizeof(iv))));
        }
        default:
            break;
        }
    }break;
    case 1: // Cho mode ECB 
    {
        wcout<<"Chon nguon key : 1.Random 2.Screen 3.File\n";
        int ikv;
	    wcin>>ikv;
        switch (ikv)
        {
        case 1: 
        {
            // key t??? sinh
            AutoSeededRandomPool prng;
		    prng.GenerateBlock(key, sizeof(key));
        }break;
        case 2:
        {
            // key t??? m??ng h??nh
	        wcout<<"Please key: ";
		    wstring wskey;
		    fflush(stdin);
	        getline(wcin,wskey);         // Second getline
	        string skey = wstring_to_string(wskey);
	        StringSource(skey,true,new HexDecoder( new CryptoPP::ArraySink(key,sizeof(key))));
        }break;
        case 3:
        {
            // key t??? file
            wcout<<"Please key filename: ";   // L???y t??n file ch???a key
            string filekey;
			wstring wk;
            wcin>> wk;
			filekey = wstring_to_string(wk);
            // key ???????c l??u ??? d???ng hex trong file n??n c???n decode tr?????c khi g??n v??o key variable
	        FileSource fs(filekey.c_str(), true,new HexDecoder( new CryptoPP::ArraySink(key, sizeof(key))));;
        }
        default:
            break;
        }   
    }break;
    default:
        break;
    }
}

// Show gi?? tr??? c???a key, iv, nan ??? d???ng hex
void Display(int i=0)
{
	if(i==0)      // Cho c??c mode c?? d??ng iv v?? key: CBC, OFB, CFB, CTR, CCM, GCM
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
	else      // Cho mode ECB ch??? d??ng ?????n key
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

// Save to some file
void savefile (string input)
{
	
	wcout<<"filename: ";        // Get filename
	string filename;
	wstring wf;
    wcin>> wf;
	filename = wstring_to_string(wf);
	StringSource s(input, true, new FileSink(filename.c_str()));    // save to file
}

int ia;
void M_ECB();
void M_CBC();
void M_OFB();
void M_CFB();
void M_CTR();

int main(int argc, char* argv[])
{
	// setup mode h??? ??i???u h??nh
    #ifdef __linux__
	setlocale(LC_ALL,"");
	#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
 	_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif
	wcout<<"*********************************" << endl << "               DES\n" << "*********************************\n";
    // L???y mode (t??? m??ng h??nh)
	wcout<<"Please mode: 1.ECB 2.CBC 3.OFB 4.CFB 5.CTR \n";
	int im;
	wcin>>im;
    // L???y ho???t ?????ng (t??? m??ng h??nh)
    wcout<<"Please action: 1.Encypt 2.Decrypt\n";
    wcin>>ia;
    // G???i mode
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
        default:
        {}break;
    }

}

// ECB 
void M_ECB()
{
	// prepare
    Getinput();
    GetMaterial(1);
	Display(1);

    switch (ia)
    {
    case 1:   // Encrypt
    {
        try
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
        // Pretty print cipher
	    encoded.clear();
	    StringSource(cipher, true,
	    new Base64Encoder(
			new StringSink(encoded)
		    ) // B64Encoder
	    ); // StringSource
	    wcout << "cipher text: " << string_to_wstring(encoded) << endl;
		
		// Save to file
		wcout << "Save to file? 1.Yes 2.No\n";
		int is;
		wcin>>is;
		if(is==1) savefile(encoded);
    }break;
    case 2:    //Decrypt
    {
        try 
        {
        StringSource(plain,true,new Base64Decoder(new StringSink(cipher)));
        ECB_Mode< DES >::Decryption d;
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
        // Pretty print plain
        wcout << "recovered text: " << string_to_wstring(recovered) << endl;

		// Save to file
		wcout << "Save to file? 1.Yes 2.No\n";
		int is;
		wcin>>is;
		if(is==1) savefile(encoded);
    }break;
    default:
        break;
    }
}

// CBC
void M_CBC()
{
	// prepare
    Getinput();
    GetMaterial();
	Display();

    switch (ia)
    {
    case 1:    // Encrypt
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
		// Pretty print cipher
	    encoded.clear();
	    StringSource(cipher, true,
	    new Base64Encoder(
			new StringSink(encoded)
		    ) // B64Encoder
	    ); // StringSource
	    wcout << "cipher text: " << string_to_wstring(encoded) << endl;

		// Save to file
		wcout << "Save to file? 1.Yes 2.No\n";
		int is;
		wcin>>is;
		if(is==1) savefile(encoded);
    }break;
    case 2:     // Decrypt
    {
        try 
        {
            StringSource(plain,true,new Base64Decoder(new StringSink(cipher)));
            CBC_Mode< DES >::Decryption d;
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
        // Pretty print plain
        wcout << "recovered text: " << string_to_wstring(recovered) << endl;

		// Save to file
		wcout << "Save to file? 1.Yes 2.No\n";
		int is;
		wcin>>is;
		if(is==1) savefile(encoded);
    }break;
    default:
        break;
    }
}

// OFB
void M_OFB()
{
	// prepare
    Getinput();
    GetMaterial();
	Display();

    switch (ia)
    {
    case 1:    // Encrypt
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
		// Pretty print cipher
	    encoded.clear();
	    StringSource(cipher, true,
	    new Base64Encoder(
			new StringSink(encoded)
		    ) // B64Encoder
	    ); // StringSource
	    wcout << "cipher text: " << string_to_wstring(encoded) << endl;

		// Save to file
		wcout << "Save to file? 1.Yes 2.No\n";
		int is;
		wcin>>is;
		if(is==1) savefile(encoded);
    }break;
    case 2:    // Decrypt
    {
        try
	    {
           StringSource(plain,true,new Base64Decoder(new StringSink(cipher)));
		   OFB_Mode< DES >::Decryption d;
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
		// Pretty print plain
        wcout << "recovered text: " << string_to_wstring(recovered) << endl;

		// Save to file
		wcout << "Save to file? 1.Yes 2.No\n";
		int is;
		wcin>>is;
		if(is==1) savefile(encoded);
    }break;
    default:
        break;
    }
}

// CFB
void M_CFB()
{
	// prepare
    Getinput();
    GetMaterial();
	Display();

    switch (ia)
    {
    case 1:    // Encrypt
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
		// Pretty print cipher
	    encoded.clear();
	    StringSource(cipher, true,
	    new Base64Encoder(
			new StringSink(encoded)
		    ) // B64Encoder
	    ); // StringSource
	    wcout << "cipher text: " << string_to_wstring(encoded) << endl;

		// Save to file
		wcout << "Save to file? 1.Yes 2.No\n";
		int is;
		wcin>>is;
		if(is==1) savefile(encoded);
    }break;
    case 2:    // Decrypt
    {
        try
	    {
           StringSource(plain,true,new Base64Decoder(new StringSink(cipher)));
		   CFB_Mode< DES >::Decryption d;
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
		// Pretty print plain
        wcout << "recovered text: " << string_to_wstring(recovered) << endl;

		// Save to file
		wcout << "Save to file? 1.Yes 2.No\n";
		int is;
		wcin>>is;
		if(is==1) savefile(encoded);
    }break;
    default:
        break;
    }
}

//CTR
void M_CTR()
{
	// prepare
    Getinput();
    GetMaterial();
	Display();

    switch (ia)
    {
    case 1:
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
		// Pretty print cipher
	    encoded.clear();
	    StringSource(cipher, true,
	    new Base64Encoder(
			new StringSink(encoded)
		    ) // B64Encoder
	    ); // StringSource
	    wcout << "cipher text: " << string_to_wstring(encoded) << endl;

		// Save to file
		wcout << "Save to file? 1.Yes 2.No\n";
		int is;
		wcin>>is;
		if(is==1) savefile(encoded);
    }break;
    case 2:
    {
        try
	    {
           StringSource(plain,true,new Base64Decoder(new StringSink(cipher)));
		   CTR_Mode< DES >::Decryption d;
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
		// Pretty print plain
        wcout << "recovered text: " << string_to_wstring(recovered) << endl;

		// Save to file
		wcout << "Save to file? 1.Yes 2.No\n";
		int is;
		wcin>>is;
		if(is==1) savefile(encoded);
    }
    default:
        break;
    }
}

// XTS
// void M_XTS()
// {
// 	// prepare
//     Getinput();
//     GetMaterial();
// 	Display();

//     switch (ia)
//     {
//     case 1:
//     {
//         try
// 		{
// 		    XTS_Mode< DES >::Encryption e;
// 		    e.SetKeyWithIV(key, sizeof(key),iv);
// 		    StringSource s(plain, true, 
// 			   new StreamTransformationFilter(e,
// 				    new StringSink(cipher)
// 			   ) 
// 		    );
// 		}
// 		catch(const CryptoPP::Exception& e)
// 		{
// 			cerr << e.what() << endl;
// 		    exit(1);
// 		}
// 		// Pretty print cipher
// 	    encoded.clear();
// 	    StringSource(cipher, true,
// 	    new Base64Encoder(
// 			new StringSink(encoded)
// 		    ) // B64Encoder
// 	    ); // StringSource
//         wcout << "cipher text: " << string_to_wstring(encoded) << endl;

// 		// Save to file
// 		wcout << "Save to file? 1.Yes 2.No\n";
// 		int is;
// 		wcin>>is;
// 		if(is==1) savefile(encoded);
//     }break;
//     case 2:
//     {
//         try
// 	    {
//            StringSource(plain,true,new Base64Decoder(new StringSink(cipher)));
// 		   XTS_Mode< DES >::Decryption d;
// 		   d.SetKeyWithIV(key, sizeof(key),iv);
// 		   StringSource s(cipher, true, 
// 			   new StreamTransformationFilter(d,
// 				   new StringSink(recovered)
// 			   ) 
// 		   ); 
// 	    }
// 	    catch(const CryptoPP::Exception& e)
// 	    {
// 		    cerr << e.what() << endl;
// 		    exit(1);
// 	    }
// 		// Pretty print plain
//         wcout << "recovered text: " << string_to_wstring(recovered) << endl;

// 		// Save to file
// 		wcout << "Save to file? 1.Yes 2.No\n";
// 		int is;
// 		wcin>>is;
// 		if(is==1) savefile(encoded);
//     }break;
//     default:
//         break;
//     }
// }

// // CCM
// void M_CCM()
// {
// 	// prepare
//     Getinput();
//     GetMaterial();
// 	Display();

//     switch (ia)
//     {
//     case 1:
//     {
//         try
//         {
// 			CCM< DES, 12 >::Encryption e;
// 		    e.SetKeyWithIV(key, sizeof(key),iv);
// 		    e.SpecifyDataLengths( 0, plain.size(), 0 );
// 		    StringSource s(plain, true, 
// 			   new AuthenticatedEncryptionFilter(e,
// 				    new StringSink(cipher)
// 			   ) 
// 		    );
// 		}
// 		catch(const CryptoPP::Exception& e)
// 		{
// 			cerr << e.what() << endl;
// 		    exit(1);
// 		}
// 		// Pretty print cipher
// 	    encoded.clear();
// 	    StringSource(cipher, true,
// 	    new Base64Encoder(
// 			new StringSink(encoded)
// 		    ) // B64Encoder
// 	    ); // StringSource
// 	    wcout << "cipher text: " << string_to_wstring(encoded) << endl;

// 		// Save to file
// 		wcout << "Save to file? 1.Yes 2.No\n";
// 		int is;
// 		wcin>>is;
// 		if(is==1) savefile(encoded);
//     }break;
//     case 2:
//     {
//         try
// 	    {
//            StringSource(plain,true,new Base64Decoder(new StringSink(cipher)));
// 		   CCM< DES, 12 >::Decryption d;
// 		   d.SetKeyWithIV(key, sizeof(key),iv);
// 		   d.SpecifyDataLengths( 0, cipher.size() - 12, 0 );
// 		   AuthenticatedDecryptionFilter df( d,
//            new StringSink( recovered));
// 		   StringSource s(cipher, true, 
// 			   new Redirector(df));
// 	    }
// 	    catch(const CryptoPP::Exception& e)
// 	    {
// 		    cerr << e.what() << endl;
// 		    exit(1);
// 	    }
// 		// Pretty print plain
//         wcout << "recovered text: " << string_to_wstring(recovered) << endl;

// 		// Save to file
// 		wcout << "Save to file? 1.Yes 2.No\n";
// 		int is;
// 		wcin>>is;
// 		if(is==1) savefile(encoded);
//     }break;
//     default:
//         break;
//     }
// }

// // GCM
// void M_GCM()
// {
// 	//prepare
//     Getinput();
//     GetMaterial();
// 	Display();

//     switch (ia)
//     {
//     case 1:
//     {
//         try
// 		{
// 		    GCM< DES >::Encryption e;
// 		    e.SetKeyWithIV(key, sizeof(key),iv);
// 		    StringSource s(plain, true, 
// 			   new AuthenticatedEncryptionFilter(e,
// 				    new StringSink(cipher)
// 			   ) 
// 		    );
// 		}
// 		catch(const CryptoPP::Exception& e)
// 		{
// 			cerr << e.what() << endl;
// 		    exit(1);
// 		}
// 		// Pretty print cipher
// 	    encoded.clear();
// 	    StringSource(cipher, true,
// 	    new Base64Encoder(
// 			new StringSink(encoded)
// 		    ) // B64Encoder
// 	    ); // StringSource
// 	    wcout << "cipher text: " << string_to_wstring(encoded) << endl;

// 		// Save to file
// 		wcout << "Save to file? 1.Yes 2.No\n";
// 		int is;
// 		wcin>>is;
// 		if(is==1) savefile(encoded);
//     }break;
//     case 2:
//     {
//         try
// 	    {
// 		   StringSource(plain,true,new Base64Decoder(new StringSink(cipher)));
// 		   GCM< DES >::Decryption d;
// 		   d.SetKeyWithIV(key, sizeof(key),iv);
// 		   StringSource s(cipher, true, 
// 			new AuthenticatedDecryptionFilter(d,
// 				new StringSink(recovered)
// 			) 
// 		); 
// 		// Pretty print plain
// 		wcout << "recovered text: " << string_to_wstring(recovered) << endl;

// 		// Save to file
// 		wcout << "Save to file? 1.Yes 2.No\n";
// 		int is;
// 		wcin>>is;
// 		if(is==1) savefile(encoded);
// 	    }
// 	    catch(const CryptoPP::Exception& e)
// 	    {
// 		    cerr << e.what() << endl;
// 		    exit(1);
// 	    }
//     }break;
//     default:
//         break;
//     }
// }