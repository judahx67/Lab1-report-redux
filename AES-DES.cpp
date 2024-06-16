#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
#include <chrono> //for benchmarkng
#include <cstring>
#include <iostream>
using std::cerr;
using std::cout;
using std::endl;

#include <string>
using std::string;
#include "cryptopp/des.h"
#include <cstdlib>
using std::exit;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "cryptopp/filters.h"
using CryptoPP::ArraySink;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/modes.h"
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;

#include "cryptopp/ccm.h"
using CryptoPP::CCM;

#include "cryptopp/gcm.h"
using CryptoPP::GCM;

#ifdef CRYPTOPP_XTS_MODE
#include "cryptopp/xts.h"
using CryptoPP::XTS_Mode;
#endif

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "assert.h"

#include <cstdlib>
#include <locale>
#include <cctype>

using namespace CryptoPP;
int getMode(const std::string &modeStr)
{
    if (modeStr == "CBC")
        return 0;
    if (modeStr == "ECB")
        return 1;
    if (modeStr == "OFB")
        return 2;
    if (modeStr == "CFB")
        return 3;
    if (modeStr == "CTR")
        return 4;
#ifdef CRYPTOPP_XTS_MODE
    if (modeStr == "XTS")
        return 5;
#endif
    if (modeStr == "CCM")
        return 6;
    if (modeStr == "GCM")
        return 7;
    if (modeStr == "DES-CBC")
        return 8;
    if (modeStr == "DES-ECB")
        return 9;
    if (modeStr == "DES-OFB")
        return 10;
    if (modeStr == "DES-CFB")
        return 11;
    if (modeStr == "DES-CTR")
        return 12;
    return -1;
}
int getKeySize(const std::string &mode, int keysize)
{
    switch (getMode(mode))
    {
    case 0: // CBC
    case 1: // ECB
    case 2: // OFB
    case 3: // CFB
    case 4: // CTR
    case 5: // XTS
    case 6: // CCM
    case 7: // GCM
        return keysize;
    case 8:  // DES-CBC
    case 9:  // DES-ECB
    case 10: // DES-OFB
    case 11: // DES-CFB
    case 12: // DES-CTR
        return 64;
    default:
        return 0;
    }
}
std::string Encrypt(const std::string &plainText, const byte *key, const byte *iv, string mode, int keysize, const byte *aad = nullptr, size_t aad_len = 0)
{
    std::string cipherText;
    try
    {
        int keySizeBytes = getKeySize(mode, keysize) / 8;
        switch (getMode(mode))
        {
        case 0:
        {
            CBC_Mode<AES>::Encryption encryptor;
            encryptor.SetKeyWithIV(key, keySizeBytes, iv);
            StringSource(plainText, true,
                         new StreamTransformationFilter(encryptor,
                                                        new StringSink(cipherText)));
            break;
        }
        case 1:
        {
            ECB_Mode<AES>::Encryption encryptor;
            encryptor.SetKey(key, keySizeBytes);
            StringSource(plainText, true,
                         new StreamTransformationFilter(encryptor,
                                                        new StringSink(cipherText)));
            break;
        }
        case 2:
        {
            OFB_Mode<AES>::Encryption encryptor;
            encryptor.SetKeyWithIV(key, keySizeBytes, iv);
            StringSource(plainText, true,
                         new StreamTransformationFilter(encryptor,
                                                        new StringSink(cipherText)));
            break;
        }
        case 3:
        {
            CFB_Mode<AES>::Encryption encryptor;
            encryptor.SetKeyWithIV(key, keySizeBytes, iv);
            StringSource(plainText, true,
                         new StreamTransformationFilter(encryptor,
                                                        new StringSink(cipherText)));
            break;
        }
        case 4:
        {
            CTR_Mode<AES>::Encryption encryptor;
            encryptor.SetKeyWithIV(key, keySizeBytes, iv);
            StringSource(plainText, true,
                         new StreamTransformationFilter(encryptor,
                                                        new StringSink(cipherText)));
            break;
        }
#ifdef CRYPTOPP_XTS_MODE
        case 5:
        {
            XTS_Mode<AES>::Encryption encryptor;
            encryptor.SetKeyWithIV(key, keySizeBytes * 2, iv);
            StringSource(plainText, true,
                         new StreamTransformationFilter(encryptor,
                                                        new StringSink(cipherText)));
            break;
        }
#endif
        case 6: // CCM
        {
            const int CCM_IV_LENGTH = 13; // Adjust the IV length as needed
            CCM<AES>::Encryption encryptor;
            encryptor.SetKeyWithIV(key, keySizeBytes, iv, CCM_IV_LENGTH);
            encryptor.SpecifyDataLengths(aad_len, plainText.size(), 0);
            StringSource(plainText, true,
                         new AuthenticatedEncryptionFilter(encryptor,
                                                           new StringSink(cipherText),
                                                           false, aad_len));
            break;
        }

        case 7:
        {
            GCM<AES>::Encryption encryptor;
            encryptor.SetKeyWithIV(key, keySizeBytes, iv);
            StringSource(plainText, true,
                         new AuthenticatedEncryptionFilter(encryptor,
                                                           new StringSink(cipherText), false, aad_len));
            break;
        }

        case 8:
        {
            CBC_Mode<DES>::Encryption encryptor;
            encryptor.SetKeyWithIV(key, DES::DEFAULT_KEYLENGTH, iv);
            StringSource(plainText, true,
                         new StreamTransformationFilter(encryptor,
                                                        new StringSink(cipherText)));
            break;
        }
        case 9:
        {
            ECB_Mode<DES>::Encryption encryptor;
            encryptor.SetKey(key, DES::DEFAULT_KEYLENGTH);
            StringSource(plainText, true,
                         new StreamTransformationFilter(encryptor,
                                                        new StringSink(cipherText)));
            break;
        }
        case 10:
        {
            OFB_Mode<DES>::Encryption encryptor;
            encryptor.SetKeyWithIV(key, DES::DEFAULT_KEYLENGTH, iv);
            StringSource(plainText, true,
                         new StreamTransformationFilter(encryptor,
                                                        new StringSink(cipherText)));
            break;
        }
        case 11:
        {
            CFB_Mode<DES>::Encryption encryptor;
            encryptor.SetKeyWithIV(key, DES::DEFAULT_KEYLENGTH, iv);
            StringSource(plainText, true,
                         new StreamTransformationFilter(encryptor,
                                                        new StringSink(cipherText)));
            break;
        }
        case 12:
        {
            CTR_Mode<DES>::Encryption encryptor;
            encryptor.SetKeyWithIV(key, DES::DEFAULT_KEYLENGTH, iv);
            StringSource(plainText, true,
                         new StreamTransformationFilter(encryptor,
                                                        new StringSink(cipherText)));
            break;
        }
        }
    }
    catch (const Exception &ex)
    {
        std::cerr << "Encryption error: " << ex.what() << std::endl;
    }
    return cipherText;
}

std::string Decrypt(const std::string &cipherText, const byte *key, const byte *iv, string mode, int keysize, const byte *aad = nullptr, size_t aad_len = 0)
{
    std::string decrypted;
    try
    {
        int keySizeBytes = getKeySize(mode, keysize) / 8;
        switch (getMode(mode))
        {
        case 0:
        {
            CBC_Mode<AES>::Decryption decryptor;
            decryptor.SetKeyWithIV(key, keySizeBytes, iv);
            StringSource(cipherText, true,
                         new StreamTransformationFilter(decryptor,
                                                        new StringSink(decrypted)));
            break;
        }
        case 1:
        {
            ECB_Mode<AES>::Decryption decryptor;
            decryptor.SetKey(key, keySizeBytes);
            StringSource(cipherText, true,
                         new StreamTransformationFilter(decryptor,
                                                        new StringSink(decrypted)));
            break;
        }
        case 2:
        {
            OFB_Mode<AES>::Decryption decryptor;
            decryptor.SetKeyWithIV(key, keySizeBytes, iv);
            StringSource(cipherText, true,
                         new StreamTransformationFilter(decryptor,
                                                        new StringSink(decrypted)));
            break;
        }
        case 3:
        {
            CFB_Mode<AES>::Decryption decryptor;
            decryptor.SetKeyWithIV(key, keySizeBytes, iv);
            StringSource(cipherText, true,
                         new StreamTransformationFilter(decryptor,
                                                        new StringSink(decrypted)));
            break;
        }
        case 4:
        {
            CTR_Mode<AES>::Decryption decryptor;
            decryptor.SetKeyWithIV(key, keySizeBytes, iv);
            StringSource(cipherText, true,
                         new StreamTransformationFilter(decryptor,
                                                        new StringSink(decrypted)));
            break;
        }
#ifdef CRYPTOPP_XTS_MODE
        case 5:
        {
            XTS_Mode<AES>::Decryption decryptor;
            decryptor.SetKeyWithIV(key, keySizeBytes * 2, iv);
            StringSource(cipherText, true,
                         new StreamTransformationFilter(decryptor,
                                                        new StringSink(decrypted)));
            break;
        }
#endif
        case 6: // CCM
        {
            // This is where dreams go to die
            const int CCM_IV_LENGTH = 13; // Adjust the IV length as needed
            CCM<AES>::Decryption decryptor;
            decryptor.SetKeyWithIV(key, keySizeBytes, iv, CCM_IV_LENGTH);
            // decryptor.SpecifyDataLengths(aad_len, 0, cipherText.size() - CCM<AES>::DIGESTSIZE);
            StringSource(cipherText, true,
                         new AuthenticatedDecryptionFilter(decryptor,
                                                           new StringSink(decrypted),
                                                           AuthenticatedDecryptionFilter::THROW_EXCEPTION, aad_len));
            break;
        }

        case 7:
        {
            // Definitely works
            GCM<AES>::Decryption decryptor;
            decryptor.SetKeyWithIV(key, keySizeBytes, iv);
            StringSource(cipherText, true,
                         new AuthenticatedDecryptionFilter(decryptor,
                                                           new StringSink(decrypted),
                                                           AuthenticatedDecryptionFilter::THROW_EXCEPTION, aad_len));
            break;
        }
        case 8:
        {
            CBC_Mode<DES>::Decryption decryptor;
            decryptor.SetKeyWithIV(key, DES::DEFAULT_KEYLENGTH, iv);
            StringSource(cipherText, true,
                         new StreamTransformationFilter(decryptor,
                                                        new StringSink(decrypted)));
            break;
        }
        case 9:
        {
            ECB_Mode<DES>::Decryption decryptor;
            decryptor.SetKey(key, DES::DEFAULT_KEYLENGTH);
            StringSource(cipherText, true,
                         new StreamTransformationFilter(decryptor,
                                                        new StringSink(decrypted)));
            break;
        }
        case 10:
        {
            OFB_Mode<DES>::Decryption decryptor;
            decryptor.SetKeyWithIV(key, DES::DEFAULT_KEYLENGTH, iv);
            StringSource(cipherText, true,
                         new StreamTransformationFilter(decryptor,
                                                        new StringSink(decrypted)));
            break;
        }
        case 11:
        {
            CFB_Mode<DES>::Decryption decryptor;
            decryptor.SetKeyWithIV(key, DES::DEFAULT_KEYLENGTH, iv);
            StringSource(cipherText, true,
                         new StreamTransformationFilter(decryptor,
                                                        new StringSink(decrypted)));
            break;
        }
        case 12:
        {
            CTR_Mode<DES>::Decryption decryptor;
            decryptor.SetKeyWithIV(key, DES::DEFAULT_KEYLENGTH, iv);
            StringSource(cipherText, true,
                         new StreamTransformationFilter(decryptor,
                                                        new StringSink(decrypted)));
            break;
        }
        }
    }
    catch (const Exception &ex)
    {
        std::cerr << "Decryption error: " << ex.what() << std::endl;
    }
    return decrypted;
}

std::string HexDecode(const std::string &hex)
{
    std::string decoded;
    StringSource(hex, true,
                 new HexDecoder(
                     new StringSink(decoded)));
    return decoded;
}

std::string HexEncode(const std::string &input)
{
    std::string encoded;
    StringSource(input, true,
                 new HexEncoder(
                     new StringSink(encoded)));
    return encoded;
}

void printUsage(const char *programName)
{
    std::cerr << "Usage: <Program Name> <mode> -ks <key_size> -a <action> [-k <key_file>] [-i <iv_file>] [-pt <plaintext_file>] [-ct <ciphertext_file>]" << std::endl;
    std::cerr << "\nModes (AES needs not prefixed):\n";
    std::cerr << "  CBC, ECB, OFB, CFB, CTR, XTS, CCM, GCM, DES-CBC, DES-ECB, DES-OFB, DES-CFB, DES-CTR\n";
    std::cerr << "Keysizes: 128, 192, 256\n";
    std::cerr << "\nActions:\n";
    std::cerr << "  1 - Generate and save key (and IV if needed)\n";
    std::cerr << "  2 - Encrypt plaintext file\n";
    std::cerr << "  3 - Decrypt ciphertext file\n";
    std::cerr << "\nOptions:\n";
    std::cerr << "  -ks <key_size>       Key size in bits (128, 192, 256)\n";
    std::cerr << "  -k <key_file>        File to save/load the encryption key\n";
    std::cerr << "  -i <iv_file>         File to save/load the initialization vector (IV) (required for modes other than ECB)\n";
    std::cerr << "  -pt <plaintext_file> File containing the plaintext to encrypt\n";
    std::cerr << "  -ct <ciphertext_file>File containing the ciphertext to decrypt\n";
    std::cerr << "  -aad <aad_file>      File containing additional authenticated data (AAD) (required for CCM and GCM)\n";
    std::cerr << "Excess options are accepte and will be omitted later on hopefully.\n";
    exit(1);
}

void generateKeyAndIV(const char *keyFile, const char *ivFile, const std::string &mode, int keysize)
{
    AutoSeededRandomPool prng;
    int keySize = getKeySize(mode, keysize) / 8;
    SecByteBlock key(keySize);
    prng.GenerateBlock(key, key.size());

    FileSink keySink(keyFile);
    keySink.Put(key, key.size());
    keySink.MessageEnd();

    if (mode != "ECB" && mode != "DES-ECB")
    {
        if (mode == "CCM")
        {
            const int CCM_IV_LENGTH = 13;
            SecByteBlock iv(CCM_IV_LENGTH);
            prng.GenerateBlock(iv, iv.size());

            FileSink ivSink(ivFile);
            ivSink.Put(iv, iv.size());
            ivSink.MessageEnd();
        }
        else
        {
            SecByteBlock iv(AES::BLOCKSIZE);
            prng.GenerateBlock(iv, iv.size());

            FileSink ivSink(ivFile);
            ivSink.Put(iv, iv.size());
            ivSink.MessageEnd();
        }
    }

    std::cout << "Key and IV generated and saved successfully." << std::endl;
}
void encryptFile(int keysize, const char *keyFile, const char *ivFile, const char *plainTextFile, const char *cipherTextFile, const std::string &mode, const char *aadFile)
{
    std::string plainText, cipherText;
    FileSource fs(plainTextFile, true, new StringSink(plainText));

    int keySizeBytes = getKeySize(mode, keysize) / 8;
    SecByteBlock key(keySizeBytes);
    FileSource keySource(keyFile, true, new ArraySink(key, key.size()));

    SecByteBlock iv(AES::BLOCKSIZE);
    if (mode != "ECB" && mode != "DES-ECB")
    {
        FileSource ivSource(ivFile, true, new ArraySink(iv, iv.size()));
    }

    SecByteBlock aad;
    if (mode == "CCM" || mode == "GCM")
    {
        std::string aadStr;
        if (aadFile != nullptr && strlen(aadFile) > 0)
        {
            FileSource aadSource(aadFile, true, new StringSink(aadStr));
            if (aadStr.empty())
            {
                std::cerr << "AAD file is empty or not read correctly." << std::endl;
            }
            else
            {
                std::cerr << "AAD read successfully: " << aadStr << std::endl;
            }
        }
        else
        {
            std::cerr << "AAD file not provided." << std::endl;
        }
        aad.Assign((const byte *)aadStr.data(), aadStr.size());
    }

    cipherText = Encrypt(plainText, key, iv, mode, keysize, aad.BytePtr(), aad.size());

    FileSink cipherSink(cipherTextFile);
    cipherSink.Put((const byte *)cipherText.data(), cipherText.size());
    cipherSink.MessageEnd();
}

void decryptFile(int keysize, const char *keyFile, const char *ivFile, const char *cipherTextFile, const char *plainTextFile, const std::string &mode, const char *aadFile)
{
    std::string cipherText, decryptedText;
    FileSource fs(cipherTextFile, true, new StringSink(cipherText));

    int keySizeBytes = getKeySize(mode, keysize) / 8;
    SecByteBlock key(keySizeBytes);
    FileSource keySource(keyFile, true, new ArraySink(key, key.size()));

    SecByteBlock iv(AES::BLOCKSIZE);
    if (mode != "ECB" && mode != "DES-ECB")
    {
        FileSource ivSource(ivFile, true, new ArraySink(iv, iv.size()));
    }

    SecByteBlock aad;
    if (mode == "CCM" || mode == "GCM")
    {
        std::string aadStr;
        if (aadFile != nullptr && strlen(aadFile) > 0)
        {
            FileSource aadSource(aadFile, true, new StringSink(aadStr));
            if (aadStr.empty())
            {
                std::cerr << "AAD file is empty or not read correctly." << std::endl;
            }
            else
            {
                std::cerr << "AAD read successfully: " << aadStr << std::endl;
            }
        }
        else
        {
            std::cerr << "AAD file not provided." << std::endl;
        }
        aad.Assign((const byte *)aadStr.data(), aadStr.size());
    }

    decryptedText = Decrypt(cipherText, key, iv, mode, keysize, aad.BytePtr(), aad.size());

    FileSink plainSink(plainTextFile);
    plainSink.Put((const byte *)decryptedText.data(), decryptedText.size());
    plainSink.MessageEnd();
}

int main(int argc, char *argv[])
{
    if (argc < 5)
    {
        printUsage(argv[0]);
    }

    std::string keySizeStr;
    std::string mode = argv[1];
    std::string action = argv[3];

    std::string keyFile, ivFile, plainTextFile, cipherTextFile, aadFile;

    for (int i = 4; i < argc; ++i)
    {
        if (std::strcmp(argv[i], "-ks") == 0 && i + 1 < argc)
        {
            keySizeStr = argv[++i];
        }
        else if (std::strcmp(argv[i], "-k") == 0 && i + 1 < argc)
        {
            keyFile = argv[++i];
        }
        else if (std::strcmp(argv[i], "-i") == 0 && i + 1 < argc)
        {
            ivFile = argv[++i];
        }
        else if (std::strcmp(argv[i], "-pt") == 0 && i + 1 < argc)
        {
            plainTextFile = argv[++i];
        }
        else if (std::strcmp(argv[i], "-ct") == 0 && i + 1 < argc)
        {
            cipherTextFile = argv[++i];
        }
        else if (std::strcmp(argv[i], "-aad") == 0 && i + 1 < argc)
        {
            aadFile = argv[++i];
        }
        else
        {
            printUsage(argv[0]);
        }
    }

    int modeSelectedForBenchmarking = std::atoi(action.c_str());
    int keySize = std::atoi(keySizeStr.c_str());

    // Start clock

    switch (modeSelectedForBenchmarking)
    {
    case 1:
        generateKeyAndIV(keyFile.c_str(), ivFile.c_str(), mode, keySize);
        return 0;
    case 2:
    {
        if (keyFile.empty() || ((mode != "ECB" && ivFile.empty()) && (mode != "DES-ECB" && ivFile.empty())) || plainTextFile.empty() || cipherTextFile.empty())
        {
            printUsage(argv[0]);
        }
        auto start = std::chrono::steady_clock::now();
        for (int i = 0; i < 1000; i++)
        {
            encryptFile(keySize, keyFile.c_str(), ivFile.c_str(), plainTextFile.c_str(), cipherTextFile.c_str(), mode, aadFile.c_str());
        }
            auto end = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
            std::cout << "Time taken per encryption with mode " << mode << ": " << duration.count() / 1000 << " microseconds" << std::endl;
    }    

        break;
    case 3:
    {
        if (keyFile.empty() || ((mode != "ECB" && ivFile.empty()) && (mode != "DES-ECB" && ivFile.empty())) || cipherTextFile.empty() || plainTextFile.empty())
        {
            printUsage(argv[0]);
        }
        auto start = std::chrono::steady_clock::now();

        for (int i = 0; i < 1000; i++)
        {
            decryptFile(keySize, keyFile.c_str(), ivFile.c_str(), cipherTextFile.c_str(), plainTextFile.c_str(), mode, aadFile.c_str());
        }
            auto end = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
            std::cout << "Time taken per decryption with mode " << mode << ": " << duration.count() / 1000 << " microseconds" << std::endl;
            break;
    }
            default: 
            printUsage(argv[0]);
            break;
        }
    
    

    
    // case 3:
    //     std::cout << "Time taken per decryption with mode " << mode << ": " << duration.count() / 10000 << " microseconds" << std::endl;
    //     break;
    // default:
    //     break;
    

    return 0;
}
