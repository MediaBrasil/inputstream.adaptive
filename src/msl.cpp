/*
*      Copyright (C) 2016-2016 peak3d
*      http://www.peak3d.de
*
*  This Program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.
*
*  This Program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
*  GNU General Public License for more details.
*
*  <http://www.gnu.org/licenses/>.
*
*/
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <cassert>
#include <algorithm>

#include <string>
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <sstream>

#include "msl.h"
#include <assert.h>
#include <jsoncpp/json/json.h>
#include <jsoncpp/json/reader.h>
#include <iostream>
#include "kodi/libXBMC_addon.h"
#include "base64.h"
#include "helpers.h"
#include "string.h"

#include <ctime>
#include <errno.h>
#include <zlib.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>


// Found these here http://mail-archives.apache.org/mod_mbox/trafficserver-dev/201110.mbox/%3CCACJPjhYf=+br1W39vyazP=ix
//eQZ-4Gh9-U6TtiEdReG3S4ZZng@mail.gmail.com%3E
#define MOD_GZIP_ZLIB_WINDOWSIZE 15
#define MOD_GZIP_ZLIB_CFACTOR    9
#define MOD_GZIP_ZLIB_BSIZE      8096

static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz"
                "0123456789+/";

static inline bool is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

ADDON::CHelper_libXBMC_addon *kodi = 0;

bool MSLFilter::msl_initialize(ADDON::CHelper_libXBMC_addon *xbmc_addon) {
    kodi = xbmc_addon;
    this->create_private_key();
    this->perform_key_exchange();
    return false;
}

bool MSLFilter::create_private_key() {

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (EVP_PKEY_keygen_init(ctx) <= 0)
        printf("Wurst");
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0)
        printf("Wurst");

    /* Generate key */
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        printf("Wurst");


    // Init Decryption
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (EVP_PKEY_decrypt_init(ctx) <= 0)
        kodi->Log(ADDON::LOG_ERROR, "Error RSA Decrypt Init");
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        kodi->Log(ADDON::LOG_ERROR, "Error setting RSA Padding");



    int ret;
    BIO *bp_public = NULL, *bp_private = NULL;
    //TODO Remove these savings
    bp_public = BIO_new_file("public.pem", "w+");
    ret = PEM_write_bio_PUBKEY(bp_public, pkey);
    BIO_free(bp_public);


    bp_private = BIO_new_file("private.pem", "w+");
    ret = PEM_write_bio_PrivateKey(bp_private, pkey, NULL, NULL, 0, NULL, NULL);
    BIO_free(bp_private);

    //Get the public key encoded as DER in base64
    int len;
    unsigned char *buf;
    buf = NULL;
    len = i2d_PUBKEY(pkey, &buf);
    if (len < 0) {
        kodi->Log(ADDON::LOG_ERROR, "Error Generating Pub and Priv Key");
    }
    this->publicKey = b64_encode(buf, len, false);
    return true;
}

std::string MSLFilter::b64_decode_string(std::string const &encoded_string) {
    int in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::string ret;

    while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
        char_array_4[i++] = encoded_string[in_];
        in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                ret += char_array_3[i];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 4; j++)
            char_array_4[j] = 0;

        for (j = 0; j < 4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
    }

    return ret;
}


size_t calcDecodeLength(const char *b64input) { //Calculates the length of a decoded string
    size_t len = strlen(b64input),
            padding = 0;

    if (b64input[len - 1] == '=' && b64input[len - 2] == '=') //last two chars are =
        padding = 2;
    else if (b64input[len - 1] == '=') //last char is =
        padding = 1;

    return (len * 3) / 4 - padding;
}

int Base64Decode(const char *b64message, unsigned char **buffer, size_t *length) { //Decodes a base64 encoded string
    BIO *bio, *b64;

    int decodeLen = calcDecodeLength(b64message);
    *buffer = (unsigned char *) malloc(decodeLen + 1);
    (*buffer)[decodeLen] = '\0';

    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
    *length = BIO_read(bio, *buffer, strlen(b64message));
    assert(*length == decodeLen); //length should equal decodeLen, else something went horribly wrong
    BIO_free_all(bio);

    return (0); //success
}




std::string  MSLFilter::decrypt_rsa(std::string base64Encrypted) {
    unsigned char *encrypted, *decrypted;
    size_t encryptedLength, decryptedLength;


    //Load the error Strings //TODO wrong position
    ERR_load_crypto_strings();

    //Base64 to Binary Encryption Payload
    Base64Decode(base64Encrypted.c_str(), &encrypted, &encryptedLength);

    // Calculate Decryption Length
    if (EVP_PKEY_decrypt(ctx, NULL, &decryptedLength, encrypted, encryptedLength) <= 0) {
        kodi->Log(ADDON::LOG_ERROR, "Error getting RSA decrypting length");
        printf( "ERROR: RSA_private_decrypt: %s\n", ERR_error_string(ERR_get_error(), NULL) ) ;
    }

    //Allocate Memory for the enc. Content
    decrypted = (unsigned char *)OPENSSL_malloc(decryptedLength);
    if (!encrypted) {
        kodi->Log(ADDON::LOG_ERROR, "Error Allocation decrypt-out Space");
    }
    //Finnaly decrypt
    if (EVP_PKEY_decrypt(ctx, decrypted, &decryptedLength, encrypted, encryptedLength) <= 0) {
        kodi->Log(ADDON::LOG_ERROR, "Error RSA decrypting");
        printf( "ERROR: RSA_private_decrypt: %s\n", ERR_error_string(ERR_get_error(), NULL) ) ;
    }

    std::string retString(decrypted, decrypted + decryptedLength);
    return retString;
}




bool MSLFilter::perform_key_exchange() {

    //TODO cleanup

    // Define the headerdata for the request
    Json::Value headerData;
    headerData["handshake"] = true;
    headerData["nonreplayable"] = false;

    headerData["capabilities"]["languages"] = Json::arrayValue;
    headerData["capabilities"]["languages"].append("en-US");
    headerData["capabilities"]["compressionalgos"] = Json::arrayValue;

    headerData["renewable"] = true;
    headerData["messageid"] = 23; //TODO some random number
    headerData["keyrequestdata"] = Json::arrayValue;

    //Create keyrequestdata object
    Json::Value keyrequestData;
    keyrequestData["scheme"] = "ASYMMETRIC_WRAPPED";
    keyrequestData["keydata"]["publickey"] = this->publicKey;
    keyrequestData["keydata"]["mechanism"] = "JWK_RSA";
    keyrequestData["keydata"]["keypairid"] = "kodiKey"; //TODO add kind of random keyid

    //Add keyrequestdata to the header
    headerData["keyrequestdata"].append(keyrequestData);

    headerData["timestamp"] = 1467733923; //TODO add real timestamp


    Json::StyledWriter *styledWriter = new Json::StyledWriter;
    std::string temp = styledWriter->write(headerData);


    Json::FastWriter *writer = new Json::FastWriter;
    std::string headerJson = writer->write(headerData);
    std::string encodedHeaderJson = b64_encode(reinterpret_cast<const unsigned char *>(headerJson.c_str()),
                                               headerJson.length(), false);

    // now build first request
    Json::Value request;
    request["headerdata"] = encodedHeaderJson;
    request["signature"] = "";
    request["entityauthdata"]["scheme"] = "NONE";
    request["entityauthdata"]["authdata"]["identity"] = "NFCDCH-LX-CQE0NU6PA5714R25VPLXVU2A193T36"; //TODO Add generated or fetched entity id?!

    std::string requestJson = writer->write(request);

    Json::Value keyRequestResponse;
    keyRequestResponse = this->perform_msl_post_json_request("http://www.netflix.com/api/msl/NFCDCH-LX/cadmium/manifest",
                                                        requestJson);

    Json::Value responseHeader;
    Json::Reader reader;
    reader.parse(this->b64_decode_string(keyRequestResponse["headerdata"].asString()), responseHeader);

    masterToken = responseHeader["keyresponsedata"]["mastertoken"];

    //Get sequencenumber of the token
    Json::Value tokenData;
    reader.parse(this->b64_decode_string(masterToken["tokendata"].asString()), tokenData);
    this->sequenceNumber = tokenData["sequencenumber"].asInt();


    Json::Value keydata = responseHeader["keyresponsedata"]["keydata"];


    //Get the encryption and signing Keys
    std::string encKeyBase64 = keydata["encryptionkey"].asString();
    std::string hmacKeyBase64 = keydata["hmackey"].asString();



    std::string encryptionKeyJsonString = this->decrypt_rsa(encKeyBase64);
    std::string hmacKeyJsonString = this->decrypt_rsa(hmacKeyBase64);


    // Get the encryption key form json
    Json::Value encryptionKeyJson;
    reader.parse(encryptionKeyJsonString, encryptionKeyJson);
    std::string encryptionKey = encryptionKeyJson["k"].asString();

    // Get the hmac key form json
    Json::Value hmacKeyJson;
    reader.parse(hmacKeyJsonString, hmacKeyJson);
    std::string hmacKey = hmacKeyJson["k"].asString();

    //Add base64 padding
    //encryptionKey key is urlsafebase64 encoded
    std::replace( encryptionKey.begin(), encryptionKey.end(), '_', '/');
    std::replace( encryptionKey.begin(), encryptionKey.end(), '-', '+');
    int rest = encryptionKey.length() % 4;
    if (rest == 2) {
        encryptionKey += "==";
    }
    else if (rest == 3) {
        encryptionKey += "=";
    }
    size_t AESEncryptionKeyLength;
    Base64Decode(encryptionKey.c_str(), &AESEncryptionKey, &AESEncryptionKeyLength);

    //hmac key is urlsafebase64 encoded
    std::replace( hmacKey.begin(), hmacKey.end(), '_', '/');
    std::replace( hmacKey.begin(), hmacKey.end(), '-', '+');
    //Add base64 padding
    int rest2 = hmacKey.length() % 4;
    if (rest2 == 2) {
        hmacKey += "==";
    }
    else if (rest2 == 3) {
        hmacKey += "=";
    }
    Base64Decode(hmacKey.c_str(), &HMACSigningKey, &hmacKeyLength);


    return true;
}

Json::Value MSLFilter::perform_msl_post_json_request(std::string url, std::string postData) {
    std::string response = perform_msl_post_request(url, postData);

    //Parse Response
    Json::Value mslResponse;
    Json::Reader reader;
    reader.parse(response, mslResponse);

    //Make a sanity check. Meas check if a error message is present
    if (mslResponse.isMember("errordata")) {
        std::string errorMessage = this->b64_decode_string(mslResponse["errordata"].asString());
        kodi->Log(ADDON::LOG_DEBUG, "Error in Keyexchange: %s ", errorMessage.c_str());
        std::cout << errorMessage << std::endl;
    }
    return mslResponse;
}


std::string MSLFilter::perform_msl_post_request(std::string url, std::string postData) {
    void *file = kodi->CURLCreate(url.c_str());

    // Convert Post Data to base64 Data
    std::string postDataBase = b64_encode(reinterpret_cast<const unsigned char *>(postData.c_str()), postData.size(), false);

    //Create CURL Request
    kodi->CURLAddOption(file, XFILE::CURL_OPTION_PROTOCOL, "Content-Type", "application/json");
    kodi->CURLAddOption(file, XFILE::CURL_OPTION_PROTOCOL, "postdata", postDataBase.c_str());
    kodi->CURLOpen(file, XFILE::READ_NO_CACHE);

    //Read the Response
    size_t nbRead;
    std::string response;
    char buf[2048];
    while ((nbRead = kodi->ReadFile(file, buf, 1024)) > 0)
        response += std::string((const char *) buf, nbRead);

    return response;
}

std::string MSLFilter::sign(std::string payload) {
    //Create key type
    EVP_PKEY *hmacKey = NULL;
    hmacKey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, reinterpret_cast<unsigned char *>(HMACSigningKey), hmacKeyLength);

    //Create Context
    EVP_MD_CTX context;
    EVP_MD_CTX_init(&context);


    //Init Digest with SHA256
    int rc = EVP_DigestInit_ex(&context, EVP_sha256(), NULL);

    //Init Sign with SHA256
    rc = EVP_DigestSignInit(&context, NULL, EVP_sha256(), NULL, hmacKey);
    if(rc != 1) {
        printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
    }

    //Get length of the signature
    rc = EVP_DigestSignUpdate(&context, reinterpret_cast<unsigned char *>(&payload[0]), payload.size());
    if(rc != 1) {
        printf("EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
    }

    //Cretae Signature vector
    std::vector<uint8_t> signature;

    //Calc Length of sig
    size_t signLength = 0;
    EVP_DigestSignFinal(&context, NULL, &signLength);

    //Allocate space
    signature.resize(signLength);

    //Finally create signature+
    EVP_DigestSignFinal(&context, &signature.front(), &signLength);

    //Create Base64 of the signature
    std::string base64sig = b64_encode(&signature[0], signLength, false);

    //Free up //TODO add missing
    EVP_PKEY_free(hmacKey);

    return base64sig;
}

std::string MSLFilter::AESEncrypt(std::string payload, int sequenceNumber) {
    //Encrypt the given payload
    EVP_CIPHER_CTX context;
    EVP_CIPHER_CTX_init(&context);


    unsigned char iv[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}; //TODO add at least pseudo random
    assert(sizeof(iv) == 16);   // IV is always the AES block size


    // If data isn't a multiple of 16, the default behavior is to pad with
    // n bytes of value n, where n is the number of padding bytes required
    // to make data a multiple of the block size.  This is PKCS7 padding.
    // The output then will be a multiple of the block size.
    std::vector<unsigned char> encrypted;
    size_t max_output_len = payload.length() + 16 - (payload.length() % 16);
    encrypted.resize(max_output_len);

    // Enc is 1 to encrypt, 0 to decrypt, or -1 (see documentation).
    EVP_CipherInit_ex(&context, EVP_aes_128_cbc(), NULL, AESEncryptionKey, iv, 1);

    // EVP_CipherUpdate can encrypt all your data at once, or you can do
    // small chunks at a time.
    int actual_size = 0;
    EVP_CipherUpdate(&context,
                     &encrypted[0], &actual_size,
                     reinterpret_cast<unsigned char *>(&payload[0]), payload.size());

    // EVP_CipherFinal_ex is what applies the padding.  If your data is
    // a multiple of the block size, you'll get an extra AES block filled
    // with nothing but padding.
    int final_size;
    EVP_CipherFinal_ex(&context, &encrypted[actual_size], &final_size);
    actual_size += final_size;

    encrypted.resize(actual_size);

    std::string encHeaderBase64 = b64_encode(&encrypted[0], actual_size, false);

    //Create the Encryption Envelope for the encoded data
    Json::Value encryptionEnvelope;
    encryptionEnvelope["ciphertext"] = encHeaderBase64;
    encryptionEnvelope["keyid"] = "NFCDCH-LX-CQE0NU6PA5714R25VPLXVU2A193T36_" + std::to_string(this->sequenceNumber);
    encryptionEnvelope["sha256"] = "AA==";
    encryptionEnvelope["iv"] = b64_encode(reinterpret_cast<unsigned char *>(iv), 16, false);

    //Serialize JSON and return
    Json::FastWriter *writer = new Json::FastWriter;
    std::string serializedEncryptionEnvelope = writer->write(encryptionEnvelope);

    //Free UP //TODO maybe more


    //

    return serializedEncryptionEnvelope;
}


void replaceAll(std::string& str, const std::string& from, const std::string& to) {
    if(from.empty())
        return;
    size_t start_pos = 0;
    while((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); // In case 'to' contains 'from', like replacing 'x' with 'yx'
    }
}

std::string MSLFilter::generate_msl_request(Json::Value requestData) {

    //Generate a header
    Json::Value requestHeader = this->generate_msl_header();

    //Serialize the request Data
    Json::FastWriter *writer = new Json::FastWriter;
    std::string serializedRequestData = writer->write(requestData);


    //cause jsoncpp is goddamn old version fastwriter adds a newline at the end of the json
    serializedRequestData = serializedRequestData.substr(0, serializedRequestData.size()-1);

    //Dirty quickfix for xid long
    serializedRequestData = serializedRequestData.substr(0, serializedRequestData.size()-1); // remove }
    serializedRequestData += ", \"xid\":";
    serializedRequestData += requestData["clientTime"].asString();
    serializedRequestData += "1618}";


    //Serialized Data will be includes in other json so escape the "
    replaceAll(serializedRequestData,  "\"", "\\\"");

    std::string plaintextRequest = "[{},{\"headers\":{},\"path\":\"/cbp/cadmium-11\",\"payload\":{\"data\":\""+serializedRequestData+"\"},\"query\":\"\"}]\n";


    std::string compressedPlaintextRequest = compress_string(plaintextRequest, Z_BEST_COMPRESSION);

    //Create the first payload chunk
    Json::Value payload;
    payload["messageid"] = 23; //TODO GenmessageId - MUST be same as in header!
    payload["data"] = compressedPlaintextRequest;
    payload["compressionalgo"] = "GZIP";
    payload["sequencenumber"] = 1;

    //Get payload encrypted
    std::string encryptedPayload = this->AESEncrypt(writer->write(payload), 1);
    Json::Value firstPayloadChunk;
    firstPayloadChunk["payload"] = b64_encode(reinterpret_cast<const unsigned char *>(encryptedPayload.c_str()), encryptedPayload.length(), false);
    firstPayloadChunk["signature"] = this->sign(encryptedPayload);

    //Create second and last payload chunk
    payload["sequencenumber"] = 2;
    payload["data"] = "";
    payload["endofmsg"] = true;
    encryptedPayload = this->AESEncrypt(writer->write(payload), 1);
    Json::Value secondPayloadChunk;
    secondPayloadChunk["payload"] = b64_encode(reinterpret_cast<const unsigned char *>(encryptedPayload.c_str()), encryptedPayload.length(), false);
    secondPayloadChunk["signature"] = this->sign(encryptedPayload);

    //Finnaly create the data string that will be send via POST request
    // The Message request is not a pure json object but it consists of
    //one (header) or more (header + payloadchunks) json objects concatenated to one single string
    std::string postData = writer->write(requestHeader) + writer->write(firstPayloadChunk) + writer->write(secondPayloadChunk);

    return postData;

}

Json::Value MSLFilter::generate_msl_header() {
    // Define the headerdata for the request - this will be encrypted later on and packaged into an encryption envelope
    Json::Value headerData;
    headerData["handshake"] = false;
    headerData["nonreplayable"] = false;

    headerData["capabilities"]["languages"] = Json::arrayValue;
    headerData["capabilities"]["languages"].append("en-US");
    headerData["capabilities"]["compressionalgos"] = Json::arrayValue;
    headerData["capabilities"]["compressionalgos"].append("GZIP");


    headerData["renewable"] = true;
    headerData["sender"] = "NFCDCH-LX-CQE0NU6PA5714R25VPLXVU2A193T36";
    headerData["recipient"] = "Netflix";
    headerData["messageid"] = 23; //TODO some random number


    //Determine if auth by username and/password or use tokens if already present
    if (this->useridtoken == Json::nullValue && this->serviceTokens == Json::nullValue) {
        headerData["userauthdata"]["scheme"] = "EMAIL_PASSWORD";
        headerData["userauthdata"]["authdata"]["password"] = "";
        headerData["userauthdata"]["authdata"]["email"] = "";
    }
    else {
        headerData["servicetokens"] = this->serviceTokens;
        headerData["useridtoken"] = this->useridtoken;
    }


    Json::FastWriter *writer = new Json::FastWriter;
    std::string serializedHeaderData = writer->write(headerData);

    //Encrypt and sign the serialized Header
    std::string encHeaderData = this->AESEncrypt(serializedHeaderData, 1);
    std::string headerSignature = this->sign(encHeaderData);

    //Finally create real header in msl request
    Json::Value requestHeader;
    requestHeader["headerdata"] = b64_encode(reinterpret_cast<const unsigned char *>(encHeaderData.c_str()), encHeaderData.length(), false);
    requestHeader["signature"] = headerSignature;
    requestHeader["mastertoken"] = masterToken;

    return requestHeader;
}


std::string MSLFilter::parse_msl_response(std::string response) {

    std::string headerStr = "";
    std::string respPayloadStr = "";
    int opencount = 0;
    int closecount = 0;
    int oldEnd = 0;
    for(int i = 0; i < response.length(); i++) {
        if (response.compare(i, 1, "{") == 0) {
            opencount += 1;
        }
        if (response.compare(i, 1, "}") == 0) {
            closecount += 1;
        }
        if (opencount == closecount) {
            if (headerStr.compare("") == 0) {
                headerStr = response.substr(oldEnd, i);
                oldEnd = i+1;
            }
            else {
                respPayloadStr = response.substr(oldEnd, i+1);
            }
        }
    }

    Json::Reader reader;


    //Parse header, extract and save tokens
    Json::Value headerJson;
    reader.parse(headerStr, headerJson);
    std::string headerDataString = this->b64_decode_string(headerJson["headerdata"].asString());
    Json::Value headerDataEncEnevelope;
    reader.parse(headerDataString, headerDataEncEnevelope);
    std::string decryptedHeaderStr = this->AESDecrypt(headerDataEncEnevelope["ciphertext"].asString(), headerDataEncEnevelope["iv"].asString());
    Json::Value decryptedHeader;
    reader.parse(decryptedHeaderStr, decryptedHeader);
    this->serviceTokens = decryptedHeader["servicetokens"];
    this->useridtoken = decryptedHeader["useridtoken"];

    //Extract, Decrypt the payload
    Json::Value jsonPayload;
    reader.parse(respPayloadStr, jsonPayload);

    Json::Value encryptionEnvelope;
    reader.parse(this->b64_decode_string(jsonPayload["payload"].asString()), encryptionEnvelope);


    std::string chipertext = encryptionEnvelope["ciphertext"].asString();
    std::string iv = encryptionEnvelope["iv"].asString();
    std::string decrypted = this->AESDecrypt(chipertext, iv);

    Json::Value decryptedJson;
    reader.parse(decrypted, decryptedJson);

    //Check if data is compressd
    std::string data = decryptedJson["data"].asString();
    if (decryptedJson.isMember("compressionalgo")) {
      data = this->decompress_string(this->b64_decode_string(data));
    }

    Json::Value plainTextJsonResponse;
    reader.parse(data, plainTextJsonResponse);

    //Check response status if error log data
    if(plainTextJsonResponse[(int)1]["status"].asString() != "200") {
        kodi->Log(ADDON::LOG_DEBUG, "Error in MSL Response: %s", data.c_str());
    }

    return this->b64_decode_string(plainTextJsonResponse[(int)1]["payload"]["data"].asString());

}

std::string MSLFilter::msl_download_manifest(const char *url) {

    // Create Manifest request Data
    Json::Value manifestRequestData;
    manifestRequestData["method"] = "manifest";
    manifestRequestData["lookupType"] = "PREPARE";
    manifestRequestData["viewableIds"] = Json::arrayValue;
    manifestRequestData["viewableIds"].append(80103584);
    manifestRequestData["profiles"] = Json::arrayValue;
    manifestRequestData["profiles"].append("playready-h264mpl30-dash");
    manifestRequestData["profiles"].append("playready-h264mpl31-dash");
    manifestRequestData["profiles"].append("heaac-2-dash");
    manifestRequestData["profiles"].append("dfxp-ls-sdh");
    manifestRequestData["profiles"].append("simplesdh");
    manifestRequestData["profiles"].append("nflx-cmisc");
    manifestRequestData["profiles"].append("BIF240");
    manifestRequestData["profiles"].append("BIF320");
    manifestRequestData["drmSystem"] = "widevine";
    manifestRequestData["appId"] = "14673889385265";
    manifestRequestData["trackId"] = 0;

    manifestRequestData["sessionParams"]["pinCapableClient"] = false;
    manifestRequestData["sessionParams"]["uiplaycontext"] = "null";
    manifestRequestData["sessionId"] = "14673889385265";

    manifestRequestData["usePlayReadyHeaderObject"] = false;

    manifestRequestData["flavor"] = "PRE_FETCH";
    manifestRequestData["secureUrls"] = false;
    manifestRequestData["supportPreviewContent"] = false;
    manifestRequestData["forceClearStreams"] = false;
    manifestRequestData["languages"] = Json::arrayValue;
    manifestRequestData["languages"].append("de-DE");
    manifestRequestData["clientVersion"] = "4.0005.887.011";
    manifestRequestData["uiVersion"] = "akira";

    //Generate the request POST Data
    std::string requestData = this->generate_msl_request(manifestRequestData);

    //Get plain response cause chunked payloads
    std::string response = this->perform_msl_post_request("http://www.netflix.com/api/msl/NFCDCH-LX/cadmium/manifest", requestData);

    //Parse the msl response
    std::string manifest = this->parse_msl_response(response);

    //this->msl_download_license();

    return manifest;
}


std::string MSLFilter::msl_download_license(const char* challengeStr, const char* playbackContextId, const char* sessionId, const char* drmContextId) {
    Json::Value licenseRequestData;

    std::time_t t = std::time(0);  // t is an integer type
    licenseRequestData["method"] = "license";
    licenseRequestData["clientTime"] = (int)t;
    //licenseRequestData["challengeBase64"] = challengeStr;
    licenseRequestData["clientVersion"] = "4.0005.887.011";
    licenseRequestData["licenseType"] = "STANDARD";
    licenseRequestData["playbackContextId"] = playbackContextId;//"E1-BQFRAAELEB32o6Se-GFvjwEIbvDydEtfj6zNzEC3qwfweEPAL3gTHHT2V8rS_u1Mc3mw5BWZrUlKYIu4aArdjN8z_Z8t62E5jRjLMdCKMsVhlSJpiQx0MNW4aGqkYz-1lPh85Quo4I_mxVBG5lgd166B5NDizA8.";
    licenseRequestData["uiVersion"] = "akira";
    licenseRequestData["languages"] = Json::arrayValue;
    licenseRequestData["languages"].append("de-DE");
    licenseRequestData["drmContextIds"] = Json::arrayValue;
    licenseRequestData["drmContextIds"].append(drmContextId);

    licenseRequestData["challenges"] = Json::arrayValue;
    Json::Value challenge;
    challenge["dataBase64"] = challengeStr;
    challenge["sessionId"] = sessionId;
    licenseRequestData["challenges"].append(challenge);


    //Generate the request POST Data
    std::string requestData = this->generate_msl_request(licenseRequestData);

    //Get plain response cause chunked payloads
    std::string response = this->perform_msl_post_request("http://www.netflix.com/api/msl/NFCDCH-LX/cadmium/license", requestData);

    //Parse the msl response
    std::string licenseStr = this->parse_msl_response(response);
    Json::Value licenseJson;

    Json::Reader reader;
    reader.parse(licenseStr, licenseJson);

    //Check if request was successfull
    if (!licenseJson["success"].asBool()) {
        kodi->Log(ADDON::LOG_DEBUG, "License MSL Request Data: %s", licenseRequestData);
        kodi->Log(ADDON::LOG_DEBUG, "License Plain MSL Response: %s", response.c_str());
        kodi->Log(ADDON::LOG_DEBUG, "License Parsed MSL Response: %s", licenseStr.c_str());
        throw(std::runtime_error("MSL License request was NOT successful!"));
    }


    return licenseJson["result"]["licenses"][(int)0]["data"].asString();
}

std::string MSLFilter::msl_bind() {
    Json::Value bindData;

    bindData["method"] = "bind";
    bindData["clientVersion"] = "4.0005.887.011";
    bindData["uiVersion"] = "akira";
    bindData["languages"] = Json::arrayValue;
    bindData["languages"].append("de-DE");


    //Generate the request POST Data
    std::string requestData = this->generate_msl_request(bindData);

    //Get plain response cause chunked payloads
    std::string response = this->perform_msl_post_request("http://www.netflix.com/api/msl/NFCDCH-LX/cadmium/bind", requestData);

//    //Parse the msl response
//    std::string licenseStr = this->parse_msl_response(response);
//    Json::Value licenseJson;
//    Json::Reader reader;
//    reader.parse(licenseStr, licenseJson);
//
//    std::cout << licenseJson << std::endl;

    return "";

}

std::string MSLFilter::AESDecrypt(std::string ciphertextBase64, std::string ivBase64) {

    unsigned char* iv;
    size_t ivLength;
    Base64Decode(ivBase64.c_str(), &iv, &ivLength);

    unsigned char* encrypted;
    size_t encryptedLength;
    Base64Decode(ciphertextBase64.c_str(), &encrypted, &encryptedLength);



    //Encrypt the given payload
    EVP_CIPHER_CTX context;
    EVP_CIPHER_CTX_init(&context);

    // Enc is 1 to encrypt, 0 to decrypt, or -1 (see documentation).
    EVP_CipherInit_ex(&context, EVP_aes_128_cbc(), NULL, AESEncryptionKey, iv, 0);



    size_t max_output_len = encryptedLength;
    std::vector<unsigned char> decrypted;
    decrypted.resize(max_output_len);

    int out_len1 = (int)decrypted.size();
    // EVP_CipherUpdate decrypts
    EVP_CipherUpdate(&context,
                     &decrypted[0], &out_len1,
                     encrypted, encryptedLength);


    int out_len2 = (int)decrypted.size() - out_len1;
    EVP_CipherFinal_ex(&context, &decrypted[out_len1], &out_len2);
    decrypted.resize(out_len1 + out_len2);

    std::string s(decrypted.begin(), decrypted.end());

    return s;
}




// https://panthema.net/2007/0328-ZLibString.html
std::string MSLFilter::compress_string(const std::string& str,
                            int compressionlevel = Z_BEST_COMPRESSION)
{

    z_stream zs;                        // z_stream is zlib's control structure
    memset(&zs, 0, sizeof(zs));

    if (deflateInit2(&zs, compressionlevel, Z_DEFLATED,
                         MOD_GZIP_ZLIB_WINDOWSIZE + 16,
                         MOD_GZIP_ZLIB_CFACTOR,
                         Z_DEFAULT_STRATEGY) != Z_OK)
        throw(std::runtime_error("deflateInit failed while compressing."));


    zs.next_in = (Bytef*)str.data();
    zs.avail_in = str.size();           // set the z_stream's input

    int ret;
    char outbuffer[32768];
    std::string outstring;

    // retrieve the compressed bytes blockwise
    do {
        zs.next_out = reinterpret_cast<Bytef*>(outbuffer);
        zs.avail_out = sizeof(outbuffer);

        ret = deflate(&zs, Z_FINISH);

        if (outstring.size() < zs.total_out) {
            // append the block to the output string
            outstring.append(outbuffer,
                             zs.total_out - outstring.size());
        }
    } while (ret == Z_OK);

    deflateEnd(&zs);


    if (ret != Z_STREAM_END) {          // an error occurred that was not EOF
        std::ostringstream oss;
        oss << "Exception during zlib compression: (" << ret << ") " << zs.msg;
        throw(std::runtime_error(oss.str()));
    }

    return b64_encode(
            reinterpret_cast<const unsigned char *>(outstring.c_str()),
            outstring.size(),
            false
    );
}


/** Decompress an STL string using zlib and return the original data. */
std::string MSLFilter::decompress_string(const std::string& str)
{
    z_stream zs;                        // z_stream is zlib's control structure
    memset(&zs, 0, sizeof(zs));

    if (inflateInit2(&zs, MOD_GZIP_ZLIB_WINDOWSIZE + 16) != Z_OK)
        throw(std::runtime_error("inflateInit failed while decompressing."));

    zs.next_in = (Bytef*)str.data();
    zs.avail_in = str.size();

    int ret;
    char outbuffer[32768];
    std::string outstring;

    // get the decompressed bytes blockwise using repeated calls to inflate
    do {
        zs.next_out = reinterpret_cast<Bytef*>(outbuffer);
        zs.avail_out = sizeof(outbuffer);

        ret = inflate(&zs, 0);

        if (outstring.size() < zs.total_out) {
            outstring.append(outbuffer,
                             zs.total_out - outstring.size());
        }

    } while (ret == Z_OK);

    inflateEnd(&zs);

    if (ret != Z_STREAM_END) {          // an error occurred that was not EOF
        std::ostringstream oss;
        oss << "Exception during zlib decompression: (" << ret << ") "
            << zs.msg;
        throw(std::runtime_error(oss.str()));
    }

    return outstring;
}



