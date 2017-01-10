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

#pragma once
#include <jsoncpp/json/json.h>
#include "libXBMC_addon.h"
#include "string.h"
#include <zlib.h>

#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
typedef unsigned char BYTE;



class MSLFilter
{
public:
    enum CURLOPTIONS
    {
        OPTION_PROTOCOL,
        OPTION_HEADER
    };
  bool msl_initialize(ADDON::CHelper_libXBMC_addon *xbmc);
  std::string msl_download_manifest(const char *url);
  bool msl_download_license();

private:
    std::string publicKey;
    Json::Value masterToken;
    Json::Value serviceTokens;
    Json::Value useridtoken;

    int sequenceNumber;
    unsigned char *privateKey;
    unsigned char *AESEncryptionKey;
    unsigned char *HMACSigningKey;
    size_t hmacKeyLength;
    EVP_PKEY *pkey;
    EVP_PKEY_CTX *ctx;

    std::string AESEncrypt(std::string payload, int sequenceNumber);
    std::string AESDecrypt(std::string ciphertext, std::string iv);

    std::string sign(std::string payload);
    std::string b64_decode_string(std::string const& encoded_string);



    std::string perform_msl_post_request(std::string url, std::string postData);
    Json::Value perform_msl_post_json_request(std::string url, std::string postData);

    std::string generate_msl_request(Json::Value requestData);
    Json::Value generate_msl_header();

    std::string parse_msl_response(std::string response);

    std::string compress_string(const std::string& str, int compressionlevel);
    std::string decompress_string(const std::string& str);

    std::string decrypt_rsa(std::string base64Encrypted);


    bool create_private_key();
    bool perform_key_exchange();
};
