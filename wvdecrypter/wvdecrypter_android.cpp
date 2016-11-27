/*
*      Copyright (C) 2016 liberty-developer
*      https://github.com/liberty-developer
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

#include "media/NdkMediaDrm.h"
#include "../src/helpers.h"
#include "../src/SSD_dll.h"
#include "jsmn.h"
#include "Ap4.h"
#include <stdarg.h>
#include <deque>

SSD_HOST *host = 0;

static void Log(SSD_HOST::LOGLEVEL loglevel, const char *format, ...)
{
  char buffer[16384];
  va_list args;
  va_start(args, format);
  vsprintf(buffer, format, args);
  va_end(args);
  return host->Log(loglevel, buffer);
}

/*******************************************************
CDM
********************************************************/

/*----------------------------------------------------------------------
|   WV_CencSingleSampleDecrypter
+---------------------------------------------------------------------*/
class WV_CencSingleSampleDecrypter : public AP4_CencSingleSampleDecrypter
{
public:
  // methods
  WV_CencSingleSampleDecrypter(std::string licenseURL, const uint8_t *pssh, size_t pssh_size);
  ~WV_CencSingleSampleDecrypter();

  bool initialized()const { return media_drm_ != 0; };

  virtual AP4_Result SetFrameInfo(const AP4_UI16 key_size, const AP4_UI08 *key, const AP4_UI08 nal_length_size) override;

  virtual AP4_Result DecryptSampleData(AP4_DataBuffer& data_in,
    AP4_DataBuffer& data_out,

    // always 16 bytes
    const AP4_UI08* iv,

    // pass 0 for full decryption
    unsigned int    subsample_count,

    // array of <subsample_count> integers. NULL if subsample_count is 0
    const AP4_UI16* bytes_of_cleartext_data,

    // array of <subsample_count> integers. NULL if subsample_count is 0
    const AP4_UI32* bytes_of_encrypted_data);

private:
  bool ProvisionRequest();
  bool GetLicense();
  bool SendSessionMessage();

  AMediaDrm *media_drm_;
  AMediaDrmByteArray session_id_;
  const uint8_t *key_request_;
  size_t key_request_size_;

  std::string pssh_, license_url_;
  AP4_UI16 key_size_;
  uint8_t key_[32];
  AP4_UI08 nal_length_size_;
};


void MediaDrmEventListener(AMediaDrm *media_drm, const AMediaDrmSessionId *sessionId, AMediaDrmEventType eventType, int extra, const uint8_t *data, size_t dataSize)
{
  Log(SSD_HOST::LL_DEBUG, "EVENT occured (%d)", eventType);
}

/*----------------------------------------------------------------------
|   WV_CencSingleSampleDecrypter::WV_CencSingleSampleDecrypter
+---------------------------------------------------------------------*/

WV_CencSingleSampleDecrypter::WV_CencSingleSampleDecrypter(std::string licenseURL, const uint8_t *pssh, size_t pssh_size)
  : AP4_CencSingleSampleDecrypter(0)
  , media_drm_(0)
  , license_url_(licenseURL)
  , pssh_(std::string(reinterpret_cast<const char*>(pssh), pssh_size))
  , key_size_(0)
  , nal_length_size_(0)
{
  SetParentIsOwner(false);

  if (pssh_size > 256)
  {
    Log(SSD_HOST::LL_ERROR, "Init_data with length: %u seems not to be cenc init data!", pssh_size);
    return;
  }

#ifdef _DEBUG
  std::string strDbg = host->GetProfilePath();
  strDbg += "EDEF8BA9-79D6-4ACE-A3C8-27DCD51D21ED.init";
  FILE*f = fopen(strDbg.c_str(), "wb");
  fwrite(pssh_.c_str(), 1, pssh_.size(), f);
  fclose(f);
#endif

  if (strcmp(&pssh_[4], "pssh") != 0)
  {
    static const uint8_t atom[] = { 0x00, 0x00, 0x00, 0x00, 0x70, 0x73, 0x73, 0x68, 0x00, 0x00, 0x00, 0x00, 0xed, 0xef, 0x8b, 0xa9,
      0x79, 0xd6, 0x4a, 0xce, 0xa3, 0xc8, 0x27, 0xdc, 0xd5, 0x1d, 0x21, 0xed, 0x00, 0x00, 0x00, 0x00 };

    pssh_.insert(0, std::string(reinterpret_cast<const char*>(atom), sizeof(atom)));

    pssh_[3] = static_cast<uint8_t>(pssh_.size());
    pssh_[sizeof(atom) - 1] = static_cast<uint8_t>(pssh_.size()) - sizeof(atom);
  }

  std::string strBasePath = host->GetProfilePath();
  char cSep = strBasePath.back();
  strBasePath += "widevine";
  strBasePath += cSep;
  host->CreateDirectory(strBasePath.c_str());

  //Build up a CDM path to store decrypter specific stuff. Each domain gets it own path
  const char* bspos(strchr(license_url_.c_str(), ':'));
  if (!bspos || bspos[1] != '/' || bspos[2] != '/' || !(bspos = strchr(bspos + 3, '/')))
  {
    Log(SSD_HOST::LL_ERROR, "Could not find protocol inside url - invalid");
    return;
  }
  if (bspos - license_url_.c_str() > 256)
  {
    Log(SSD_HOST::LL_ERROR, "Length of domain exeeds max. size of 256 - invalid");
    return;
  }
  char buffer[1024];
  buffer[(bspos - license_url_.c_str()) * 2] = 0;
  AP4_FormatHex(reinterpret_cast<const uint8_t*>(license_url_.c_str()), bspos - license_url_.c_str(), buffer);

  strBasePath += buffer;
  strBasePath += cSep;
  host->CreateDirectory(strBasePath.c_str());

  uint8_t keysystem[16] = { 0xed, 0xef, 0x8b, 0xa9, 0x79, 0xd6, 0x4a, 0xce, 0xa3, 0xc8, 0x27, 0xdc, 0xd5, 0x1d, 0x21, 0xed };
  media_drm_ = AMediaDrm_createByUUID(keysystem);
  if (!media_drm_)
  {
    Log(SSD_HOST::LL_ERROR, "Unable to initialize media_drm");
    return;
  }
  Log(SSD_HOST::LL_DEBUG, "Successful instanciated media_drm: %X", (unsigned int)media_drm_);

  media_status_t status;
  if ((status = AMediaDrm_setOnEventListener(media_drm_, MediaDrmEventListener)) != AMEDIA_OK)
  {
    Log(SSD_HOST::LL_ERROR, "Unable to install Event Listener (%d)", status);
    AMediaDrm_release(media_drm_);
    media_drm_ = 0;
    return;
  }

  memset(&session_id_, 0, sizeof(session_id_));
  if ((status = AMediaDrm_openSession(media_drm_, &session_id_)) != AMEDIA_OK)
  {
    Log(SSD_HOST::LL_ERROR, "Unable to open DRM session (%d)", status);
    AMediaDrm_release(media_drm_);
    media_drm_ = 0;
    return;
  }

  // For backward compatibility: If no | is found in URL, make the amazon convention out of it
  if (license_url_.find('|') == std::string::npos)
    license_url_ += "|Content-Type=application%2Fx-www-form-urlencoded|widevine2Challenge=B{SSM}&includeHdcpTestKeyInLicense=false|JBlicense";

  if (/*!ProvisionRequest() ||*/ !GetLicense())
  {
    Log(SSD_HOST::LL_ERROR, "Unable to generate a license");
    AMediaDrm_closeSession(media_drm_, &session_id_);
    AMediaDrm_release(media_drm_);
    media_drm_ = 0;
    return;
  }
}

WV_CencSingleSampleDecrypter::~WV_CencSingleSampleDecrypter()
{
  if (media_drm_)
  {
    AMediaDrm_closeSession(media_drm_, &session_id_);
    AMediaDrm_release(media_drm_);
    media_drm_ = 0;
  }
}

bool WV_CencSingleSampleDecrypter::ProvisionRequest()
{
  const char *url(0);

  media_status_t status = AMediaDrm_getProvisionRequest(media_drm_, &key_request_, &key_request_size_, &url);

  if (status != AMEDIA_OK || !url)
  {
    Log(SSD_HOST::LL_ERROR, "PrivisionData request failed with status: %d", status);
    return false;
  }
  Log(SSD_HOST::LL_DEBUG, "PrivisionData: status: %d, size: %u, url: %s", status, key_request_size_, url);

  std::string tmp_str(url);
  tmp_str += "&signedRequest=";
  tmp_str += std::string(reinterpret_cast<const char*>(key_request_), key_request_size_);

  void* file = host->CURLCreate(tmp_str.c_str());

  if (!host->CURLOpen(file))
  {
    Log(SSD_HOST::LL_ERROR, "Provisioning server returned failure");
    return false;
  }
  tmp_str.clear();
  char buf[8192];
  size_t nbRead;

  // read the file
  while ((nbRead = host->ReadFile(file, buf, 8192)) > 0)
    tmp_str += std::string((const char*)buf, nbRead);

  Log(SSD_HOST::LL_DEBUG, tmp_str.c_str());
  return false;
}


bool WV_CencSingleSampleDecrypter::GetLicense()
{
  media_status_t status = AMediaDrm_getKeyRequest(media_drm_, &session_id_,
    reinterpret_cast<const uint8_t*>(pssh_.data()), pssh_.size(), "video/mp4", KEY_TYPE_STREAMING,
    0, 0,
    &key_request_, &key_request_size_);

  if (status != AMEDIA_OK || !key_request_size_)
  {
    Log(SSD_HOST::LL_ERROR, "Key request not successful (%d)", status);
    return false;
  }

  Log(SSD_HOST::LL_DEBUG, "Key request successful, size: %u", reinterpret_cast<unsigned int>(key_request_size_));

  if (!SendSessionMessage())
    return false;

  Log(SSD_HOST::LL_DEBUG, "License update successful");

  return true;
}

bool WV_CencSingleSampleDecrypter::SendSessionMessage()
{

  std::vector<std::string> headers, header, blocks = split(license_url_, '|');
  if (blocks.size() != 4)
  {
    Log(SSD_HOST::LL_ERROR, "4 '|' separated blocks in licURL expected (req / header / body / response)");
    return false;
  }

#ifdef _DEBUG
  std::string strDbg = host->GetProfilePath();
  strDbg += "EDEF8BA9-79D6-4ACE-A3C8-27DCD51D21ED.challenge";
  FILE*f = fopen(strDbg.c_str(), "wb");
  fwrite(wv_adapter->GetMessage(), 1, wv_adapter->GetMessageSize(), f);
  fclose(f);
#endif

  //Process placeholder in GET String
  std::string::size_type insPos(blocks[0].find("{SSM}"));
  if (insPos != std::string::npos)
  {
    if (insPos >= 0 && blocks[0][insPos - 1] == 'B')
    {
      std::string msgEncoded = b64_encode(key_request_, key_request_size_, true);
      blocks[0].replace(insPos - 1, 6, msgEncoded);
    }
    else
    {
      Log(SSD_HOST::LL_ERROR, "Unsupported License request template (cmd)");
      return false;
    }
  }

  void* file = host->CURLCreate(blocks[0].c_str());

  size_t nbRead;
  std::string response;
  char buf[2048];
  AMediaDrmKeySetId dummy_ksid; //STREAMING returns 0
  media_status_t status;
  //Set our std headers
  host->CURLAddOption(file, SSD_HOST::OPTION_PROTOCOL, "acceptencoding", "gzip, deflate");
  host->CURLAddOption(file, SSD_HOST::OPTION_PROTOCOL, "seekable", "0");
  host->CURLAddOption(file, SSD_HOST::OPTION_HEADER, "Expect", "");

  //Process headers
  headers = split(blocks[1], '&');
  for (std::vector<std::string>::iterator b(headers.begin()), e(headers.end()); b != e; ++b)
  {
    header = split(*b, '=');
    host->CURLAddOption(file, SSD_HOST::OPTION_PROTOCOL, trim(header[0]).c_str(), header.size() > 1 ? url_decode(trim(header[1])).c_str() : "");
  }

  //Process body
  if (!blocks[2].empty())
  {
    insPos = blocks[2].find("{SSM}");
    if (insPos != std::string::npos)
    {
      if (insPos >= 0)
      {
        if (blocks[2][insPos - 1] == 'B')
        {
          std::string msgEncoded = b64_encode(key_request_, key_request_size_, true);
          blocks[2].replace(insPos - 1, 6, msgEncoded);
        }
        else
          blocks[2].replace(insPos - 1, 6, reinterpret_cast<const char*>(key_request_), key_request_size_);
      }
      else
      {
        Log(SSD_HOST::LL_ERROR, "Unsupported License request template (body)");
        goto SSMFAIL;
      }
    }
    std::string decoded = b64_encode(reinterpret_cast<const unsigned char*>(blocks[2].data()), blocks[2].size(), false);
    host->CURLAddOption(file, SSD_HOST::OPTION_PROTOCOL, "postdata", decoded.c_str());
  }

  if (!host->CURLOpen(file))
  {
    Log(SSD_HOST::LL_ERROR, "License server returned failure");
    goto SSMFAIL;
  }

  // read the file
  while ((nbRead = host->ReadFile(file, buf, 1024)) > 0)
    response += std::string((const char*)buf, nbRead);

  host->CloseFile(file);
  file = 0;

  if (nbRead != 0)
  {
    Log(SSD_HOST::LL_ERROR, "Could not read full SessionMessage response");
    goto SSMFAIL;
  }

#ifdef _DEBUG
  strDbg = host->GetProfilePath();
  strDbg += "EDEF8BA9-79D6-4ACE-A3C8-27DCD51D21ED.response";
  f = fopen(strDbg.c_str(), "wb");
  fwrite(response.c_str(), 1, response.size(), f);
  fclose(f);
#endif

  if (!blocks[3].empty())
  {
    if (blocks[3][0] == 'J')
    {
      jsmn_parser jsn;
      jsmntok_t tokens[100];

      jsmn_init(&jsn);
      int i(0), numTokens = jsmn_parse(&jsn, response.c_str(), response.size(), tokens, 100);

      for (; i < numTokens; ++i)
        if (tokens[i].type == JSMN_STRING && tokens[i].size == 1
          && strncmp(response.c_str() + tokens[i].start, blocks[3].c_str() + 2, tokens[i].end - tokens[i].start) == 0)
          break;

      if (i < numTokens)
      {
        if (blocks[3][1] == 'B')
        {
          unsigned int decoded_size = 2048;
          uint8_t decoded[2048];

          b64_decode(response.c_str() + tokens[i + 1].start, tokens[i + 1].end - tokens[i + 1].start, decoded, decoded_size);
          status = AMediaDrm_provideKeyResponse(media_drm_, &session_id_, decoded, decoded_size, &dummy_ksid);
        }
        else
          status = AMediaDrm_provideKeyResponse(media_drm_, &session_id_, reinterpret_cast<const uint8_t*>(response.c_str() + tokens[i + 1].start), tokens[i + 1].end - tokens[i + 1].start, &dummy_ksid);
      }
      else
      {
        Log(SSD_HOST::LL_ERROR, "Unable to find %s in JSON string", blocks[3].c_str() + 2);
        goto SSMFAIL;
      }
    }
    else
    {
      Log(SSD_HOST::LL_ERROR, "Unsupported License request template (response)");
      goto SSMFAIL;
    }
  }
  else //its binary - simply push the returned data as update
    status = AMediaDrm_provideKeyResponse(media_drm_, &session_id_, reinterpret_cast<const uint8_t*>(response.data()), response.size(), &dummy_ksid);

  return status == AMEDIA_OK;
SSMFAIL:
  if (file)
    host->CloseFile(file);
  return false;
}

/*----------------------------------------------------------------------
|   WV_CencSingleSampleDecrypter::SetKeyId
+---------------------------------------------------------------------*/

AP4_Result WV_CencSingleSampleDecrypter::SetFrameInfo(const AP4_UI16 key_size, const AP4_UI08 *key, const AP4_UI08 nal_length_size)
{
  if (key_size > 32)
    return AP4_ERROR_INVALID_PARAMETERS;

  key_size_ = key_size;
  memcpy(key_, key, key_size);
  nal_length_size_ = nal_length_size;
  return AP4_SUCCESS;
}

/*----------------------------------------------------------------------
|   WV_CencSingleSampleDecrypter::DecryptSampleData
+---------------------------------------------------------------------*/
AP4_Result WV_CencSingleSampleDecrypter::DecryptSampleData(
  AP4_DataBuffer& data_in,
  AP4_DataBuffer& data_out,
  const AP4_UI08* iv,
  unsigned int    subsample_count,
  const AP4_UI16* bytes_of_cleartext_data,
  const AP4_UI32* bytes_of_encrypted_data)
{
  if (!media_drm_)
    return AP4_ERROR_INVALID_STATE;

  if (data_in.GetDataSize() == 0)
  {
    data_out.SetData(reinterpret_cast<const AP4_Byte*>("CRYPTO"), 6);
    uint16_t cryptosize = 6 + 2 + (1 + session_id_.length) + 16;
    data_out.AppendData(reinterpret_cast<const AP4_Byte*>(&cryptosize), sizeof(cryptosize));
    uint8_t dummy(session_id_.length);
    data_out.AppendData(&dummy, 1);
    data_out.AppendData(session_id_.ptr, session_id_.length);
    uint8_t keysystem[16] = { 0xed, 0xef, 0x8b, 0xa9, 0x79, 0xd6, 0x4a, 0xce, 0xa3, 0xc8, 0x27, 0xdc, 0xd5, 0x1d, 0x21, 0xed };
    data_out.AppendData(keysystem, 16);
  }
  else
  {
    if (nal_length_size_ > 4)
    {
      Log(SSD_HOST::LL_ERROR, "Nalu length size > 4 not supported");
      return AP4_ERROR_NOT_SUPPORTED;
    }

    data_out.SetData(reinterpret_cast<const AP4_Byte*>(&subsample_count), sizeof(subsample_count));
    data_out.AppendData(reinterpret_cast<const AP4_Byte*>(bytes_of_cleartext_data), subsample_count * sizeof(AP4_UI16));
    data_out.AppendData(reinterpret_cast<const AP4_Byte*>(bytes_of_encrypted_data), subsample_count * sizeof(AP4_UI32));
    data_out.AppendData(reinterpret_cast<const AP4_Byte*>(iv), 16);
    data_out.AppendData(reinterpret_cast<const AP4_Byte*>(key_), 16);

    if (nal_length_size_ && subsample_count)
    {
      //check NAL / subsample
      const AP4_Byte *packet_in_tmp(data_in.GetData()), *packet_in_tmp_e(data_in.GetData() + data_in.GetDataSize());
      while (packet_in_tmp < packet_in_tmp_e)
      {
        uint32_t nalsize(0);
        for (unsigned int i(0); i < nal_length_size_; ++i) { nalsize = (nalsize << 8) + *packet_in_tmp++; };
        if (nalsize + nal_length_size_ != *bytes_of_cleartext_data + *bytes_of_encrypted_data)
        {
          Log(SSD_HOST::LL_ERROR, "Mismatch NAL / Subsample (nls: %d) %d -> &d ", nal_length_size_, nalsize + nal_length_size_, *bytes_of_cleartext_data + *bytes_of_encrypted_data);
          return AP4_ERROR_NOT_SUPPORTED;
        }
        ++bytes_of_cleartext_data;
        ++bytes_of_encrypted_data;
        packet_in_tmp += nalsize;
      }

      //convert avc -> annexb by simply removing nal 4-byte header with anex-b startcode 
      AP4_Size oldSize(data_out.GetDataSize());
      data_out.SetDataSize(data_out.GetDataSize() + data_in.GetDataSize() + (4 - nal_length_size_) * subsample_count);

      const AP4_Byte *packet_in(data_in.GetData());
      AP4_Byte *packet_out(data_out.UseData() + oldSize);
      AP4_UI16 *clrb(reinterpret_cast<AP4_UI16*>(data_out.UseData() + sizeof(subsample_count)));
      AP4_UI32 *ciphb(reinterpret_cast<AP4_UI32*>(clrb + subsample_count));

      for (unsigned int i(0); i < subsample_count; ++i)
      {
        //Anex-B Start pos
        packet_out[0] = packet_out[1] = packet_out[2] = 0; packet_out[3] = 1;
        memcpy(&packet_out[4], &packet_in[nal_length_size_], clrb[i] + ciphb[i] - nal_length_size_);
        packet_in += (clrb[i] + ciphb[i]);
        clrb[i] += (4 - nal_length_size_);
        packet_out += (clrb[i] + ciphb[i]);
      }
    }
    else
      data_out.AppendData(data_in.GetData(), data_in.GetDataSize());
  }
  return AP4_SUCCESS;
}

class WVDecrypter : public SSD_DECRYPTER
{
public:
  // Return supported URN if type matches to capabikitues, otherwise null
  const char *Supported(const char* licenseType, const char *licenseKey) override
  {
    licenseKey_ = licenseKey;
    if (strcmp(licenseType, "com.widevine.alpha") == 0)
      return "urn:uuid:EDEF8BA9-79D6-4ACE-A3C8-27DCD51D21ED";
    return 0;
  };

  AP4_CencSingleSampleDecrypter *CreateSingleSampleDecrypter(AP4_DataBuffer &streamCodec) override
  {
    AP4_CencSingleSampleDecrypter *res = new WV_CencSingleSampleDecrypter(licenseKey_, streamCodec.GetData(), streamCodec.GetDataSize());
    if (!((WV_CencSingleSampleDecrypter*)res)->initialized())
    {
      delete res;
      res = 0;
    }
    return res;
  }
private:
  std::string licenseKey_;
} decrypter;

extern "C" {

#ifdef _WIN32
#define MODULE_API __declspec(dllexport)
#else
#define MODULE_API
#endif

  class SSD_DECRYPTER MODULE_API *CreateDecryptorInstance(class SSD_HOST *h, uint32_t host_version)
  {
    if (host_version != SSD_HOST::version)
      return 0;
    host = h;
    return &decrypter;
  };

};
