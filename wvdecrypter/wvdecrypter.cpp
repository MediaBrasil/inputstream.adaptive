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

#include "cdm/media/cdm/cdm_adapter.h"
#include "../src/helpers.h"
#include "../src/SSD_dll.h"
#include "jsmn.h"
#include "Ap4.h"

#include <stdarg.h>
#include <deque>
#include <list>

#ifndef WIDEVINECDMFILENAME
#error  "WIDEVINECDMFILENAME must be set"
#endif

using namespace SSD;

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
|   CdmDecryptedBlock implementation
+---------------------------------------------------------------------*/

class CdmDecryptedBlock : public cdm::DecryptedBlock {
public:
  CdmDecryptedBlock() :buffer_(0), timestamp_(0) {};
  virtual ~CdmDecryptedBlock() {};

  virtual void SetDecryptedBuffer(cdm::Buffer* buffer) override { buffer_ = buffer; };
  virtual cdm::Buffer* DecryptedBuffer() override { return buffer_; };

  virtual void SetTimestamp(int64_t timestamp) override { timestamp_ = timestamp; };
  virtual int64_t Timestamp() const override { return timestamp_; };
private:
  cdm::Buffer *buffer_;
  int64_t timestamp_;
};

/*----------------------------------------------------------------------
|   CdmDecryptedBlock implementation
+---------------------------------------------------------------------*/
class CdmBuffer : public cdm::Buffer {
public:
  CdmBuffer(AP4_DataBuffer *buffer) :buffer_(buffer) {};
  virtual ~CdmBuffer() {};

  virtual void Destroy() override {};

  virtual uint32_t Capacity() const override
  {
    return buffer_->GetBufferSize();
  };
  virtual uint8_t* Data() override
  {
    return (uint8_t*)buffer_->GetData();
  };
  virtual void SetSize(uint32_t size) override
  {
    buffer_->SetDataSize(size);
  };
  virtual uint32_t Size() const override
  {
    return buffer_->GetDataSize();
  };
private:
  AP4_DataBuffer *buffer_;
};

/*----------------------------------------------------------------------
|   CdmVideoDecoder implementation
+---------------------------------------------------------------------*/

class CdmFixedBuffer : public cdm::Buffer {
public:
  CdmFixedBuffer() : data_(nullptr), dataSize_(0), capacity_(0) {};
  virtual ~CdmFixedBuffer() {};

  virtual void Destroy() override {};

  virtual uint32_t Capacity() const override
  {
    return capacity_;
  };
  virtual uint8_t* Data() override
  {
    return data_;
  };
  virtual void SetSize(uint32_t size) override
  {
    dataSize_ = size;
  };
  virtual uint32_t Size() const override
  {
    return dataSize_;
  };

  void initialize(uint8_t* data, size_t dataSize)
  {
    data_ = data;
    dataSize_ = 0;
    capacity_ = dataSize;
  }

private:
  uint8_t *data_;
  size_t dataSize_, capacity_;
};

class CdmVideoFrame : public cdm::VideoFrame {
public:
  CdmVideoFrame() :m_buffer(0) {};

  virtual void SetFormat(cdm::VideoFormat format) override
  {
    m_format = format;
  }

  virtual cdm::VideoFormat Format() const override
  {
    return m_format;
  }

  virtual void SetSize(cdm::Size size) override
  {
    m_size = size;
  }

  virtual cdm::Size Size() const override
  {
    return m_size;
  }

  virtual void SetFrameBuffer(cdm::Buffer* frame_buffer) override
  {
    m_buffer = frame_buffer;
  }

  virtual cdm::Buffer* FrameBuffer() override
  {
    return m_buffer;
  }

  virtual void SetPlaneOffset(VideoPlane plane, uint32_t offset) override
  {
    m_planeOffsets[plane] = offset;
  }

  virtual uint32_t PlaneOffset(VideoPlane plane) override
  {
    return m_planeOffsets[plane];
  }

  virtual void SetStride(VideoPlane plane, uint32_t stride) override
  {
    m_stride[plane] = stride;
  }

  virtual uint32_t Stride(VideoPlane plane) override
  {
    return m_stride[plane];
  }

  virtual void SetTimestamp(int64_t timestamp) override
  {
    m_pts = timestamp;
  }

  virtual int64_t Timestamp() const override
  {
    return m_pts;
  }
private:
  cdm::VideoFormat m_format;
  cdm::Buffer *m_buffer;
  cdm::Size m_size;

  uint32_t m_planeOffsets[cdm::VideoFrame::kMaxPlanes];
  uint32_t m_stride[cdm::VideoFrame::kMaxPlanes];

  uint64_t m_pts;
};

/*----------------------------------------------------------------------
|   WV_CencSingleSampleDecrypter
+---------------------------------------------------------------------*/

struct WVSession
{
  std::string session;

  AP4_DataBuffer pssh, challenge;

  struct WVSKEY
  {
    std::string keyid;
    cdm::KeyStatus status;
  };

  std::vector<WVSKEY> keys;
};

class WV_CencSingleSampleDecrypter : public AP4_CencSingleSampleDecrypter, public media::CdmAdapterClient
{
public:
  // methods
  WV_CencSingleSampleDecrypter(std::string licenseURL, AP4_DataBuffer &serverCertificate);
  ~WV_CencSingleSampleDecrypter();

  size_t CreateSession(AP4_DataBuffer &pssh);
  void CloseSession(size_t sessionhandle);
  const SSD_DECRYPTER::SSD_CAPS &GetCapabilities(size_t sessionHandle, const uint8_t* key);
  const char *GetSessionId(size_t sessionHandle);

  bool initialized()const { return wv_adapter != nullptr; };

  virtual void OnCDMMessage(const char* session, uint32_t session_size, CDMADPMSG msg, const uint8_t *data, size_t data_size, uint32_t status) override
  {
    Log(SSD_HOST::LL_DEBUG, "CDMMessage: %u arrived!", msg);
    if (msg == CDMADPMSG::kSessionMessage)
    {
      sessions_.back()->session = std::string(session, session_size);
      sessions_.back()->challenge.SetData(data, data_size);
    }
    else if (msg == CDMADPMSG::kSessionKeysChange)
    {
      sessions_.back()->keys.push_back(WVSession::WVSKEY());
      sessions_.back()->keys.back().keyid = std::string((const char*)data, data_size);
      sessions_.back()->keys.back().status = static_cast<cdm::KeyStatus>(status);
    }
  };

  virtual void CDMLog(const char *msg) override
  {
    host->Log(SSD_HOST::LOGLEVEL::LL_DEBUG, msg);
  }

  virtual cdm::Buffer *AllocateBuffer(size_t sz) override
  {
    SSD_PICTURE pic;
    pic.decodedDataSize = sz;
    if (host->GetBuffer(host_instance_, pic))
    {
      CdmFixedBuffer *buf = new CdmFixedBuffer;
      buf->initialize(pic.decodedData, pic.decodedDataSize);
      return buf;
    }
    return nullptr;
  };

  virtual AP4_Result SetFrameInfo(const AP4_UI16 key_size, const AP4_UI08 *key, const AP4_UI08 nal_length_size, AP4_DataBuffer &annexb_sps_pps)override;

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

  bool OpenVideoDecoder(const SSD_VIDEOINITDATA *initData);
  SSD_DECODE_RETVAL DecodeVideo(void* hostInstance, SSD_SAMPLE *sample, SSD_PICTURE *picture);
  void ResetVideo();

private:
  bool SendSessionMessage(const char* session, uint32_t session_size, const uint8_t *message, uint32_t message_size);

  std::shared_ptr<media::CdmAdapter> wv_adapter;
  std::vector<WVSession*> sessions_;

  unsigned int max_subsample_count_;
  cdm::SubsampleEntry *subsample_buffer_;
  AP4_DataBuffer decrypt_in_, decrypt_out_;
  bool use_single_decrypt_;

  std::string license_url_;
  AP4_UI16 key_size_;
  const AP4_UI08 *key_;
  AP4_UI08 nal_length_size_;
  AP4_DataBuffer annexb_sps_pps_;
  SSD_DECRYPTER::SSD_CAPS decrypter_caps_;
  void *host_instance_;
  uint32_t promise_id_;

  std::list<CdmVideoFrame> videoFrames_;
};

/*----------------------------------------------------------------------
|   WV_CencSingleSampleDecrypter::WV_CencSingleSampleDecrypter
+---------------------------------------------------------------------*/

WV_CencSingleSampleDecrypter::WV_CencSingleSampleDecrypter(std::string licenseURL, AP4_DataBuffer &serverCertificate)
  : AP4_CencSingleSampleDecrypter(0)
  , max_subsample_count_(0)
  , subsample_buffer_(0)
  , use_single_decrypt_(false)
  , license_url_(licenseURL)
  , key_size_(0)
  , key_(0)
  , nal_length_size_(0)
  , host_instance_(0)
  , promise_id_(0)
{
  memset(&decrypter_caps_, 0, sizeof(decrypter_caps_));

  std::string strLibPath = host->GetLibraryPath();
  if (strLibPath.empty())
  {
    Log(SSD_HOST::LL_ERROR, "Absolute path to widevine in settings expected");
    return;
  }
  strLibPath += WIDEVINECDMFILENAME;

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

  wv_adapter = std::shared_ptr<media::CdmAdapter>(new media::CdmAdapter("com.widevine.alpha", strLibPath, strBasePath, media::CdmConfig(false, true), (dynamic_cast<media::CdmAdapterClient*>(this))));
  if (!wv_adapter->valid())
  {
    Log(SSD_HOST::LL_ERROR, "Unable to load widevine shared library (%s)", strLibPath.c_str());
    wv_adapter = nullptr;
    return;
  }

  if (serverCertificate.GetDataSize())
    wv_adapter->SetServerCertificate(0, serverCertificate.GetData(), serverCertificate.GetDataSize());

  // For backward compatibility: If no | is found in URL, make the amazon convention out of it
  if (license_url_.find('|') == std::string::npos)
    license_url_ += "|Content-Type=application%2Fx-www-form-urlencoded|widevine2Challenge=B{SSM}&includeHdcpTestKeyInLicense=true|JBlicense;hdcpEnforcementResolutionPixels";

  wv_adapter->QueryOutputProtectionStatus();

  SetParentIsOwner(false);
}

WV_CencSingleSampleDecrypter::~WV_CencSingleSampleDecrypter()
{
  Log(SSD_HOST::LL_DEBUG, "Destroying wv_adapter");

  wv_adapter->RemoveClient();

  for (auto s : sessions_)
  {
    wv_adapter->CloseSession(++promise_id_, s->session.data(), s->session.size());
    delete s;
  }
  sessions_.clear();

  wv_adapter = nullptr;
}

const SSD_DECRYPTER::SSD_CAPS &WV_CencSingleSampleDecrypter::GetCapabilities(size_t sessionHandle, const uint8_t* key)
{
  if (sessions_.empty())
    return decrypter_caps_;

  decrypter_caps_.flags = SSD_DECRYPTER::SSD_CAPS::SSD_SUPPORTS_DECODING;
  use_single_decrypt_ = false;

  WVSession *session(sessions_.back());
  if (session->keys.empty())
    return decrypter_caps_;

  if (decrypter_caps_.hdcpLimit)
  {
    decrypter_caps_.flags |= (SSD_DECRYPTER::SSD_CAPS::SSD_SECURE_PATH | SSD_DECRYPTER::SSD_CAPS::SSD_ANNEXB_REQUIRED);
  }
  else
  {
    for (auto k : session->keys)
      if (!key || memcmp(k.keyid.data(), key, 16) == 0)
      {
        if (k.status != 0)
          decrypter_caps_.flags |= (SSD_DECRYPTER::SSD_CAPS::SSD_SECURE_PATH | SSD_DECRYPTER::SSD_CAPS::SSD_ANNEXB_REQUIRED);
        break;
      }
  }

  if (decrypter_caps_.flags == SSD_DECRYPTER::SSD_CAPS::SSD_SUPPORTS_DECODING)
  {
    key_ = key;
    key_size_ = 16;

    decrypter_caps_.hdcpVersion = 99;

    AP4_DataBuffer in, out;
    AP4_UI32 encb[2] = { 1,1 };
    AP4_UI16 clearb[2] = { 5,5 };
    AP4_Byte vf[12]={0,0,0,1,9,255,0,0,0,1,10,255};
    const AP4_UI08 iv[] = { 1,2,3,4,5,6,7,8,0,0,0,0,0,0,0,0 };
    in.SetBuffer(vf,12);
    in.SetDataSize(12);
    try {
      if (DecryptSampleData(in, out, iv, 2, clearb, encb) != AP4_SUCCESS)
      {
        encb[0] = 12;
        clearb[0] = 0;
        if (DecryptSampleData(in, out, iv, 1, clearb, encb) != AP4_SUCCESS)
          decrypter_caps_.flags |= (SSD_DECRYPTER::SSD_CAPS::SSD_SECURE_PATH | SSD_DECRYPTER::SSD_CAPS::SSD_ANNEXB_REQUIRED);
        else
        {
          use_single_decrypt_ = true;
        }
      }
    }
    catch (...) {
      decrypter_caps_.flags |= (SSD_DECRYPTER::SSD_CAPS::SSD_SECURE_PATH | SSD_DECRYPTER::SSD_CAPS::SSD_ANNEXB_REQUIRED);
    }
    key_size_ = 0;
  }
  return decrypter_caps_;
}

const char *WV_CencSingleSampleDecrypter::GetSessionId(size_t sessionHandle)
{
  return sessions_.empty()? nullptr : sessions_.back()->session.c_str();
}

size_t WV_CencSingleSampleDecrypter::CreateSession(AP4_DataBuffer &pssh)
{
  if (pssh.GetDataSize() > 256)
  {
    Log(SSD_HOST::LL_ERROR, "Init_data with length: %u seems not to be cenc init data!", pssh.GetDataSize());
    return 0;
  }

#ifdef _DEBUG
  std::string strDbg = host->GetProfilePath();
  strDbg += "EDEF8BA9-79D6-4ACE-A3C8-27DCD51D21ED.init";
  FILE*f = fopen(strDbg.c_str(), "wb");
  fwrite(pssh.GetData(), 1, pssh.GetDataSize(), f);
  fclose(f);
#endif

  sessions_.push_back(new WVSession);

  if (memcmp(pssh.GetData()+4, "pssh", 4) == 0)
  {
    wv_adapter->CreateSessionAndGenerateRequest(0, cdm::SessionType::kTemporary, cdm::InitDataType::kCenc,
      reinterpret_cast<const uint8_t *>(pssh.GetData()), pssh.GetDataSize());
  }
  else
  {
    unsigned int buf_size = 32 + pssh.GetDataSize();
    uint8_t buf[1024];

    // This will request a new session and initializes session_id and message members in cdm_adapter.
    // message will be used to create a license request in the step after CreateSession call.
    // Initialization data is the widevine cdm pssh code in google proto style found in mpd schemeIdUri
    static uint8_t proto[] = { 0x00, 0x00, 0x00, 0x63, 0x70, 0x73, 0x73, 0x68, 0x00, 0x00, 0x00, 0x00, 0xed, 0xef, 0x8b, 0xa9,
      0x79, 0xd6, 0x4a, 0xce, 0xa3, 0xc8, 0x27, 0xdc, 0xd5, 0x1d, 0x21, 0xed, 0x00, 0x00, 0x00, 0x00 };

    proto[3] = static_cast<uint8_t>(buf_size);
    proto[31] = static_cast<uint8_t>(pssh.GetDataSize());

    memcpy(buf, proto, sizeof(proto));
    memcpy(&buf[32], pssh.GetData(), pssh.GetDataSize());

    wv_adapter->CreateSessionAndGenerateRequest(0, cdm::SessionType::kTemporary, cdm::InitDataType::kCenc, buf, buf_size);
  }

  if (sessions_.back()->session.empty())
  {
    Log(SSD_HOST::LL_ERROR, "License update not successful (no session)");
    return 0;
  }

  SendSessionMessage(sessions_.back()->session.data(), sessions_.back()->session.size(),
    sessions_.back()->challenge.GetData(), sessions_.back()->challenge.GetDataSize());

  if (sessions_.back()->keys.empty())
  {
    Log(SSD_HOST::LL_ERROR, "License update not successful (no keys)");
    CloseSession((size_t)sessions_.back());
    return 0;
  }

  sessions_.back()->pssh.SetData(pssh.GetData(), pssh.GetDataSize());

  Log(SSD_HOST::LL_DEBUG, "License update successful");
  return (size_t)sessions_.back();
}

void WV_CencSingleSampleDecrypter::CloseSession(size_t sessionhandle)
{
  for (std::vector<WVSession*>::iterator b(sessions_.begin()), e(sessions_.end());b!=e;++b)
    if ((size_t)*b == sessionhandle)
    {
      wv_adapter->CloseSession(++promise_id_, (*b)->session.data(), (*b)->session.size());
      delete *b;
      sessions_.erase(b);
      break;
    }
}

bool WV_CencSingleSampleDecrypter::SendSessionMessage(const char* session, uint32_t session_size, const uint8_t *message, uint32_t message_size)
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
  fwrite(message, 1, message_size, f);
  fclose(f);
#endif

  //Process placeholder in GET String
  std::string::size_type insPos(blocks[0].find("{SSM}"));
  if (insPos != std::string::npos)
  {
    if (insPos >= 0 && blocks[0][insPos - 1] == 'B')
    {
      std::string msgEncoded = b64_encode(message, message_size, true);
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
      std::string::size_type sidSearchPos(insPos);
      if (insPos >= 0)
      {
        if (blocks[2][insPos - 1] == 'B' || blocks[2][insPos - 1] == 'b')
        {
          std::string msgEncoded = b64_encode(message, message_size, blocks[2][insPos - 1] == 'B');
          blocks[2].replace(insPos - 1, 6, msgEncoded);
          sidSearchPos += msgEncoded.size();
        }
        else
        {
          blocks[2].replace(insPos - 1, 6, reinterpret_cast<const char*>(message), message_size);
          sidSearchPos += message_size;
        }
      }
      else
      {
        Log(SSD_HOST::LL_ERROR, "Unsupported License request template (body)");
        goto SSMFAIL;
      }

      insPos = blocks[2].find("{SID}", sidSearchPos);
      if (insPos != std::string::npos)
      {
        if (insPos >= 0)
        {
          if (blocks[2][insPos - 1] == 'B' || blocks[2][insPos - 1] == 'b')
          {
            std::string msgEncoded = b64_encode(reinterpret_cast<const unsigned char*>(session),session_size, blocks[2][insPos - 1] == 'B');
            blocks[2].replace(insPos - 1, 6, msgEncoded);
          }
          else
            blocks[2].replace(insPos - 1, 6, session, session_size);
        }
        else
        {
          Log(SSD_HOST::LL_ERROR, "Unsupported License request template (body)");
          goto SSMFAIL;
        }
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

      std::vector<std::string> jsonVals = split(blocks[3].c_str()+2, ';');

      // Find HDCP limit
      if (jsonVals.size() > 1)
      {
        for (; i < numTokens; ++i)
          if (tokens[i].type == JSMN_STRING && tokens[i].size == 1 && jsonVals[1].size() == tokens[i].end - tokens[i].start
            && strncmp(response.c_str() + tokens[i].start, jsonVals[1].c_str(), tokens[i].end - tokens[i].start) == 0)
            break;
        if (i < numTokens)
          decrypter_caps_.hdcpLimit = atoi((response.c_str() + tokens[i + 1].start));
      }
      // Find license key
      if (jsonVals.size() > 1)
      {
        for (i = 0; i < numTokens; ++i)
          if (tokens[i].type == JSMN_STRING && tokens[i].size == 1 && jsonVals[0].size() == tokens[i].end - tokens[i].start
            && strncmp(response.c_str() + tokens[i].start, jsonVals[0].c_str(), tokens[i].end - tokens[i].start) == 0)
            break;
      }
      else
        i = numTokens;

      if (i < numTokens)
      {
        if (blocks[3][1] == 'B')
        {
          unsigned int decoded_size = 2048;
          uint8_t decoded[2048];
          b64_decode(response.c_str() + tokens[i + 1].start, tokens[i + 1].end - tokens[i + 1].start, decoded, decoded_size);
          wv_adapter->UpdateSession(++promise_id_, session, session_size, reinterpret_cast<const uint8_t*>(decoded), decoded_size);
        }
        else
          wv_adapter->UpdateSession(++promise_id_, session, session_size,
            reinterpret_cast<const uint8_t*>(response.c_str() + tokens[i + 1].start), tokens[i + 1].end - tokens[i + 1].start);
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
  } else //its binary - simply push the returned data as update
    wv_adapter->UpdateSession(++promise_id_, session, session_size, 
      reinterpret_cast<const uint8_t*>(response.data()), response.size());

  return true;
SSMFAIL:
  if (file)
    host->CloseFile(file);
  return false;
}

/*----------------------------------------------------------------------
|   WV_CencSingleSampleDecrypter::SetKeyId
+---------------------------------------------------------------------*/

AP4_Result WV_CencSingleSampleDecrypter::SetFrameInfo(const AP4_UI16 key_size, const AP4_UI08 *key, const AP4_UI08 nal_length_size, AP4_DataBuffer &annexb_sps_pps)
{
  key_size_ = key_size;
  key_ = key;
  nal_length_size_ = nal_length_size;
  annexb_sps_pps_.SetData(annexb_sps_pps.GetData(), annexb_sps_pps.GetDataSize());

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
  if (!wv_adapter)
  {
    data_out.SetData(data_in.GetData(), data_in.GetDataSize());
    return AP4_SUCCESS;
  }

  if(decrypter_caps_.flags & SSD_DECRYPTER::SSD_CAPS::SSD_SECURE_PATH) //we can not decrypt only
  {
    if (nal_length_size_ > 4)
    {
      Log(SSD_HOST::LL_ERROR, "Nalu length size > 4 not supported");
      return AP4_ERROR_NOT_SUPPORTED;
    }

    AP4_UI16 dummyClear(0);
    AP4_UI32 dummyCipher(data_in.GetDataSize());

    if (iv)
    {
      if (!subsample_count)
      {
        subsample_count = 1;
        bytes_of_cleartext_data = &dummyClear;
        bytes_of_encrypted_data = &dummyCipher;
      }

      data_out.SetData(reinterpret_cast<const AP4_Byte*>(&subsample_count), sizeof(subsample_count));
      data_out.AppendData(reinterpret_cast<const AP4_Byte*>(bytes_of_cleartext_data), subsample_count * sizeof(AP4_UI16));
      data_out.AppendData(reinterpret_cast<const AP4_Byte*>(bytes_of_encrypted_data), subsample_count * sizeof(AP4_UI32));
      data_out.AppendData(reinterpret_cast<const AP4_Byte*>(iv), 16);
      data_out.AppendData(reinterpret_cast<const AP4_Byte*>(key_), 16);
    }
    else
    {
      data_out.SetDataSize(0);
      bytes_of_cleartext_data = &dummyClear;
      bytes_of_encrypted_data = &dummyCipher;
    }

    if (nal_length_size_ && (!iv || bytes_of_cleartext_data[0] > 0))
    {
      //Note that we assume that there is enough data in data_out to hold everything without reallocating.

      //check NAL / subsample
      const AP4_Byte *packet_in(data_in.GetData()), *packet_in_e(data_in.GetData() + data_in.GetDataSize());
      AP4_Byte *packet_out(data_out.UseData() + data_out.GetDataSize());
      AP4_UI16 *clrb_out(iv ? reinterpret_cast<AP4_UI16*>(data_out.UseData() + sizeof(subsample_count)):nullptr);
      unsigned int nalunitcount(0), nalunitsum(0), configSize(0);

      while (packet_in < packet_in_e)
      {
        uint32_t nalsize(0);
        for (unsigned int i(0); i < nal_length_size_; ++i) { nalsize = (nalsize << 8) + *packet_in++; };

        //look if we have to inject sps / pps
        if (annexb_sps_pps_.GetDataSize() && (*packet_in & 0x1F) != 9 /*AVC_NAL_AUD*/)
        {
          memcpy(packet_out, annexb_sps_pps_.GetData(), annexb_sps_pps_.GetDataSize());
          packet_out += annexb_sps_pps_.GetDataSize();
          if(clrb_out) *clrb_out += annexb_sps_pps_.GetDataSize();
          configSize = annexb_sps_pps_.GetDataSize();
          annexb_sps_pps_.SetDataSize(0);
        }

        //Anex-B Start pos
        packet_out[0] = packet_out[1] = packet_out[2] = 0; packet_out[3] = 1;
        packet_out += 4;
        memcpy(packet_out, packet_in, nalsize);
        packet_in += nalsize;
        packet_out += nalsize;
        if (clrb_out) *clrb_out += (4 - nal_length_size_);
        ++nalunitcount;

        if (nalsize + nal_length_size_ + nalunitsum > *bytes_of_cleartext_data + *bytes_of_encrypted_data)
        {
          Log(SSD_HOST::LL_ERROR, "NAL Unit exceeds subsample definition (nls: %d) %d -> %d ", nal_length_size_, nalsize + nal_length_size_ + nalunitsum, *bytes_of_cleartext_data + *bytes_of_encrypted_data);
          return AP4_ERROR_NOT_SUPPORTED;
        }
        else if (!iv)
        {
          nalunitsum = 0;
        }
        else if (nalsize + nal_length_size_ + nalunitsum == *bytes_of_cleartext_data + *bytes_of_encrypted_data)
        {
          ++bytes_of_cleartext_data;
          ++bytes_of_encrypted_data;
          ++clrb_out;
          --subsample_count;
          nalunitsum = 0;
        }
        else
          nalunitsum += nalsize + nal_length_size_;
      }
      if (packet_in != packet_in_e || subsample_count)
      {
        Log(SSD_HOST::LL_ERROR, "NAL Unit definition incomplete (nls: %d) %d -> %u ", nal_length_size_, (int)(packet_in_e - packet_in), subsample_count);
        return AP4_ERROR_NOT_SUPPORTED;
      }
      data_out.SetDataSize(data_out.GetDataSize() + data_in.GetDataSize() + configSize + (4 - nal_length_size_) * nalunitcount);
    }
    else
      data_out.AppendData(data_in.GetData(), data_in.GetDataSize());
    return AP4_SUCCESS;
  }

  if (!key_size_)
    return AP4_ERROR_INVALID_PARAMETERS;

  // the output has the same size as the input
  data_out.SetDataSize(data_in.GetDataSize());

  // check input parameters
  if (iv == NULL) return AP4_ERROR_INVALID_PARAMETERS;
  if (subsample_count) {
    if (bytes_of_cleartext_data == NULL || bytes_of_encrypted_data == NULL) {
      return AP4_ERROR_INVALID_PARAMETERS;
    }
  }

  // transform ap4 format into cmd format
  cdm::InputBuffer cdm_in;
  if (subsample_count > max_subsample_count_)
  {
    subsample_buffer_ = (cdm::SubsampleEntry*)realloc(subsample_buffer_, subsample_count*sizeof(cdm::SubsampleEntry));
    max_subsample_count_ = subsample_count;
  }

  if (use_single_decrypt_)
  {
    decrypt_in_.Reserve(data_in.GetDataSize());
    decrypt_in_.SetDataSize(0);
    size_t absPos = 0;

    for (unsigned int i(0); i < subsample_count; ++i)
    {
      absPos += bytes_of_cleartext_data[i];
      decrypt_in_.AppendData(data_in.GetData() + absPos, bytes_of_encrypted_data[i]);
      absPos += bytes_of_encrypted_data[i];
    }
    decrypt_out_.SetDataSize(decrypt_in_.GetDataSize());
    subsample_buffer_[0].clear_bytes = 0;
    subsample_buffer_[0].cipher_bytes = decrypt_in_.GetDataSize();
    cdm_in.data = decrypt_in_.GetData();
    cdm_in.data_size = decrypt_in_.GetDataSize();
    cdm_in.num_subsamples = 1;
  }
  else
  {
    unsigned int i(0);
    for (cdm::SubsampleEntry *b(subsample_buffer_), *e(subsample_buffer_ + subsample_count); b != e; ++b, ++i)
    {
      b->clear_bytes = bytes_of_cleartext_data[i];
      b->cipher_bytes = bytes_of_encrypted_data[i];
    }
    cdm_in.data = data_in.GetData();
    cdm_in.data_size = data_in.GetDataSize();
    cdm_in.num_subsamples = subsample_count;
  }
  cdm_in.iv = iv;
  cdm_in.iv_size = 16; //Always 16, see AP4_CencSingleSampleDecrypter declaration.
  cdm_in.key_id = key_;
  cdm_in.key_id_size = key_size_;
  cdm_in.subsamples = subsample_buffer_;

  CdmBuffer buf(use_single_decrypt_ ? &decrypt_out_ : &data_out);
  CdmDecryptedBlock cdm_out;
  cdm_out.SetDecryptedBuffer(&buf);

  cdm::Status ret = wv_adapter->Decrypt(cdm_in, &cdm_out);

  if (ret == cdm::Status::kSuccess && use_single_decrypt_)
  {
    size_t absPos = 0, cipherPos = 0;
    for (unsigned int i(0); i < subsample_count; ++i)
    {
      memcpy(data_out.UseData() + absPos, data_in.GetData() + absPos, bytes_of_cleartext_data[i]);
      absPos += bytes_of_cleartext_data[i];
      memcpy(data_out.UseData() + absPos, decrypt_out_.GetData() + cipherPos, bytes_of_encrypted_data[i]);
      absPos += bytes_of_encrypted_data[i], cipherPos += bytes_of_encrypted_data[i];
    }
  }

  return (ret == cdm::Status::kSuccess) ? AP4_SUCCESS : AP4_ERROR_INVALID_PARAMETERS;
}

bool WV_CencSingleSampleDecrypter::OpenVideoDecoder(const SSD_VIDEOINITDATA *initData)
{
  cdm::VideoDecoderConfig vconfig;
  vconfig.codec = static_cast<cdm::VideoDecoderConfig::VideoCodec>(initData->codec);
  vconfig.coded_size.width = initData->width;
  vconfig.coded_size.height = initData->height;
  vconfig.extra_data = const_cast<uint8_t*>(initData->extraData);
  vconfig.extra_data_size = initData->extraDataSize;
  vconfig.format = static_cast<cdm::VideoFormat> (initData->videoFormats[0]);
  vconfig.profile = static_cast<cdm::VideoDecoderConfig::VideoCodecProfile>(initData->codecProfile);

  cdm::Status ret = wv_adapter->InitializeVideoDecoder(vconfig);
  videoFrames_.clear();

  Log(SSD_HOST::LL_DEBUG, "WVDecoder initialization returned status %i", ret);

  return ret == cdm::Status::kSuccess;
}

SSD_DECODE_RETVAL WV_CencSingleSampleDecrypter::DecodeVideo(void* hostInstance, SSD_SAMPLE *sample, SSD_PICTURE *picture)
{
  if (sample)
  {
    // if we have an picture waiting, or not yet get the dest buffer, do nothing
    if (videoFrames_.size() == 4)
      return VC_ERROR;

    cdm::InputBuffer cdm_in;

    if (sample->numSubSamples) {
      if (sample->clearBytes == NULL || sample->cipherBytes == NULL) {
        return VC_ERROR;
      }
    }

    // transform ap4 format into cmd format
    if (sample->numSubSamples > max_subsample_count_)
    {
      subsample_buffer_ = (cdm::SubsampleEntry*)realloc(subsample_buffer_, sample->numSubSamples * sizeof(cdm::SubsampleEntry));
      max_subsample_count_ = sample->numSubSamples;
    }
    cdm_in.num_subsamples = sample->numSubSamples;
    cdm_in.subsamples = subsample_buffer_;

    const uint16_t *clearBytes(sample->clearBytes);
    const uint32_t *cipherBytes(sample->cipherBytes);

    for (cdm::SubsampleEntry *b(subsample_buffer_), *e(subsample_buffer_ + sample->numSubSamples); b != e; ++b, ++clearBytes, ++cipherBytes)
    {
      b->clear_bytes = *clearBytes;
      b->cipher_bytes = *cipherBytes;
    }
    cdm_in.data = sample->data;
    cdm_in.data_size = sample->dataSize;
    cdm_in.iv = sample->iv;
    cdm_in.iv_size = sample->iv ? 16 : 0;
    cdm_in.timestamp = sample->pts;

    uint8_t unencryptedKID = 0x31;
    cdm_in.key_id = sample->kid ? sample->kid : &unencryptedKID;
    cdm_in.key_id_size = sample->kid ? 16 : 1;

    //DecryptAndDecode calls Alloc wich cals kodi VideoCodec. Set instance handle.
    host_instance_ = hostInstance;
    CdmVideoFrame frame;
    cdm::Status ret = wv_adapter->DecryptAndDecodeFrame(cdm_in, &frame);
    host_instance_ = nullptr;

    if (ret == cdm::Status::kSuccess)
    {
      std::list<CdmVideoFrame>::iterator f(videoFrames_.begin());
      while (f != videoFrames_.end() && f->Timestamp() < frame.Timestamp())++f;
      videoFrames_.insert(f, frame);
    }

    if (ret == cdm::Status::kSuccess || (cdm_in.data && ret == cdm::Status::kNeedMoreData))
      return VC_NONE;
    else
      return VC_ERROR;
  }
  else if (picture)
  {
    if (videoFrames_.size() == 4 || (videoFrames_.size() && (picture->flags & SSD_PICTURE::FLAG_DRAIN)))
    {
      CdmVideoFrame &videoFrame_(videoFrames_.front());

      picture->width = videoFrame_.Size().width;
      picture->height = videoFrame_.Size().height;
      picture->pts = videoFrame_.Timestamp();
      picture->decodedData = videoFrame_.FrameBuffer()->Data();
      picture->decodedDataSize = videoFrame_.FrameBuffer()->Size();

      for (unsigned int i(0); i < cdm::VideoFrame::kMaxPlanes; ++i)
      {
        picture->planeOffsets[i] = videoFrame_.PlaneOffset(static_cast<cdm::VideoFrame::VideoPlane>(i));
        picture->stride[i] = videoFrame_.Stride(static_cast<cdm::VideoFrame::VideoPlane>(i));
      }
      picture->videoFormat = static_cast<SSD::SSD_VIDEOFORMAT>(videoFrame_.Format());
      videoFrame_.SetFrameBuffer(nullptr); //marker for "No Picture"

      delete (CdmFixedBuffer*)(videoFrame_.FrameBuffer());
      videoFrames_.pop_front();

      return VC_PICTURE;
    }
    else if ((picture->flags & SSD_PICTURE::FLAG_DRAIN))
    {
      static SSD_SAMPLE drainSample = { nullptr,0,0,0,0,nullptr,nullptr,nullptr,nullptr };
      if (DecodeVideo(hostInstance, &drainSample, nullptr) == VC_ERROR)
        return VC_EOF;
      else
        return VC_NONE;
    }
    else
      return VC_BUFFER;
  }
  else
    return VC_ERROR;
}

void WV_CencSingleSampleDecrypter::ResetVideo()
{
  wv_adapter->ResetDecoder(cdm::kStreamTypeVideo);
}

/*********************************************************************************************/

class WVDecrypter: public SSD_DECRYPTER
{
public:
  WVDecrypter() :decrypter_(nullptr) {};
  ~WVDecrypter()
  {
    delete decrypter_;
    decrypter_ = nullptr;
  };

  // Return supported URN if type matches to capabikitues, otherwise null
  virtual const char *Supported(const char* licenseType, const char *licenseKey) override
  {
    licenseKey_ = licenseKey;
    if (strcmp(licenseType, "com.widevine.alpha") == 0)
      return "urn:uuid:EDEF8BA9-79D6-4ACE-A3C8-27DCD51D21ED";
    return 0;
  };

  virtual AP4_CencSingleSampleDecrypter *CreateSingleSampleDecrypter(AP4_DataBuffer &serverCertificate) override
  {
    decrypter_ = new WV_CencSingleSampleDecrypter(licenseKey_, serverCertificate);
    if (!decrypter_->initialized())
    {
      delete decrypter_;
      decrypter_ = 0;
    }
    return decrypter_;
  }

  virtual size_t CreateSession(AP4_DataBuffer &streamCodec) override
  {
    if (!decrypter_)
      return 0;

    return decrypter_->CreateSession(streamCodec);
  }

  virtual void CloseSession(size_t sessionHandle) override
  {
    if (!decrypter_)
      return decrypter_->CloseSession(sessionHandle);
  }

  virtual const SSD_DECRYPTER::SSD_CAPS &GetCapabilities(size_t sessionHandle, const uint8_t *keyid) override
  {
    if (!decrypter_)
    {
      static const SSD_DECRYPTER::SSD_CAPS dummy_caps = { 0,0,0 };
      return dummy_caps;
    }

    return decrypter_->GetCapabilities(sessionHandle, keyid);
  }

  virtual const char *GetSessionId(size_t sessionHandle) override
  {
    if (!decrypter_)
      return nullptr;

    return decrypter_->GetSessionId(sessionHandle);
  }

  virtual bool OpenVideoDecoder(const SSD_VIDEOINITDATA *initData)
  {
    if (!decrypter_ || !initData)
      return false;

    return decrypter_->OpenVideoDecoder(initData);
  }

  virtual SSD_DECODE_RETVAL DecodeVideo(void* hostInstance, SSD_SAMPLE *sample, SSD_PICTURE *picture) override
  {
    if (!decrypter_)
      return VC_ERROR;

    return decrypter_->DecodeVideo(hostInstance, sample, picture);
  }

  virtual void ResetVideo() override
  {
    if (decrypter_)
      decrypter_->ResetVideo();
  }

private:
  std::string licenseKey_;
  WV_CencSingleSampleDecrypter *decrypter_;
};

extern "C" {

#ifdef _WIN32
#define MODULE_API __declspec(dllexport)
#else
#define MODULE_API
#endif

  SSD_DECRYPTER MODULE_API *CreateDecryptorInstance(class SSD_HOST *h, uint32_t host_version)
  {
    if (host_version != SSD_HOST::version)
      return 0;
    host = h;
    return new WVDecrypter();
  };

  void MODULE_API DeleteDecryptorInstance(SSD_DECRYPTER *d)
  {
    delete static_cast<WVDecrypter*>(d);
  }
};
