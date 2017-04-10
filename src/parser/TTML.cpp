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

#include "TTML.h"
#include "expat.h"
#include <cstring>

static void XMLCALL
start(void *data, const char *el, const char **attr)
{
  TTML2SRT *ttml(reinterpret_cast<TTML2SRT*>(data));
  if (ttml->m_node & TTML2SRT::NODE_TT)
  {
    if (ttml->m_node & TTML2SRT::NODE_BODY)
    {
      if (ttml->m_node & TTML2SRT::NODE_DIV)
      {
        if (ttml->m_node & TTML2SRT::NODE_P)
        {
          if (strcmp(el, "span") == 0)
            {
              ttml->m_strXMLText += "<i>";
              ttml->m_node |= TTML2SRT::NODE_SPAN;
            }
        }
        else if (strcmp(el, "p") == 0)
        {
          ttml->m_strXMLText.clear();
          const char *b(0), *e(0), *id("");

          for (; *attr;)
          {
            if (strcmp((const char*)*attr, "begin") == 0)
              b = (const char*)*(attr + 1);
            else if (strcmp((const char*)*attr, "end") == 0)
              e = (const char*)*(attr + 1);
            else if (strcmp((const char*)*attr, "xml:id") == 0)
              id = (const char*)*(attr + 1);
            attr += 2;
          }
          if (ttml->StackSubTitle(b, e, id))
            ttml->m_node |= TTML2SRT::NODE_P;
        }
      }
      else if (strcmp(el, "div") == 0)
        ttml->m_node |= TTML2SRT::NODE_DIV;
    }
    else if (strcmp(el, "body") == 0)
      ttml->m_node |= TTML2SRT::NODE_BODY;
  }
  else if (strcmp(el, "tt") == 0)
  {
    ttml->m_node |= TTML2SRT::NODE_TT;
    for (; *attr;)
    {
      if (strcmp((const char*)*attr, "ttp:tickRate") == 0)
        ttml->m_tickRate = atoll((const char*)*(attr + 1));
      attr += 2;
    }
  }
}

static void XMLCALL
text(void *data, const char *s, int len)
{
  TTML2SRT *ttml(reinterpret_cast<TTML2SRT*>(data));
  
  if (ttml->m_node & TTML2SRT::NODE_P)
    ttml->m_strXMLText += std::string(s, len);
}

static void XMLCALL
end(void *data, const char *el)
{
  TTML2SRT *ttml(reinterpret_cast<TTML2SRT*>(data));

  if (ttml->m_node & TTML2SRT::NODE_TT)
  {
    if (ttml->m_node & TTML2SRT::NODE_BODY)
    {
      if (ttml->m_node & TTML2SRT::NODE_DIV)
      {
        if (ttml->m_node & TTML2SRT::NODE_P)
        {
          if (strcmp(el, "span") == 0)
          {
            ttml->m_node &= ~TTML2SRT::NODE_SPAN;
            ttml->m_strXMLText += "</i>";
          }
          else if (strcmp(el, "p") == 0)
          {
            ttml->m_node &= ~TTML2SRT::NODE_P;
            ttml->StackText();
          }
          else if (strcmp(el, "br") == 0)
            ttml->m_strXMLText += "\n";
        }
        else if (strcmp(el, "div") == 0)
          ttml->m_node &= ~TTML2SRT::NODE_DIV;
      }
      else if (strcmp(el, "body") == 0)
        ttml->m_node &= ~TTML2SRT::NODE_BODY;
    }
    else if (strcmp(el, "tt") == 0)
      ttml->m_node &= ~TTML2SRT::NODE_TT;
  }
}

bool TTML2SRT::Parse(const void *buffer, size_t buffer_size, uint64_t timescale)
{
  bool done(true);
  m_node = 0;
  m_pos =  0;
  m_strXMLText.clear();
  m_subTitles.clear();
  m_timescale = timescale;

  XML_Parser parser = XML_ParserCreate(NULL);
  if (!parser)
    return false;
  XML_SetUserData(parser, (void*)this);
  XML_SetElementHandler(parser, start, end);
  XML_SetCharacterDataHandler(parser, text);

  XML_Status retval = XML_Parse(parser, (const char*)buffer, buffer_size, done);
  XML_ParserFree(parser);

  if (retval == XML_STATUS_ERROR)
    return false;
  
  while (m_pos < m_subTitles.size() && m_subTitles[m_pos].id != m_lastId)
    ++m_pos;
  
  if (m_pos == m_subTitles.size())
    m_pos = 0;
  else
    ++m_pos;

  m_lastId.clear();
  
  return true;
}

bool TTML2SRT::Prepare(uint64_t &pts, uint32_t &duration)
{
  if (m_pos >= m_subTitles.size())
    return false;
  
  SUBTITLE &sub(m_subTitles[m_pos++]);
  pts = sub.start;
  duration = static_cast<uint32_t>(sub.end - sub.start);

  m_SRT.clear();
  for (size_t i(0); i < sub.text.size(); ++i)
  {
    if (i) m_SRT += "\r\n";
    m_SRT += sub.text[i];
  }
  m_lastId = sub.id;
  return true;
}

bool TTML2SRT::TimeSeek(uint64_t seekPos)
{
  for (m_pos = 0; m_pos < m_subTitles.size() && m_subTitles[m_pos].end < seekPos; ++m_pos);
  return true;
}

uint64_t TTML2SRT::GetTime(const char *tmchar)
{
  uint64_t ret;
  if (tmchar[strlen(tmchar) - 1] == 't')
  {
    ret = atoll(tmchar) * m_timescale;
    if (m_tickRate)
      ret /= m_tickRate;
  }
  else
  {
    unsigned int th, tm, ts, tms;
    sscanf(tmchar, "%u:%u:%u.%u", &th, &tm, &ts, &tms);
    ret = th * 3600 + tm * 60 + ts;
    ret = ret * 1000 + tms * 10;
    ret = (ret * m_timescale) / 1000;
  }
  return ret;
}

bool TTML2SRT::StackSubTitle(const char *s, const char *e, const char *id)
{
  if (!s || !e || !*s || !*e)
    return false;
  
  m_subTitles.push_back(SUBTITLE());
  SUBTITLE &sub(m_subTitles.back());
  
  sub.start = GetTime(s);
  sub.end = GetTime(e);

  sub.id = id;

  return true;
}

void TTML2SRT::StackText()
{
  m_subTitles.back().text.push_back(m_strXMLText);
}
