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

#include <string>
#include <cstring>
#include <time.h>
#include <float.h>

#include "NxMslTree.h"
#include "../oscompat.h"
#include "../helpers.h"
#include <jsoncpp/json/json.h>


using namespace adaptive;

NxMslTree::NxMslTree()
{
    this->jsonString = "";
}



bool NxMslTree::parseManifest() {
    Json::Value manifest;
    Json::Value responseHeader;
    Json::Reader reader;
    reader.parse(jsonString, manifest);


    Json::Value viewables = manifest["result"]["viewables"][(int)0];


    this->overallSeconds_ = viewables["runtime"].asInt();//3573000;
    this->stream_start_ = time(0);
    this->base_time_ = ~0ULL;


    this->playbackContextId = viewables["playbackContextId"].asString();
    this->drmContextId = viewables["drmContextId"].asString();

    //Add pssh
    this->pssh_.first = "urn:uuid:EDEF8BA9-79D6-4ACE-A3C8-27DCD51D21ED";
    this->pssh_.second = viewables["psshb64"][(int)0].asString();

    this->adp_pssh_.first = "urn:uuid:EDEF8BA9-79D6-4ACE-A3C8-27DCD51D21ED";
    this->adp_pssh_.second =  viewables["psshb64"][(int)0].asString();

    //this->defaultKID_ = viewables["keyId"].asString();


    this->encryptionState_ |= AdaptiveTree::ENCRYTIONSTATE_SUPPORTED;


    Json::Value video_tracks;
    video_tracks = viewables["videoTracks"];

    Json::Value video_track;
    video_track = video_tracks[(int)0];


    Json::Value audio_tracks;
    audio_tracks = viewables["audioTracks"];

    Json::Value audio_track;
    audio_track = audio_tracks[(int)0];


    //Add the one and only period
    this->current_period_ = new NxMslTree::Period();
    this->periods_.push_back(current_period_);


    //Create one Adptionset
    this->current_adaptationset_ = new NxMslTree::AdaptationSet();
    //Add the Adaptionset to the period
    this->current_period_->adaptationSets_.push_back(this->current_adaptationset_);


    //One Downloadable is one representation
    for (size_t i = 0; i != video_track["downloadables"].size(); i++) {
        Json::Value downloadable = video_track["downloadables"][(int)i];
        //URLs have "random" ids
        //TODO there must be a better solution for this
        std::string url;
        for( Json::ValueIterator itr =  downloadable["urls"].begin() ; itr !=  downloadable["urls"].end() ; itr++ ) {
            std::string temp = downloadable["urls"][itr.key().asString()].asString();
            url = temp;
            break;
        }

        this->current_representation_ = new NxMslTree::Representation();
        this->current_representation_->channelCount_ = 1;
        this->current_representation_->codecs_ = this->current_adaptationset_->codecs_;
        this->current_representation_->url_ = url;
        this->current_representation_->duration_ = 1000;
        this->current_representation_->width_ = downloadable["width"].asInt();
        this->current_representation_->height_ = downloadable["height"].asInt();
        //this->current_representation_->fpsRate_ = downloadable["bitrate"].asInt();
        this->current_representation_->codecs_ = "h264";
        //this->current_representation_->flags_ |= NxMslTree::Representation::TEMPLATE;

        this->current_adaptationset_->startPTS_ = 0;
        this->current_adaptationset_->repesentations_.push_back(this->current_representation_);

        this->current_representation_->flags_ |= NxMslTree::Representation::SEGMENTBASE;
        this->current_representation_->indexRangeMin_ = 0;
        this->current_representation_->indexRangeMax_ = 1024 * 200;


    }
    this->current_adaptationset_->segment_durations_.data.reserve(100);
    this->current_adaptationset_->base_url_ = this->current_representation_->url_;
    this->current_adaptationset_->encrypted = true;
    this->current_adaptationset_->timescale_ = 1000;
    this->adpChannelCount_ = 2;
    this->adpwidth_ = this->current_representation_->width_;
    this->adpheight_ =this->current_representation_->height_;
    this->adpfpsRate_ =this->current_representation_->fpsRate_;
    this->current_adaptationset_->type_ = NxMslTree::VIDEO;





    //Audio Adaptionset
    //Create one Adptionset
    this->current_adaptationset_ = new NxMslTree::AdaptationSet();
    //Add the Adaptionset to the period
    //this->current_period_->adaptationSets_.push_back(this->current_adaptationset_);


    //One Downloadable is one representation
    for (size_t i = 0; i != audio_track["downloadables"].size(); i++) {
        Json::Value downloadable = audio_track["downloadables"][(int)i];


        //URLs have "random" ids
        //TODO there must be a better solution for this
        std::string url;
        for( Json::ValueIterator itr =  downloadable["urls"].begin() ; itr !=  downloadable["urls"].end() ; itr++ ) {
            std::string temp = downloadable["urls"][itr.key().asString()].asString();
            url = temp;
            break;
        }


        this->current_representation_ = new NxMslTree::Representation();
        this->current_representation_->channelCount_ = 2;
        this->current_representation_->url_ = url;
        this->current_representation_->codecs_ = "aac";

        this->current_adaptationset_->startPTS_ = 0;
        this->current_adaptationset_->repesentations_.push_back(this->current_representation_);

        this->current_representation_->flags_ |= NxMslTree::Representation::SEGMENTBASE;
        this->current_representation_->indexRangeMin_ = 0;
        this->current_representation_->indexRangeMax_ = 1024 * 200;




    }
    this->current_adaptationset_->segment_durations_.data.reserve(100);
    //this->current_adaptationset_->base_url_ = this->current_representation_->url_;
    this->current_adaptationset_->encrypted = false;
    this->adpChannelCount_ = 2;
    this->current_adaptationset_->type_ = NxMslTree::AUDIO;







}


/*----------------------------------------------------------------------
|   NxMslTree
+---------------------------------------------------------------------*/

bool NxMslTree::open(const char *url)
{
  bool ret = download(url);
    parseManifest();
  return ret;
}

bool NxMslTree::write_data(void *buffer, size_t buffer_size)
{
  std::string s((const char*)buffer, buffer_size);
  jsonString += s;
//  XML_Status retval = XML_Parse(parser_, (const char*)buffer, buffer_size, done);
  return true;
}
