//
//  PGPMessageImpl.h
//  cryptopg
//
//  Created by Anton Sarychev on 22.4.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef __cryptopg__PGPMessageImpl__
#define __cryptopg__PGPMessageImpl__

#include <iostream>
#include <vector>

#include "cryptopglib/PGPMessage.h"
#include "PGPData/PGPPacket.h"


class PGPMessageImpl : public PGPMessage
{
public:
    PGPMessageImpl();
    ~PGPMessageImpl();
    
    PGPMessageType GetMessageType();
    std::string GetPlainText();
    std::string GetBase64Data();
    std::string GetCRC();
    
    CharDataVector GetRawData();
    
    void SetMessageType(const PGPMessageType message_type);
    void SetPlainText(const std::string& plain_text);
    void SetBase64Data(const std::string& data);
    void SetCRC(const std::string& crc);
    
    void AddArmorHeaderValue(const std::string& key, const std::string& value);
    void AddPlainText(const std::string& text);
    void AddData(const std::string& data);
        
    void SetPackets(PGPPacketsArray& packets);
    const PGPPacketsArray& GetPackets();
    
    void AddPacket(std::shared_ptr<PGPPacket> packet);

private:
     
    PGPMessageType message_type_;
    std::string plain_text_; // used for plain text
    std::string data_;
    std::string crc_;
    ArmorHeadersMap armor_header_map_;
    
    KeyIDData key_id_;
    PGPPacketsArray packets_;
};

typedef std::shared_ptr<PGPMessageImpl> PGPMessagePtr;

#endif /* defined(__cryptopg__PGPMessageImpl__) */
