//
//  PGPMessageParser.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 16.3.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "pgp_message_parser.h"

#include <vector>
#include <map>

#include "cryptopglib/pgp_errors.h"
#include "../Utils/base64.h"
#include "../Utils/crc24.h"

/// TODO:
/// 1. Parse end line
/// 2. Add Parse errors
/// 3.


namespace
{
    const static std::string base64symbols = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    const char END_LINE[] = "\n";

    const char BEGIN[] = "-----BEGIN";
    //const char PGP[] = "PGP";
    const char PRIVATE[] = "PRIVATE";
    const char PUBLIC[] = "PUBLIC";
    //const char KEY[] = "KEY";
    //const char BLOCK[] = "BLOCK";
    //const char PART[] = "PART";
    const char SIGNED[] = "SIGNED";
    const char MESSAGE[] = "MESSAGE";
    //const char SIGNATURE[] = "SIGNATURE";
    //const char END[] = "-----END";
    

    
    
    size_t GetNextLine(const std::string& source, std::string& destination, const size_t last_position)
    {
        size_t end_line_pos = source.find(END_LINE, last_position);
        if (end_line_pos == std::string::npos)
        {
            return end_line_pos;
        }
        
        destination.assign(source.begin() + last_position, source.begin() + end_line_pos);
        
        return end_line_pos;
    }
    
    bool IsDataLine(const std::string& source)
    {
        if (source.empty())
        {
            return false;
        }
        
        for (size_t i = 0; i < source.size(); ++i)
        {
            size_t t = base64symbols.find(source[i]);
            if (t == std::string::npos)
            {
                return false;
            }
        }
        
        return true;
    }
}


PGPMessageParser::PGPMessageParser()
{
    
}

PGPMessageParser::~PGPMessageParser()
{
    
    
}

PGPMessagePtr PGPMessageParser::ParseMessage(const std::string& source)
{
    state_ = PS_START_LINE;
    
    message_ = std::make_shared<PGPMessageImpl>();
    
    size_t current_position = 0;
    do
    {
        std::string string_line;
        current_position = GetNextLine(source, string_line, current_position);
        
        ParseLine(string_line);
        if (current_position != std::string::npos)
            current_position++;
    }
    while (current_position != std::string::npos);
    
    if (message_->GetRawData().empty())
    {
        return nullptr;
    }
    
    if (!CheckCRCSum())
    {
        //throw PGPError(MESSAGE_CRC_ERROR);
    }
    
    return message_;
}

void PGPMessageParser::ParseLine(const std::string& source)
{
    switch (state_)
    {
        case PS_START_LINE:
            if (ParseArmorHeaderLine(source))
            {
                state_ = PS_ARMOR;
            }
            
            break;
            
        case PS_ARMOR:
            if (!ParseArmorHeaders(source))
            {
                if ((message_->GetMessageType() == PGPMessageType::MT_SIGNED_MESSAGE)
                    && (message_->GetPlainText().empty()))
                {
                    state_ = PS_SIGNED_TEXT;
                }
                else
                {
                    if (IsDataLine(source))
                    {
                        ReadDataLine(source);
                    }
                    
                    state_ = PS_DATA;
                }
            }
            
            break;
            
        case PS_SIGNED_TEXT:
            if (!ReadSignedTextLine(source))
            {
                state_ = PS_ARMOR;
            }
            
            break;
            
        case PS_DATA:
            if (!ReadDataLine(source))
            {
                state_ = PS_END_LINE;
            }
            
            break;
            
        case PS_END_LINE:
            
            break;
            
        default:
            break;
    }
}

bool PGPMessageParser::ParseArmorHeaderLine(const std::string& source)
{
    size_t pos = source.find(BEGIN);
    if (pos == std::string::npos)
    {
        message_->SetMessageType(PGPMessageType::MT_SIMPLE_MESSAGE);
        return false;
    }
    
    pos += strlen(BEGIN) + 1;
    
    bool flag_end = false;
    std::string word;
    while (!flag_end)
    {
        if (source.length() <= pos)
        {
          break;
        }
        switch (source[pos])
        {
            case '\n':
                flag_end = true;
                break;
            case '\r':
                break;
            case ' ':
            case '/':
            case ',':
            case '-':
                if (!word.empty())
                    ParseHeaderWord(word);
                word = "";
                break;
            default:
                word.push_back(source[pos]);
                break;
        }
        pos++;
    }
    
    return true;
}

bool PGPMessageParser::ParseArmorHeaders(const std::string& source)
{
    size_t pos = source.find(':');
    if (pos != std::string::npos)
    {
        message_->AddArmorHeaderValue(std::string(source.begin(), source.begin() + pos), std::string(source.begin() + pos + 1, source.end()));
        return true;
    }
    
    return false;
}

bool PGPMessageParser::ReadSignedTextLine(const std::string& source)
{    
    size_t pos = source.find(BEGIN);
    
    if (pos == std::string::npos)
    {
        if (!message_->GetPlainText().empty())
        {
            message_->AddPlainText("\n");
        }
        
        message_->AddPlainText(source);
        
        std::string str(message_->GetPlainText());
        
        CharDataVector data(str.begin(), str.end());

        return true;
    }

    return false;
}

bool PGPMessageParser::ReadDataLine(const std::string& source)
{
    if (source[0] == '=')
    {
        std::string crc_string;
        if (source.back() == '\r')
        {
            crc_string.assign(std::string(source.begin() + 1, source.end() - 1));
        }
        else
        {
            crc_string.assign(std::string(source.begin() + 1, source.end()));
        }
        
        if (crc_string.size() == 6)
        {
            crc_string.assign(crc_string.begin() + 2, crc_string.end());
        }
        
        message_->SetCRC(crc_string);

        return false;
    }
    
    
    std::string data_string;
    if (source.back() == '\r')
    {
        data_string.assign(std::string(source.begin(), source.end() - 1));
    }
    else
    {
        data_string.assign(source);
    }
    
    size_t pos;
    while ((pos = data_string.find("=3D")) != std::string::npos)
    {
        data_string.erase(data_string.begin() + pos + 1, data_string.begin() + pos + 3);
    }
    
    message_->AddData(data_string);

    return true;
}

void PGPMessageParser::ParseHeaderWord(const std::string& word)
{
    std::map<std::string, PGPMessageType> words_map;
    words_map[SIGNED] = PGPMessageType::MT_SIGNED_MESSAGE;
    words_map[MESSAGE] = PGPMessageType::MT_CRYPTO_MESSAGE;
    words_map[PUBLIC] = PGPMessageType::MT_PUBLIC_KEY;
    words_map[PRIVATE] = PGPMessageType::MT_PRIVATE_KEY;
    
    auto iter = words_map.find(word);
    if (iter == words_map.end())
    {
        return;
    }
    if (iter->second == PGPMessageType::MT_CRYPTO_MESSAGE)
    {
        if (message_->GetMessageType() != PGPMessageType::MT_SIGNED_MESSAGE)
        {
            message_->SetMessageType(PGPMessageType::MT_CRYPTO_MESSAGE);
        }
    }
    else
    {
        message_->SetMessageType(words_map[word]);
    }
    
    //if (message_info_.message_type_ == MT_PART_MESSAGE)
    {
        // TODO: read numbers
    }
    
}

bool PGPMessageParser::CheckCRCSum()
{
    long crc_sum = Utils::CRC24(message_->GetRawData());
    
    CharDataVector crc_sum_vector;
    crc_sum_vector.push_back(crc_sum >> 16);
    crc_sum_vector.push_back(crc_sum >> 8);
    crc_sum_vector.push_back(crc_sum);
    
    std::string crc_result = Utils::Base64Encode(crc_sum_vector);
    
    return message_->GetCRC().compare(crc_result) == 0 ? true : false;
}

