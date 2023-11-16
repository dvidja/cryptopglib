//
//  base64.c
//  cryptopg
//
//  Created by Anton Sarychev on 2.3.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//
#include "base64.h"


//Lookup table for encoding
//If you want to use an alternate alphabet, change the characters here
namespace
{
    const char encodeLookup[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const char padCharacter = '=';
}

namespace Utils
{
    
    std::string Base64Encode(CharDataVector inputBuffer)
    {
        std::string encodedString;
        encodedString.reserve(((inputBuffer.size() / 3) + (inputBuffer.size() % 3 > 0)) * 4);
        
        long temp;
        auto cursor = inputBuffer.begin();
        
        for(size_t idx = 0; idx < inputBuffer.size() / 3; idx++)
        {
            temp  = (*cursor++) << 16;
            temp += (*cursor++) << 8;
            temp += (*cursor++);
            
            encodedString.append(1,encodeLookup[(temp & 0x00FC0000) >> 18]);
            encodedString.append(1,encodeLookup[(temp & 0x0003F000) >> 12]);
            encodedString.append(1,encodeLookup[(temp & 0x00000FC0) >> 6 ]);
            encodedString.append(1,encodeLookup[(temp & 0x0000003F)      ]);
        }
        
        switch(inputBuffer.size() % 3)
        {
            case 1:
                temp  = (*cursor++) << 16; //Convert to big endian
                encodedString.append(1,encodeLookup[(temp & 0x00FC0000) >> 18]);
                encodedString.append(1,encodeLookup[(temp & 0x0003F000) >> 12]);
                encodedString.append(2,padCharacter);
                break;
                
            case 2:
                temp  = (*cursor++) << 16; //Convert to big endian
                temp += (*cursor++) << 8;
                encodedString.append(1,encodeLookup[(temp & 0x00FC0000) >> 18]);
                encodedString.append(1,encodeLookup[(temp & 0x0003F000) >> 12]);
                encodedString.append(1,encodeLookup[(temp & 0x00000FC0) >> 6 ]);
                encodedString.append(1,padCharacter);
                break;
        }
        
        return encodedString;
    }

    CharDataVector Base64Decode(const std::string& input)
    {
        if (input.length() % 4)
        {
            return CharDataVector(0);
        }
        
        size_t padding = 0;
        if (input.length())
        {
            if (input[input.length()-1] == padCharacter)
                padding++;
            if (input[input.length()-2] == padCharacter)
                padding++;
        }
        
        //set up a vector to hold the result
        CharDataVector decodedBytes;
        decodedBytes.reserve(((input.length() / 4)*3) - padding);
        
        long temp = 0; //Holds decoded quanta
        std::string::const_iterator cursor = input.begin();
        
        while (cursor < input.end())
        {
            for (size_t quantumPosition = 0; quantumPosition < 4; quantumPosition++)
            {
                temp <<= 6;
                if       (*cursor >= 0x41 && *cursor <= 0x5A)
                    temp |= *cursor - 0x41;
                else if  (*cursor >= 0x61 && *cursor <= 0x7A)
                    temp |= *cursor - 0x47;
                else if  (*cursor >= 0x30 && *cursor <= 0x39)
                    temp |= *cursor + 0x04;
                else if  (*cursor == 0x2B)
                    temp |= 0x3E;
                else if  (*cursor == 0x2F)
                    temp |= 0x3F;
                else if  (*cursor == padCharacter)
                {
                    switch( input.end() - cursor )
                    {
                        case 1: //One pad character
                            decodedBytes.push_back((temp >> 16) & 0x000000FF);
                            decodedBytes.push_back((temp >> 8 ) & 0x000000FF);
                            return decodedBytes;
                            
                        case 2: //Two pad characters
                            decodedBytes.push_back((temp >> 10) & 0x000000FF);
                            return decodedBytes;
                            
                        default:
                            return CharDataVector(0);
                    }
                }
                else
                {
                    return CharDataVector(0);
                }
                
                cursor++;
            }
            
            decodedBytes.push_back((temp >> 16) & 0x000000FF);
            decodedBytes.push_back((temp >> 8 ) & 0x000000FF);
            decodedBytes.push_back((temp      ) & 0x000000FF);
        }
        
        return decodedBytes;
    }
    
}