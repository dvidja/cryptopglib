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
#include "../utils/base64.h"
#include "../utils/crc24.h"

/// TODO:
/// 1. Parse end line
/// 2. Add Parse errors
/// 3.

//new
namespace {
    class ParsingData {
    private:
        std::string_view data;
        std::size_t currentPosition;
        static const char endLine = '\n';

    public:
        explicit ParsingData(std::string_view message)
                : data(message)
                , currentPosition(0) {

        }

        std::string_view GetNextLine() {
            size_t endLinePosition = data.find(endLine, currentPosition);
            if (endLinePosition == std::string::npos)
            {
                return {};
            }

            std::string_view result {data.begin() + currentPosition, data.begin() + endLinePosition};
            currentPosition = endLinePosition + 1;
            return result;
        }

        bool IsEndOfMessage() {
            return currentPosition >= data.size();
        }
    };

    // - Message type from
    bool ParseArmorHeaderLine(ParsingData& parsingData) {
        auto line = parsingData.GetNextLine();
        if (line.starts_with("-----BEGIN")) {
            return true;
        }
        return false;
    }

    std::map<std::string, std::string> ParseArmorHeaders(ParsingData& parsingData) {
        std::map<std::string, std::string> result;
        auto line = parsingData.GetNextLine();
        while (!line.empty()) {
            auto pos = line.find(':');
            if (pos != std::string::npos) {
                // POS + 2 is used because key and value separating with a colon (':' 0x38)
                // and a single space (0x20)
                result[{line.begin(), line.begin() + pos}] =  (pos + 2) < line.size() ?
                     std::string(line.begin() + pos + 2, line.end()) : std::string();
            }

            line = parsingData.GetNextLine();
        }

        return result;
    }

    std::tuple<std::string_view, std::string_view> ParseData(ParsingData& parsingData) {
        auto line = parsingData.GetNextLine();
        auto begin_data = line.begin();

        while (line[0]  != '=') {
            line = parsingData.GetNextLine();
        }

        auto end_data = line.begin();
        std::string_view data(begin_data, end_data);
        std::string_view crc {line.begin() + 1, line.end()};

        return std::make_tuple(data, crc);
    }

    std::vector<unsigned char> DecodeBase64Data(const char* begin, const char* end) {
        return cryptopglib::utils::Base64Decode(begin, end);
    }

    bool CheckCRCChecksum(const std::vector<unsigned char>& data, std::string_view crc) {
        auto calculatedCRC = cryptopglib::utils::CRC24(data);
        std::cout << "CRC calculated:" << calculatedCRC << std::endl;

        //TODO: change checking CRC from base64 to real value
        std::vector<unsigned char> crc_sum_vector;
        crc_sum_vector.push_back(calculatedCRC >> 16);
        crc_sum_vector.push_back(calculatedCRC >> 8);
        crc_sum_vector.push_back(calculatedCRC);

        std::string receivedCRC = cryptopglib::utils::Base64Encode(crc_sum_vector);

        std::cout << "CRC calculated base64:" << receivedCRC << std::endl;
        std::cout << "CRC received: " << crc << std::endl;

        return crc == receivedCRC;
    }

    bool ParseArmorTail(ParsingData& parsingData) {
        auto line = parsingData.GetNextLine();
        if (line.starts_with("-----END")) {
            return true;
        }
        return false;
    }
}


namespace cryptopglib::pgp_parser {

    PGPMessage ParseMessage(const std::string& data) {
        ParsingData parsingData(data);

            if (!ParseArmorHeaderLine(parsingData)) {
                //log the error state. file begin error
                return {};
            }
            auto headers = ParseArmorHeaders(parsingData);

            // TODO: implement parsing of signed message with plain text
            //if signed message parse text message (with armoring of data signature)
            auto [base64Data, crc] = ParseData(parsingData);
            auto rawData = DecodeBase64Data(base64Data.begin(), base64Data.end());

            if (!CheckCRCChecksum(rawData, crc)) {
                // TODO: return or throw an error in case of non valid crc
                return {};
            }

            //TODO: implement parsing tail of need
            if (!ParseArmorTail(parsingData)) {
                //TODO: log error
                return {};
            }

            //parse packets
            auto packets = ParsePackets();

        return PGPMessage{};
    }
}


//unknown
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

//old
namespace cryptopglib::pgp_parser {

    PGPMessagePtr PGPMessageParserOld::ParseMessage(const std::string &source) {
        state_ = PS_START_LINE;

        message_ = std::make_shared<PGPMessageImpl>();

        size_t current_position = 0;
        do {
            std::string string_line;
            current_position = GetNextLine(source, string_line, current_position);

            ParseLine(string_line);
            if (current_position != std::string::npos)
                current_position++;
        } while (current_position != std::string::npos);

        if (message_->GetRawData().empty()) {
            return nullptr;
        }

        if (!CheckCRCSum()) {
            //throw PGPError(MESSAGE_CRC_ERROR);
        }

        return message_;
    }

    void PGPMessageParserOld::ParseLine(const std::string &source) {
        switch (state_) {
            case PS_START_LINE:
                if (ParseArmorHeaderLine(source)) {
                    state_ = PS_ARMOR;
                }

                break;

            case PS_ARMOR:
                if (!ParseArmorHeaders(source)) {
                    if ((message_->GetMessageType() == PGPMessageType::kSignedMessage)
                        && (message_->GetPlainText().empty())) {
                        state_ = PS_SIGNED_TEXT;
                    } else {
                        if (IsDataLine(source)) {
                            ReadDataLine(source);
                        }

                        state_ = PS_DATA;
                    }
                }

                break;

            case PS_SIGNED_TEXT:
                if (!ReadSignedTextLine(source)) {
                    state_ = PS_ARMOR;
                }

                break;

            case PS_DATA:
                if (!ReadDataLine(source)) {
                    state_ = PS_END_LINE;
                }

                break;

            case PS_END_LINE:

                break;

            default:
                break;
        }
    }

    bool PGPMessageParserOld::ParseArmorHeaderLine(const std::string &source) {
        size_t pos = source.find(BEGIN);
        if (pos == std::string::npos) {
            message_->SetMessageType(PGPMessageType::kPlainTextMessage);
            return false;
        }

        pos += strlen(BEGIN) + 1;

        bool flag_end = false;
        std::string word;
        while (!flag_end) {
            if (source.length() <= pos) {
                break;
            }
            switch (source[pos]) {
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

    bool PGPMessageParserOld::ParseArmorHeaders(const std::string &source) {
        size_t pos = source.find(':');
        if (pos != std::string::npos) {
            message_->AddArmorHeaderValue(std::string(source.begin(), source.begin() + pos),
                                          std::string(source.begin() + pos + 1, source.end()));
            return true;
        }

        return false;
    }

    bool PGPMessageParserOld::ReadSignedTextLine(const std::string &source) {
        size_t pos = source.find(BEGIN);

        if (pos == std::string::npos) {
            if (!message_->GetPlainText().empty()) {
                message_->AddPlainText("\n");
            }

            message_->AddPlainText(source);

            std::string str(message_->GetPlainText());

            CharDataVector data(str.begin(), str.end());

            return true;
        }

        return false;
    }

    bool PGPMessageParserOld::ReadDataLine(const std::string &source) {
        if (source[0] == '=') {
            std::string crc_string;
            if (source.back() == '\r') {
                crc_string.assign(std::string(source.begin() + 1, source.end() - 1));
            } else {
                crc_string.assign(std::string(source.begin() + 1, source.end()));
            }

            if (crc_string.size() == 6) {
                crc_string.assign(crc_string.begin() + 2, crc_string.end());
            }

            message_->SetCRC(crc_string);

            return false;
        }


        std::string data_string;
        if (source.back() == '\r') {
            data_string.assign(std::string(source.begin(), source.end() - 1));
        } else {
            data_string.assign(source);
        }

        size_t pos;
        while ((pos = data_string.find("=3D")) != std::string::npos) {
            data_string.erase(data_string.begin() + pos + 1, data_string.begin() + pos + 3);
        }

        message_->AddData(data_string);

        return true;
    }

    void PGPMessageParserOld::ParseHeaderWord(const std::string &word) {
        std::map<std::string, PGPMessageType> words_map;
        words_map[SIGNED] = PGPMessageType::kSignedMessage;
        words_map[MESSAGE] = PGPMessageType::kEncryptedMessage;
        words_map[PUBLIC] = PGPMessageType::kPublicKey;
        words_map[PRIVATE] = PGPMessageType::kPrivateKey;

        auto iter = words_map.find(word);
        if (iter == words_map.end()) {
            return;
        }
        if (iter->second == PGPMessageType::kEncryptedMessage) {
            if (message_->GetMessageType() != PGPMessageType::kSignedMessage) {
                message_->SetMessageType(PGPMessageType::kEncryptedMessage);
            }
        } else {
            message_->SetMessageType(words_map[word]);
        }

        //if (message_info_.message_type_ == MT_PART_MESSAGE)
        {
            // TODO: read numbers
        }

    }

    bool PGPMessageParserOld::CheckCRCSum() {
        long crc_sum = utils::CRC24(message_->GetRawData());

        CharDataVector crc_sum_vector;
        crc_sum_vector.push_back(crc_sum >> 16);
        crc_sum_vector.push_back(crc_sum >> 8);
        crc_sum_vector.push_back(crc_sum);

        std::string crc_result = utils::Base64Encode(crc_sum_vector);

        return message_->GetCRC().compare(crc_result) == 0 ? true : false;
    }
}
