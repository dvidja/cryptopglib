//
//  ModificationDetectionCodePacket.cpp
//  cryptopg
//
//  Created by Anton Sarychev on 2.10.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "modification_detection_code_packet.h"

namespace cryptopglib::pgp_data::packets {
    ModificationDetectionCodePacket::ModificationDetectionCodePacket()
            : PGPPacket(PT_MODIFICATION_DETECTION_CODE_PACKET) {

    }

    void ModificationDetectionCodePacket::SetData(const CharDataVector &data) {
        data_.assign(data.begin(), data.end());
    }

    CharDataVector &ModificationDetectionCodePacket::GetData() {
        return data_;
    }

    bool ModificationDetectionCodePacket::GetRawData(CharDataVector &data) {
        return false;
    }

    bool ModificationDetectionCodePacket::GetBinaryData(CharDataVector &data) {
        return false;
    }
}
