//
//  CompressionAlgorithms.h
//  cryptopg
//
//  Created by Anton Sarychev on 14.6.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#ifndef cryptopg_CompressionAlgorithms_h
#define cryptopg_CompressionAlgorithms_h


#include <memory>

#include "../PGPData/PGPDataTypes.h"

enum CompressionAlgorithms
{
    CA_UNCOMPRESSED = 0,
    CA_ZIP = 1,
    CA_ZLIB = 2,
    CA_BZIP2 = 3,
};

namespace crypto
{
    class CompressionAlgorithm
    {
    public:
        virtual bool CompressData(const CharDataVector& source, CharDataVector& dst) = 0;
        virtual bool DecompressData(const CharDataVector& source, CharDataVector& dst) = 0;

        virtual ~CompressionAlgorithm() {}
    };

    typedef std::unique_ptr<CompressionAlgorithm> CompressionAlgorithmPtr;

    class ZipCompressionAlgorithm : public CompressionAlgorithm
    {
    public:
        virtual bool CompressData(const CharDataVector& source, CharDataVector& dst);
        virtual bool DecompressData(const CharDataVector& source, CharDataVector& dst);
    };

    class ZLibCompressionAlgorithm  : public CompressionAlgorithm
    {
    public:
        virtual bool CompressData(const CharDataVector& source, CharDataVector& dst);
        virtual bool DecompressData(const CharDataVector& source, CharDataVector& dst);
    };

    class BZip2CompressionAlgorithm : public CompressionAlgorithm
    {
    public:
        virtual bool CompressData(const CharDataVector& source, CharDataVector& dst);
        virtual bool DecompressData(const CharDataVector& source, CharDataVector& dst);
    };

    
    CompressionAlgorithmPtr GetCompressionAlgorithmImpl(CompressionAlgorithms compress_algo);
}

#endif
