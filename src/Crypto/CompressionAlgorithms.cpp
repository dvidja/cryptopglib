//
//  CompressionAlgorithms
//  cryptopg
//
//  Created by Anton Sarychev on 14.6.13.
//  Copyright (c) 2013 Anton Sarychev. All rights reserved.
//

#include "CompressionAlgorithms.h"
extern "C" {
#include <zlib.h>
#include <bzlib.h>
}

namespace crypto
{
    
    bool ZipCompressionAlgorithm::CompressData(const CharDataVector& source, CharDataVector& dst)
    {
        std::vector<uint8_t> buffer;
        
        const size_t BUFSIZE = 128 * 1024;
        uint8_t temp_buffer[BUFSIZE];
        
        CharDataVector new_source(source);
        
        z_stream strm;
        strm.zalloc = 0;
        strm.zfree = 0;
        strm.next_in = &new_source[0];
        strm.avail_in = static_cast<unsigned int>(new_source.size());
        strm.next_out = temp_buffer;
        strm.avail_out = BUFSIZE;
        
        int res = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -13, 8, Z_DEFAULT_STRATEGY);
        if(res != Z_OK)
        {
            return false;
        }
        
        while (strm.avail_in != 0)
        {
            res = deflate(&strm, Z_NO_FLUSH);
            if (res != Z_OK)
            {
                return false;
            }
            
            if (strm.avail_out == 0)
            {
                buffer.insert(buffer.end(), temp_buffer, temp_buffer + BUFSIZE);
                strm.next_out = temp_buffer;
                strm.avail_out = BUFSIZE;
            }
        }
        
        int deflate_res = Z_OK;
        while (deflate_res == Z_OK)
        {
            if (strm.avail_out == 0)
            {
                buffer.insert(buffer.end(), temp_buffer, temp_buffer + BUFSIZE);
                strm.next_out = temp_buffer;
                strm.avail_out = BUFSIZE;
            }
            
            deflate_res = deflate(&strm, Z_FINISH);
        }
        
        if (deflate_res != Z_STREAM_END)
        {
            return false;
        }
        
        buffer.insert(buffer.end(), temp_buffer, temp_buffer + BUFSIZE - strm.avail_out);
        deflateEnd(&strm);
        
        dst.swap(buffer);
        
        return true;

    }
    
    bool ZipCompressionAlgorithm::DecompressData(const CharDataVector& source, CharDataVector& dst)
    {
        int bufferSize = 128 * 1024;
        
        z_stream strm;
        strm.zalloc = NULL;
        strm.zfree = NULL;
        strm.opaque = NULL;
        
        int ret = inflateInit2(&strm, -15);
        if(ret != Z_OK)
        {
            return false;
        }
        
        CharDataVector new_source(source);
        strm.next_in = &new_source[0];
        strm.avail_in = static_cast<unsigned int>(new_source.size());
        
        CharDataVector buf(bufferSize);
        
        while (Z_OK == ret)
        {
            strm.next_out = &buf[0];
            strm.avail_out = bufferSize;
            ret = inflate(&strm, Z_NO_FLUSH);
            
            // Write out the bufs if we had no error.
            if (Z_OK == ret || Z_STREAM_END == ret)
            {
                if (strm.next_out == &buf[0])
                {
                    return false;
                }
                
                dst.insert(dst.end(), &buf[0], &buf[strm.next_out - &buf[0]]);
            }
        }
        
        inflateEnd(&strm);
        
        return true;
    }

    bool ZLibCompressionAlgorithm::CompressData(const CharDataVector& source, CharDataVector& dst)
    {
        std::vector<uint8_t> buffer;
        
        const size_t BUFSIZE = 128 * 1024;
        uint8_t temp_buffer[BUFSIZE];
        
        CharDataVector new_source(source);
        
        z_stream strm;
        strm.zalloc = 0;
        strm.zfree = 0;
        strm.next_in = &new_source[0];
        strm.avail_in = static_cast<unsigned int>(new_source.size());
        strm.next_out = temp_buffer;
        strm.avail_out = BUFSIZE;
        
        int res = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
        if(res != Z_OK)
        {
            return false;
        }
        
        while (strm.avail_in != 0)
        {
            res = deflate(&strm, Z_NO_FLUSH);
            if (res != Z_OK)
            {
                return false;
            }
         
            if (strm.avail_out == 0)
            {
                buffer.insert(buffer.end(), temp_buffer, temp_buffer + BUFSIZE);
                strm.next_out = temp_buffer;
                strm.avail_out = BUFSIZE;
            }
        }
        
        int deflate_res = Z_OK;
        while (deflate_res == Z_OK)
        {
            if (strm.avail_out == 0)
            {
                buffer.insert(buffer.end(), temp_buffer, temp_buffer + BUFSIZE);
                strm.next_out = temp_buffer;
                strm.avail_out = BUFSIZE;
            }
            
            deflate_res = deflate(&strm, Z_FINISH);
        }
        
        if (deflate_res != Z_STREAM_END)
        {
            return false;
        }
        
        buffer.insert(buffer.end(), temp_buffer, temp_buffer + BUFSIZE - strm.avail_out);
        deflateEnd(&strm);
        
        dst.swap(buffer);
        
        return true;
    }
    
    bool ZLibCompressionAlgorithm::DecompressData(const CharDataVector& source, CharDataVector& dst)
    {
        int bufferSize = 128 * 1024;
        
        z_stream strm;
        strm.zalloc = NULL;
        strm.zfree = NULL;
        strm.opaque = NULL;
        
        int ret = inflateInit(&strm);
        if(ret != Z_OK)
        {
            return false;
        }
        
        CharDataVector new_source(source);
        strm.next_in = &new_source[0];
        strm.avail_in = static_cast<unsigned int>(new_source.size());
        
        CharDataVector buf(bufferSize);
        
        while (Z_OK == ret)
        {
            strm.next_out = &buf[0];
            strm.avail_out = bufferSize;
            ret = inflate(&strm, Z_NO_FLUSH);
            
            // Write out the bufs if we had no error.
            if (Z_OK == ret || Z_STREAM_END == ret)
            {
                if (strm.next_out == &buf[0])
                {
                    return false;
                }
                
                dst.insert(dst.end(), &buf[0], &buf[strm.next_out - &buf[0]]);
            }
        }
        
        inflateEnd(&strm);
        
        return true;
    }

    bool BZip2CompressionAlgorithm::CompressData(const CharDataVector& source, CharDataVector& dst)
    {
        std::vector<uint8_t> buffer;
        
        const size_t BUFSIZE = 128 * 1024;
        char temp_buffer[BUFSIZE];
        
        CharDataVector new_source(source);
        
        bz_stream strm;
        strm.bzalloc = 0;
        strm.bzfree = 0;
        strm.next_in = (char*)&new_source[0];
        strm.avail_in = static_cast<unsigned int>(new_source.size());
        strm.next_out = temp_buffer;
        strm.avail_out = BUFSIZE;
        
        int res = BZ2_bzCompressInit(&strm, 9, 0, 0);
        if((res != BZ_OK) && (res != BZ_RUN_OK))
        {
            return false;
        }
        
        while (strm.avail_in != 0)
        {
            res = BZ2_bzCompress(&strm, BZ_RUN);
            if((res != BZ_OK) && (res != BZ_RUN_OK))
            {
                return false;
            }
            
            if (strm.avail_out == 0)
            {
                buffer.insert(buffer.end(), temp_buffer, temp_buffer + BUFSIZE);
                strm.next_out = temp_buffer;
                strm.avail_out = BUFSIZE;
            }
        }
        
        int deflate_res = BZ_OK;
        while (deflate_res == BZ_OK)
        {
            if (strm.avail_out == 0)
            {
                buffer.insert(buffer.end(), temp_buffer, temp_buffer + BUFSIZE);
                strm.next_out = temp_buffer;
                strm.avail_out = BUFSIZE;
            }
            
            deflate_res = BZ2_bzCompress(&strm, BZ_FINISH);
        }
        
        if (deflate_res != BZ_STREAM_END)
        {
            return false;
        }
        
        buffer.insert(buffer.end(), temp_buffer, temp_buffer + BUFSIZE - strm.avail_out);
        BZ2_bzCompressEnd(&strm);
        
        dst.swap(buffer);
        
        return true;
    }
    
    bool BZip2CompressionAlgorithm::DecompressData(const CharDataVector& source, CharDataVector& dst)
    {
        int verbosity = 0;
        int small = 0;
        int bufferSize = 10240;
        
        bz_stream strm;
        strm.bzalloc = NULL;
        strm.bzfree = NULL;
        strm.opaque = NULL;

        strm.next_in = (char*)&source[0];
        strm.avail_in = static_cast<unsigned int>(source.size());
        int ret = BZ2_bzDecompressInit(&strm, verbosity, small);
        if (ret != BZ_OK)
        {
            return false;
        }
        
        std::vector<char> buf(bufferSize);
        
        while (BZ_OK == ret)
        {
            strm.next_out = &buf[0];
            strm.avail_out = bufferSize;
            ret = BZ2_bzDecompress(&strm);
            
            // Write out the bufs if we had no error.
            if (BZ_OK == ret || BZ_STREAM_END == ret)
            {
                if (strm.next_out == &buf[0])
                {
                    return false;
                }
                
                dst.insert(dst.end(), &buf[0], &buf[strm.next_out - &buf[0]]);
            }
        }

        BZ2_bzDecompressEnd(&strm);
            
        return true;
    }

    CompressionAlgorithmPtr GetCompressionAlgorithmImpl(CompressionAlgorithms compress_algo)
    {
        CompressionAlgorithmPtr compresseion_algo_impl(nullptr);
        switch (compress_algo)
        {
            case CA_ZIP:
                compresseion_algo_impl.reset(new ZipCompressionAlgorithm());
                break;
            case CA_ZLIB:
                compresseion_algo_impl.reset(new ZLibCompressionAlgorithm());
                break;
            case CA_BZIP2:
                compresseion_algo_impl.reset(new BZip2CompressionAlgorithm());
                break;
                
            default:
                return nullptr;
                break;
        }
        
        return compresseion_algo_impl;
    }
}