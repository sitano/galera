/*
 * Copyright (C) 2010-2019 Codership Oy <info@codership.com>
 */

/*! @file page file class */

#ifndef _gcache_page_hpp_
#define _gcache_page_hpp_

#include "gcache_memops.hpp"
#include "gcache_bh.hpp"

#include "gu_fdesc.hpp"
#include "gu_mmap.hpp"
#include "gu_logger.hpp"
#include "gu_byteswap.hpp"

#include <string>
#include <ostream>
#include <vector>

namespace gcache
{
    class Page : public MemOps
    {
    public:

        class Nonce
        {
        public:
            Nonce();                             /* constructs random nonce */
            Nonce(const void* buf, size_t size); /* reads nonce from buffer */
            size_t write(void* buf, size_t size)const;/* write nonce to buffer */
            const wsrep_enc_iv_t* iv() const { return &d.iv; }
            const void* ptr() const { return &d; }
            static size_t size()
            {
                return sizeof(Nonce::d);
            }
            Nonce& operator +=(uint64_t i)
            {
                d.l[0] = gu::htog<uint64_t>(gu::gtoh<uint64_t>(d.l[0]) + i);
                return *this;
            }

        private:
            union { wsrep_enc_iv_t iv; uint32_t i[8]; uint64_t l[4]; } d;

            GU_COMPILE_ASSERT(sizeof(d.iv) == sizeof(d.l), size_fail1);
            GU_COMPILE_ASSERT(sizeof(d.i)  == sizeof(d.l), size_fail2);
        };

        typedef std::vector<uint8_t> EncKey;

        Page (void*              ps,
              const std::string& name,
              const Nonce&       nonce,
              const EncKey&      key,
              size_t             size,
              int                dbg);

        ~Page () {}

        void* malloc  (size_type size);

        void* realloc (void* ptr, size_type size);

        void  free    (BufferHeader* bh)
        {
            assert(bh >= mmap_.ptr);
            assert(static_cast<void*>(bh) <= // checks that bh is within page
                   (static_cast<uint8_t*>(mmap_.ptr) + mmap_.size -
                    sizeof(BufferHeader)));
            assert(bh->size >= sizeof(BufferHeader));
            assert(bh->store == BUFFER_IN_PAGE);
            assert(bh->ctx == reinterpret_cast<BH_ctx_t>(this));
            assert(BH_is_released(bh));
            assert (used_ > 0);
#ifndef NDEBUG
            if (debug_) { log_info << name() << " freed " << bh; }
#endif
            if (bh->seqno_g <= 0) // ordered buffers get dicarded in discard()
            {
                used_--;
            }
        }

        void  repossess(BufferHeader* bh)
        {
            assert(bh >= mmap_.ptr);
            assert(BH_next(bh) <= BH_cast(next_));
            assert(bh->size >= sizeof(BufferHeader));
            assert(bh->seqno_g != SEQNO_NONE);
            assert(bh->store == BUFFER_IN_PAGE);
            assert(bh->ctx == reinterpret_cast<BH_ctx_t>(this));
            assert(BH_is_released(bh)); // will be marked unreleased by caller
#ifndef NDEBUG
            if (debug_) { log_info << name() << " repossessed " << bh; }
#endif
            used_++;
        }

        void discard (BufferHeader* bh)
        {
            assert(BH_is_released(bh));
#ifndef NDEBUG
            if (debug_) { log_info << name() << " discarded " << bh; }
#endif
            assert(used_ > 0);
            used_--;
        }

        size_t used () const { return used_; }

        size_t size() const { return fd_.size(); } /* size on storage */

        const std::string& name() const { return fd_.name(); }

        void reset ();

        /* Drop filesystem cache on the file */
        void drop_fs_cache() const;

        void* parent() const { return ps_; }

        void print(std::ostream& os) const;

        void set_debug(int const dbg) { debug_ = dbg; }

        static const size_type ALIGNMENT = 16;
        /* typical encryption block size */

        static inline size_type aligned_size(size_type s)
        {
            return GU_ALIGN(s, Page::ALIGNMENT);
        }

        /* amount of space that will be reserved for metadata */
        static size_type meta_size(size_type enc_key_size)
        {
            return Page::aligned_size(sizeof(Nonce)) +
                   Page::aligned_size(enc_key_size);
        }

    private:

        gu::FileDescriptor fd_;
        gu::MMap           mmap_;
        EncKey             key_;
        Nonce              nonce_;
        void*              ps_;
        uint8_t*           next_;
        size_t             space_;
        size_t             used_;
        int                debug_;

        GU_COMPILE_ASSERT(ALIGNMENT % GU_MIN_ALIGNMENT == 0,
                          page_alignment_is_not_multiple_of_min_alignment);

        static inline BufferHeader*
        BH_next(BufferHeader* bh)
        {
            return BH_cast(reinterpret_cast<uint8_t*>(bh) +
                           aligned_size(bh->size));
        }

        void close(); /* close page for allocation */

        Page(const gcache::Page&);
        Page& operator=(const gcache::Page&);

    }; /* class Page */

    static inline std::ostream&
    operator <<(std::ostream& os, const gcache::Page& p)
    {
        p.print(os);
        return os;
    }

    static inline gcache::Page::Nonce
    operator +(gcache::Page::Nonce n, uint64_t const i)
    {
        n += i;
        return n;
    }

} /* namespace gcache */

#endif /* _gcache_page_hpp_ */
