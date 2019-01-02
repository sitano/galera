/*
 * Copyright (C) 2009-2018 Codership Oy <info@codership.com>
 */

#include "GCache.hpp"

#include <cassert>

namespace gcache
{
    void
    GCache::discard_buffer (BufferHeader* bh)
    {
        assert(bh->seqno_g > 0);
        bh->seqno_g = SEQNO_ILL; // will never be reused

        switch (bh->store)
        {
        case BUFFER_IN_MEM:  mem.discard (bh); break;
        case BUFFER_IN_RB:   rb.discard  (bh); break;
        case BUFFER_IN_PAGE: ps.discard  (bh); break;
        default:
            log_fatal << "Corrupt buffer header: " << bh;
            abort();
        }
    }

    template <typename T> bool
    GCache::discard (T& cond)
    {
        assert(mtx.locked() && mtx.owned());

#ifndef NDEBUG
        if (params.debug()) cond.debug_begin();
#endif
        for (seqno2ptr_t::iterator i = seqno2ptr.begin();
             i != seqno2ptr.end() && cond.check();)
        {
            BufferHeader* bh(ptr2BH (i->second));

            if (gu_likely(BH_is_released(bh)))
            {
                assert (bh->seqno_g == i->first);

                cond.update(bh);
                seqno2ptr.erase (i++); // post ++ is significant!
                discard_buffer(bh);
            }
            else
            {
#ifndef NDEBUG
                if (params.debug()) cond.debug_fail();
#endif
                assert(cond.check());
                return false;
            }
        }

        return true;
    }

    bool
    GCache::discard_size(size_t const size)
    {
        class Cond
        {
            size_t const upto_;
            size_t       done_;
        public:
            Cond(size_t s) : upto_(s), done_(0) {}
            bool check() const { return done_ < upto_; }
            void update(const BufferHeader* bh) { done_ += bh->size; }
            /* bh->size is actually a conservative freed estimate due to
             * store buffer alignment, which is different for each store
             * type. However it is not necessary to be exact here. Were are
             * just trying to discard some buffers because there are too many
             * allocated */
            void debug_begin()
            {
                log_info << "GCache::discard_size(" << upto_ << ")";
            }
            void debug_fail()
            {
                log_info << "GCache::discard_size() can't discard "
                         << (upto_ - done_) << ", bailing out.";
            }
        }
        cond(size);

        return discard<>(cond);
    }

    bool
    GCache::discard_seqno (seqno_t seqno)
    {
        class Cond
        {
            seqno_t const upto_;
            seqno_t       done_;
        public:
            Cond(seqno_t start, seqno_t end) : upto_(end), done_(start - 1) {}
            bool check() const { return done_ < upto_; }
            void update(const BufferHeader* bh)
            {
                assert(done_ + 1 == bh->seqno_g);
                done_ = bh->seqno_g;
            }
            void debug_begin()
            {
                log_info << "GCache::discard_seqno(" << done_ + 1 << " - "
                         << upto_ << ")";
            }
            void debug_fail()
            {
                log_info << "GCache::discard_seqno(" << upto_ << "): "
                             << done_ + 1 << " not released, bailing out.";
            }
        };

        seqno_t const start(seqno2ptr.begin() != seqno2ptr.end() ?
                            seqno2ptr.begin()->first : 0);
        assert(start > 0);

        Cond cond(start, seqno);

        return discard<>(cond);
    }

    void
    GCache::discard_tail (seqno_t seqno)
    {
        seqno2ptr_t::reverse_iterator r;
        while ((r = seqno2ptr.rbegin()) != seqno2ptr.rend() &&
               r->first > seqno)
        {
            BufferHeader* bh(ptr2BH(r->second));

            assert(BH_is_released(bh));
            assert(bh->seqno_g == r->first);
            assert(bh->seqno_g > seqno);

            seqno2ptr.erase(--(seqno2ptr.end()));
            discard_buffer(bh);
        }
    }

    void*
    GCache::malloc (ssize_type const s)
    {
        assert(s >= 0);

        void* ptr(NULL);

        if (gu_likely(s > 0))
        {
            size_type const size(BH_size(s));

            gu::Lock lock(mtx);

            bool const page_cleanup(ps.page_cleanup_needed());
            /* try to discard twice as much as being allocated in order to
             * eventually delete some pages */
            if (page_cleanup) discard_size(2*size);

            mallocs++;

            if (!encrypt_cache)
            {
                ptr = mem.malloc(size);

                if (0 == ptr) ptr = rb.malloc(size);

                if (0 == ptr) ptr = ps.malloc(size);
            }
            else /* only page store can be used */
            {
                ptr = ps.malloc(size);
            }

#ifndef NDEBUG
            if (0 != ptr) buf_tracker.insert (ptr);
#endif
        }

        assert((uintptr_t(ptr) % MemOps::ALIGNMENT) == 0);

        return ptr;
    }

    void
    GCache::free_common (BufferHeader* const bh)
    {
        assert(bh->seqno_g != SEQNO_ILL);
        BH_release(bh);

        if (gu_likely(SEQNO_NONE != bh->seqno_g))
        {
#ifndef NDEBUG
            if (!(seqno_released < bh->seqno_g ||
                  SEQNO_NONE == seqno_released))
            {
                log_fatal << "OOO release: seqno_released " << seqno_released
                          << ", releasing " << bh->seqno_g;
            }
            assert(seqno_released < bh->seqno_g ||
                   SEQNO_NONE == seqno_released);
#endif
            seqno_released = bh->seqno_g;
        }
#ifndef NDEBUG
        void* const ptr(bh + 1);
        std::set<const void*>::iterator it = buf_tracker.find(ptr);
        if (it == buf_tracker.end())
        {
            log_fatal << "Have not allocated this ptr: " << ptr;
            abort();
        }
        buf_tracker.erase(it);
#endif
        frees++;

        switch (bh->store)
        {
        case BUFFER_IN_MEM:  mem.free (bh); break;
        case BUFFER_IN_RB:   rb.free  (bh); break;
        case BUFFER_IN_PAGE: ps.free  (bh); break;
        }

        rb.assert_size_free();

#ifndef NDEBUG
        if (params.debug())
        {
            log_info << "GCache::free_common(): seqno_released: "
                     << seqno_released;
        }
#endif
    }

    void
    GCache::free (void* ptr)
    {
        if (gu_likely(0 != ptr))
        {
            BufferHeader* const bh(ptr2BH(ptr));
            gu::Lock      lock(mtx);

#ifndef NDEBUG
            if (params.debug()) { log_info << "GCache::free() " << bh; }
#endif
            free_common (bh);
        }
        else {
            log_warn << "Attempt to free a null pointer";
            assert(0);
        }
    }

    void*
    GCache::realloc (void* const ptr, ssize_type const s)
    {
        assert(s >= 0);

        if (NULL == ptr)
        {
            return malloc(s);
        }
        else if (s == 0)
        {
            free (ptr);
            return NULL;
        }

        assert((uintptr_t(ptr) % MemOps::ALIGNMENT) == 0);

        size_type const size(BH_size(s));

        void*               new_ptr(NULL);
        BufferHeader* const bh(ptr2BH(ptr));

        if (gu_unlikely(bh->seqno_g > 0)) // sanity check
        {
            log_fatal << "Internal program error: changing size of an ordered"
                      << " buffer, seqno: " << bh->seqno_g << ". Aborting.";
            abort();
        }

        gu::Lock      lock(mtx);

        reallocs++;

        MemOps* store(0);

        switch (bh->store)
        {
        case BUFFER_IN_MEM:  store = &mem; break;
        case BUFFER_IN_RB:   store = &rb;  break;
        case BUFFER_IN_PAGE: store = &ps;  break;
        default:
            log_fatal << "Memory corruption: unrecognized store: "
                      << bh->store;
            abort();
        }

        new_ptr = store->realloc (ptr, size);

        if (0 == new_ptr)
        {
            new_ptr = malloc (size);

            if (0 != new_ptr)
            {
                memcpy (new_ptr, ptr, bh->size - sizeof(BufferHeader));
                store->free (bh);
            }
        }

#ifndef NDEBUG
        if (ptr != new_ptr && 0 != new_ptr)
        {
            std::set<const void*>::iterator it = buf_tracker.find(ptr);

            if (it != buf_tracker.end()) buf_tracker.erase(it);

            it = buf_tracker.find(new_ptr);

        }
#endif
        assert((uintptr_t(new_ptr) % MemOps::ALIGNMENT) == 0);

        return new_ptr;
    }
}
