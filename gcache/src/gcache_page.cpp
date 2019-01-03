/*
 * Copyright (C) 2010-2018 Codership Oy <info@codership.com>
 */

/*! @file page file class implementation */

#include "gcache_page.hpp"
#include "gcache_limits.hpp"

#include <gu_throw.hpp>
#include <gu_logger.hpp>

// for posix_fadvise()
#if !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE 600
#endif
#include <fcntl.h>

void
gcache::Page::reset ()
{
    if (gu_unlikely (used_ > 0))
    {
        log_fatal << "Attempt to reset a page '" << name()
                  << "' used by " << used_ << " buffers. Aborting.";
        abort();
    }

    space_ = mmap_.size;
    next_  = static_cast<uint8_t*>(mmap_.ptr);
}

void
gcache::Page::drop_fs_cache() const
{
    mmap_.dont_need();

#if !defined(__APPLE__)
    int const err (posix_fadvise (fd_.get(), 0, fd_.size(),
                                  POSIX_FADV_DONTNEED));
    if (err != 0)
    {
        log_warn << "Failed to set POSIX_FADV_DONTNEED on " << fd_.name()
                 << ": " << err << " (" << strerror(err) << ")";
    }
#endif
}

gcache::Page::Page (void* ps, const std::string& name, size_t size,
                    int dbg)
    :
    fd_   (name, aligned_size(size), false, false),
    mmap_ (fd_),
    ps_   (ps),
    next_ (static_cast<uint8_t*>(mmap_.ptr)),
    space_(mmap_.size),
    used_ (0),
    debug_(dbg)
{
    log_info << "Created page " << name << " of size " << space_
             << " bytes";
    BH_clear (BH_cast(next_));
}

void
gcache::Page::close()
{
    // write empty header to signify end of chain for subsequent recovery
    if (space_ >= sizeof(BufferHeader)) BH_clear(BH_cast(next_));
}

void*
gcache::Page::malloc (size_type size)
{
    Limits::assert_size(size);
    size_type const alloc_size(aligned_size(size));

    if (alloc_size <= space_)
    {
        void* ret = next_;
        space_ -= alloc_size;
        next_  += alloc_size;
        used_++;

#ifndef NDEBUG
        assert (next_ <= static_cast<uint8_t*>(mmap_.ptr) + mmap_.size);
        if (debug_)
        {
            log_info << name() << " allocd " << size << '/' << alloc_size;
        }
#endif
        return ret;
    }
    else
    {
        close(); // this page will not be used any more.
        log_debug << "Failed to allocate " << size << " bytes, space left: "
                  << space_ << " bytes, total allocated: "
                  << next_ - static_cast<uint8_t*>(mmap_.ptr);
        return 0;
    }
}

void*
gcache::Page::realloc (void* ptr, size_type size)
{
    assert(0); // all logic must go to PageStore.
    return NULL;
}

void gcache::Page::print(std::ostream& os) const
{
    os << "page file: " << name() << ", size: " << size() << ", used: "
       << used_;

    if (used_ > 0 && debug_ > 0)
    {
        bool was_released(true);
        const uint8_t* const start(static_cast<uint8_t*>(mmap_.ptr));
        const uint8_t* p(start);
        assert(p != next_);
        while (p != next_)
        {
            ptrdiff_t const offset(p - start);
            const BufferHeader* const bh(BH_const_cast(p));
            p += bh->size;
            if (!BH_is_released(bh))
            {
                os << "\noff: " << offset << ", " << bh;
                was_released = false;
            }
            else
            {
                if (!was_released && p != next_)
                {
                    os << "\n..."; /* indicate gap */
                }
                was_released = true;
            }
        }
    }
}
