/*
 * Copyright (C) 2010-2019 Codership Oy <info@codership.com>
 */

/*! @file page store implementation */

#include "gcache_page_store.hpp"
#include "gcache_bh.hpp"
#include "gcache_limits.hpp"

#include <gu_logger.hpp>
#include <gu_throw.hpp>

#include <cstdio>
#include <cstring>
#include <pthread.h>

#include <iomanip>

static const std::string base_name ("gcache.page.");

static std::string
make_base_name (const std::string& dir_name)
{
    if (dir_name.empty())
    {
        return base_name;
    }
    else
    {
        if (dir_name[dir_name.length() - 1] == '/')
        {
            return (dir_name + base_name);
        }
        else
        {
            return (dir_name + '/' + base_name);
        }
    }
}

static std::string
make_page_name (const std::string& base_name, size_t count)
{
    std::ostringstream os;
    os << base_name << std::setfill ('0') << std::setw (6) << count;
    return os.str();
}

static void*
remove_file (void* __restrict__ arg)
{
    char* const file_name (static_cast<char*>(arg));

    if (NULL != file_name)
    {
        if (remove (file_name))
        {
            int err = errno;

            log_error << "Failed to remove page file '" << file_name << "': "
                      << err << " (" << strerror(err) << ")";
        }
        else
        {
            log_info << "Deleted page " << file_name;
        }

        free (file_name);
    }
    else
    {
        log_error << "Null file name in " << __FUNCTION__;
    }

    pthread_exit(NULL);
}

bool
gcache::PageStore::delete_page ()
{
    Page* const page = pages_.front();

    if (page->used() > 0) return false;

    pages_.pop_front();

    char* const file_name(strdup(page->name().c_str()));

    total_size_ -= page->size();

    if (current_ == page) current_ = 0;

    delete page;

#ifdef GCACHE_DETACH_THREAD
    pthread_t delete_thr_;
#else
    if (delete_thr_ != pthread_t(-1)) pthread_join (delete_thr_, NULL);
#endif /* GCACHE_DETACH_THERAD */

    int err = pthread_create (&delete_thr_, &delete_page_attr_, remove_file,
                              file_name);
    if (0 != err)
    {
        delete_thr_ = pthread_t(-1);
        gu_throw_error(err) << "Failed to create page file deletion thread";
    }

    return true;
}

/* Deleting pages only from the beginning kinda means that some free pages
 * can be locked in the middle for a while. Leaving it like that for simplicity
 * for now. */
void
gcache::PageStore::cleanup ()
{
    while (page_cleanup_needed() && delete_page()) {}
}

void
gcache::PageStore::reset ()
{
    while (pages_.size() > 0 && delete_page()) {};
}

void
gcache::PageStore::set_enc_key (const Page::EncKey& new_key)
{
    /* on key change create new page (saves current key there) */
    new_page(0, new_key);
    enc_key_ = new_key;
}

inline void
gcache::PageStore::new_page (size_type const size, const Page::EncKey& new_key)
{
    size_type const key_buf_size(BH_size(enc_key_.size()));
    size_type const meta_size(Page::meta_size(key_buf_size));
    size_type const min_size(meta_size + Page::aligned_size(size));

    Page* const page(new Page(this,
                              make_page_name(base_name_, count_),
                              nonce_,
                              new_key,
                              page_size_ > min_size ? page_size_ : min_size,
                              debug_));

    pages_.push_back (page);
    total_size_ += page->size();
    current_ = page;
    count_++;
    nonce_ += page->size(); /* advance nonce for the next page */

    // allocate, write and release key buffer
    void* const kp(current_->malloc(key_buf_size));
    std::vector<uint8_t> kv(key_buf_size); // plaintext key buffer
    BufferHeader* const bh(BH_cast(kv.data()));
    BH_clear(bh);
    bh->size = key_buf_size;
    BH_release(bh);
    ::memcpy(kp, bh, key_buf_size);
    current_->discard(BH_cast(kp));
}

gcache::PageStore::PageStore (const std::string& dir_name,
                              wsrep_encrypt_cb_t encrypt_cb,
                              size_t             keep_size,
                              size_t             page_size,
                              size_t             keep_plaintext_size,
                              int                dbg,
                              bool               keep_page)
    :
    base_name_ (make_base_name(dir_name)),
    encrypt_cb_(encrypt_cb),
    enc_key_   (),
    nonce_     (),
    keep_size_ (keep_size),
    page_size_ (page_size),
    keep_plaintext_size_ (keep_plaintext_size),
    plaintext_size_(0),
    count_     (0),
    pages_     (),
    current_   (0),
    total_size_(0),
    delete_page_attr_(),
#ifndef GCACHE_DETACH_THREAD
    delete_thr_(pthread_t(-1)),
#endif /* GCACHE_DETACH_THREAD */
    debug_     (dbg & DEBUG),
    keep_page_ (keep_page)
{
    int err = pthread_attr_init (&delete_page_attr_);

    if (0 != err)
    {
        gu_throw_error(err) << "Failed to initialize page file deletion "
                            << "thread attributes";
    }

#ifdef GCACHE_DETACH_THREAD
    err = pthread_attr_setdetachstate (&delete_page_attr_,
                                       PTHREAD_CREATE_DETACHED);
    if (0 != err)
    {
        pthread_attr_destroy (&delete_page_attr_);
        gu_throw_error(err) << "Failed to set DETACHED attribute to "
                            << "page file deletion thread";
    }
#endif /* GCACHE_DETACH_THREAD */
}

gcache::PageStore::~PageStore ()
{
    try
    {
        while (pages_.size() && delete_page()) {};
#ifndef GCACHE_DETACH_THREAD
        if (delete_thr_ != pthread_t(-1)) pthread_join (delete_thr_, NULL);
#endif /* GCACHE_DETACH_THREAD */
    }
    catch (gu::Exception& e)
    {
        log_error << e.what() << " in ~PageStore()"; // abort() ?
    }

    if (pages_.size() > 0)
    {
        log_error << "Could not delete " << pages_.size()
                  << " page files: some buffers are still \"mmapped\".";
        if (debug_)
            for (PageQueue::iterator i(pages_.begin()); i != pages_.end(); ++i)
            {
                log_error << *(*i);;
            }
    }

    pthread_attr_destroy (&delete_page_attr_);
}

inline void*
gcache::PageStore::malloc_new (size_type const size)
{
    Limits::assert_size(size);

    void* ret(NULL);

    try
    {
        new_page(size, enc_key_);
        ret = current_->malloc (size);
        cleanup();
    }
    catch (gu::Exception& e)
    {
        log_error << "Cannot create new cache page: "
                  << e.what();
        // abort();
    }
    assert(ret);
    return ret;
}

void*
gcache::PageStore::malloc (size_type const size)
{
    Limits::assert_size(size);

    BufferHeader* bh(NULL);

    if (gu_likely(NULL != current_)) bh = BH_cast(current_->malloc(size));
    if (gu_unlikely(NULL == bh)) bh = BH_cast(malloc_new(size));
    if (gu_likely(NULL != bh))
    {
        bh->size    = size;
        bh->seqno_g = SEQNO_NONE;
        bh->ctx     = reinterpret_cast<BH_ctx_t>(current_);
        bh->flags   = 0;
        bh->store   = BUFFER_IN_PAGE;

        bh += 1; // point to payload
    }

    return bh;
}

void*
gcache::PageStore::realloc (void* ptr, size_type const size)
{
    Limits::assert_size(size);

    assert(ptr != NULL);

    BufferHeader* const bh(ptr2BH(ptr));
    assert(SEQNO_NONE == bh->seqno_g);

    size_type allocd_size(Page::aligned_size(bh->size));
    if (size <= allocd_size)
    {
        bh->size = size;
        return ptr;
    }

    void* ret(malloc(size));

    if (gu_likely(0 != ret))
    {
        assert(size > bh->size);
        size_type const ptr_size(bh->size - sizeof(BufferHeader));
        ::memcpy (ret, ptr, ptr_size);
        BH_release(bh);
        release<true>(bh);
    }

    return ret;
}

void*
gcache::PageStore::get_plaintext(const void* ptr)
{
    assert(encrypt_cb_); // must be called only if encryption callback is set
    assert(0);
    return NULL;
}

void
gcache::PageStore::drop_plaintext(const void* ptr)
{
    assert(encrypt_cb_); // must be called only if encryption callback is set
    assert(0);
    (void)ptr;
}

void
gcache::PageStore::set_debug(int const dbg)
{
    debug_ = dbg & DEBUG;

    for (PageQueue::iterator i(pages_.begin()); i != pages_.end(); ++i)
    {
        (*i)->set_debug(debug_);
    }
}
