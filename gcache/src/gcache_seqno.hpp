/*
 * Copyright (C) 2016-2018 Codership Oy <info@codership.com>
 */

#ifndef __GCACHE_SEQNO__
#define __GCACHE_SEQNO__

#include <wsrep_api.h>

namespace gcache
{
    typedef wsrep_seqno_t seqno_t;

    static seqno_t const SEQNO_NONE =  0;
    static seqno_t const SEQNO_ILL  = -1;

} /* namespace gcache */

#endif /* __GCACHE_SEQNO__ */
