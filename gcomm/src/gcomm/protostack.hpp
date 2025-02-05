/*
 * Copyright (C) 2009 Codership Oy <info@codership.com>
 */

#ifndef GCOMM_PROTOSTACK_HPP
#define GCOMM_PROTOSTACK_HPP

#include "gcomm/protolay.hpp"

#include "gu_lock.hpp"
#include "gu_thread_keys.hpp"

#include <vector>
#include <deque>

namespace gcomm
{
    class Socket;
    class Acceptor;
    class Protostack;
    class Protonet;
    class BoostProtonet;
}


class gcomm::Protostack
{
public:
    Protostack() : protos_(), mutex_(gu::get_mutex_key(gu::GU_MUTEX_KEY_PROTOSTACK)) { }
    void push_proto(Protolay* p);
    void pop_proto(Protolay* p);
    gu::datetime::Date handle_timers();
    void dispatch(const void* id, const Datagram& dg,
                  const ProtoUpMeta& um);
    bool set_param(const std::string&, const std::string&,
                   Protolay::sync_param_cb_t& sync_param_cb);
    void enter() { mutex_.lock(); }
    void leave() { mutex_.unlock(); }
private:
    friend class Protonet;
    std::deque<Protolay*> protos_;
    gu::Mutex mutex_;
};


#endif // GCOMM_PROTOSTACK_HPP
