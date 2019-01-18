/*
 * Copyright (C) 2015-2019 Codership Oy <info@codership.com>
 */

#include "gcs_test_utils.hpp"
#include "../../../gcache/src/gcache_test_encryption.hpp"

#include <gu_throw.hpp>

#include <boost/filesystem.hpp>

namespace gcs_test
{

void
InitConfig::common_ctor(gu::Config& cfg)
{
    gcache::GCache::register_params(cfg);
    gcs_register_params(reinterpret_cast<gu_config_t*>(&cfg));
}

InitConfig::InitConfig(gu::Config& cfg)
{
    common_ctor(cfg);
}

InitConfig::InitConfig(gu::Config& cfg, const std::string& base_name)
{
    common_ctor(cfg);
    std::string p("gcache.size=1K;gcache.page_size=1K;gcache.name=");
    p += base_name;
#ifndef NDEBUG
    p += ";gcache.debug=4"; // additional gcache page debug info
#endif
    gu_trace(cfg.parse(p));
}

GcsGroup::GcsGroup() :
    path_   ("./"),
    conf_   (),
    init_   (conf_, "group"),
    gcache_ (NULL),
    group_  (),
    initialized_(false)
{}

void
GcsGroup::common_ctor(const std::string& node_name,
                      const std::string& inc_addr,
                      bool         enc,
                      gcs_proto_t  gver,
                      int          rver,
                      int          aver)
{
    assert(NULL  == gcache_);
    assert(false == initialized_);

    path_ += node_name + "_gcache";
    boost::filesystem::path const path(path_);
    if (!boost::filesystem::create_directories(path))
    {
        gu_throw_fatal << "Could not create directory: " << path;
    }

    if (enc)
    {
        gcache_ = new gcache::GCache(conf_, path_, gcache_test_encrypt_cb,
                                     NULL);
        wsrep_enc_key_t const key = { node_name.c_str(), node_name.length() };
        gcache_->set_enc_key(key);
    }
    else
    {
        gcache_ = new gcache::GCache(conf_, path_);
    }

    int const err(gcs_group_init(&group_, &conf_,
                                 reinterpret_cast<gcache_t*>(gcache_),
                                 node_name.c_str(), inc_addr.c_str(),
                                 gver, rver, aver));
    if (err)
    {
        gu_throw_error(-err) << "GcsGroup init failed";
    }

    initialized_ = true;
}

GcsGroup::GcsGroup(const std::string& node_id,
                   const std::string& inc_addr,
                   bool enc,
                   gcs_proto_t gver, int rver, int aver) :
    path_   ("./"),
    conf_   (),
    init_   (conf_, node_id),
    gcache_ (NULL),
    group_  (),
    initialized_(false)
{
    common_ctor(node_id, inc_addr, enc, gver, rver, aver);
}

void
GcsGroup::common_dtor()
{
    if (initialized_)
    {
        assert(NULL != gcache_);
        gcs_group_free(&group_);
        delete gcache_;

        boost::filesystem::path path(path_);
        if (path != boost::filesystem::current_path())
        {
            boost::filesystem::remove_all(path);
        }
    }
    else
    {
        assert(NULL == gcache_);
    }
}

void
GcsGroup::init(const std::string& node_name,
               const std::string& inc_addr,
               bool         enc,
               gcs_proto_t  gcs_proto_ver,
               int          repl_proto_ver,
               int          appl_proto_ver)
{
    common_dtor();
    initialized_ = false;
    gcache_ = NULL;
    common_ctor(node_name, inc_addr, enc,
                gcs_proto_ver, repl_proto_ver, appl_proto_ver);
}

GcsGroup::~GcsGroup()
{
    common_dtor();
}

} // namespace
