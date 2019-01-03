//
// Copyright (C) 2019 Codership Oy <info@codership.com>
//

#ifndef GALERA_TEST_ENV_HPP
#define GALERA_TEST_ENV_HPP

#include "gu_config.hpp"
#include "GCache.hpp"
#include "replicator_smm.hpp"
#include "galera_gcs.hpp"

#include <string>

namespace
{
    class TestEnv
    {
    public:

        TestEnv(const std::string& test_name) :
            gcache_name_(std::string(test_name) + ".cache"),
            conf_   (),
            init_   (conf_, gcache_name_),
            gcache_ (conf_, "."),
            gcs_    (conf_, gcache_)
        { }

        ~TestEnv() { ::unlink(gcache_name_.c_str()); }

        gu::Config&         conf()   { return conf_  ; }
        gcache::GCache&     gcache() { return gcache_; }
        galera::DummyGcs&   gcs()    { return gcs_;    }

    private:

        std::string const                 gcache_name_;
        gu::Config                        conf_;

        struct Init
        {
            galera::ReplicatorSMM::InitConfig init_;

            Init(gu::Config& conf, const std::string& gcache_name)
                : init_(conf, NULL, NULL)
            {
                conf.set("gcache.name", gcache_name);
                conf.set("gcache.size", "1M");
                conf.set("gcache.page_size", "16K");
                conf.set("gcache.keep_pages_size", "0");
            }
        }                                 init_;

        gcache::GCache                    gcache_;
        galera::DummyGcs                  gcs_;
    };

} // namespace

#endif /* GALERA_TEST_ENV_HPP */
