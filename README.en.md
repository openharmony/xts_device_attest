# device_attest

#### Description
Open Harmony device attest development branches
Provide the legal verification function of the device, and verify whether the device has passed the OpenHarmony compatibility certification (OHCA certification) through the combination of device and cloud

#### Software Architecture
Software architecture description

    device_attest
    |    build（compile configuration）
    |    |   devattestconfig.gni（compile public configurations such as directories）
    |    |   BUILD.gn
    |    common（common foundational competencies）
    |    |    log
    |    |    |    ***devattest_log.h
    |    |   ***devattest_errno.h
    |    interfaces（external interface）
    |    |   innerkits
    |    |   |   native_cpp
    |    |   |   |   include
    |    |   |   |   src
    |    |   |   |   BUILD.gn
    |    sample
    |    |   client(client example)
    |    services（service principal and business logic code）
    |    |   devattest_ability（service framework）
    |    |   |   include
    |    |   |   src
    |    |   |   BUILD.gn
    |    |   etc（startup profile）
    |    |   sa_profile（process configuration file）
    |    |   core（business logic code）
    |    |   |   adapter   
    |    |   |   attest
    |    |   |   dfx
    |    |   |   network
    |    |   |   security   
    |    |   |   utils
    |    |   |   include
    |    |   |   attest_entry.c
    |    |   |   attest_entry.h
    |    |   |   BUILD.gn
    |    test（test cases）
    |    bundle.json

#### Instructions

1.  Modify build_xts = true
2.  Input before compilation:export XTS_SUITENAME=acts
3.  ./build.sh product_name=rk3568

#### Contribution

1.  Fork the repository
2.  Create Feat_xxx branch
3.  Commit your code
4.  Create Pull Request


#### Gitee Feature

1.  You can use Readme\_XXX.md to support different languages, such as Readme\_en.md, Readme\_zh.md
2.  Gitee blog [blog.gitee.com](https://blog.gitee.com)
3.  Explore open source project [https://gitee.com/explore](https://gitee.com/explore)
4.  The most valuable open source project [GVP](https://gitee.com/gvp)
5.  The manual of Gitee [https://gitee.com/help](https://gitee.com/help)
6.  The most popular members  [https://gitee.com/gitee-stars/](https://gitee.com/gitee-stars/)
