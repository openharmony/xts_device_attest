# DEVICE_ATTEST 设备证明

#### 介绍
Open Harmony设备证明开发分支
提供设备的合法性验证功能，通过端云结合的方式校验设备是否通过OpenHarmony兼容性认证（OHCA认证）

#### 目录

代码目录结构：

    device_attest
    |    build（编译配置）
    |    |   devattestconfig.gni（编译目录等公共配置）
    |    |   BUILD.gn
    |    common（公共基础能力）
    |    |    log
    |    |    |    ***devattest_log.h
    |    |    ***devattest_errno.h
    |    interfaces（对外接口）
    |    |   innerkits
    |    |   |   native_cpp
    |    |   |   |   include
    |    |   |   |   src
    |    |   |   |   BUILD.gn
    |    sample(示例)
    |    |   client(客户端示例)
    |    services（服务主体和业务逻辑代码）
    |    |   devattest_ability（服务框架）
    |    |   |   include
    |    |   |   src
    |    |   |   BUILD.gn
    |    |   etc（启动配置文件）
    |    |   sa_profile（进程配置文件）
    |    |   core（业务逻辑代码）
    |    |   |   adapter   
    |    |   |   attest（证明主流程）
    |    |   |   dfx（质量）
    |    |   |   network（网络连接）
    |    |   |   security（安全加密）   
    |    |   |   utils
    |    |   |   include
    |    |   |   ***attest_entry.c
    |    |   |   ***attest_entry.h
    |    |   |   BUILD.gn
    |    test（测试用例）
    |    bundle.json

#### 使用说明

1.  将build_xts置为true
2.  编译前输入export XTS_SUITENAME=acts
3.  ./build.sh product_name=rk3568

#### 参与贡献

1.  Fork 本仓库
2.  新建 Feat_xxx 分支
3.  提交代码
4.  新建 Pull Request


#### 特技

1.  使用 Readme\_XXX.md 来支持不同的语言，例如 Readme\_en.md, Readme\_zh.md
2.  Gitee 官方博客 [blog.gitee.com](https://blog.gitee.com)
3.  你可以 [https://gitee.com/explore](https://gitee.com/explore) 这个地址来了解 Gitee 上的优秀开源项目
4.  [GVP](https://gitee.com/gvp) 全称是 Gitee 最有价值开源项目，是综合评定出的优秀开源项目
5.  Gitee 官方提供的使用手册 [https://gitee.com/help](https://gitee.com/help)
6.  Gitee 封面人物是一档用来展示 Gitee 会员风采的栏目 [https://gitee.com/gitee-stars/](https://gitee.com/gitee-stars/)
