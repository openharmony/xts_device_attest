# device_attest部件<a name="ZH-CN_TOPIC_001"></a>

## 简介<a id="section100"></a>

device_attest，设备证明部件，是一个系统服务（SystemAbility）, 是OpenHarmony compatibility agreement约定需要设备厂商在产品中集成的部件，用于支撑生态伙伴完成产品的兼容性测试。其基本功能是看护OpenHarmony生态设备认证结果，通过端云校验机制，支撑OpenHarmony南北向生态统一，保障用户体验。该部件用于标准系统（standard system）。
生态伙伴（即设备厂商）兼容性测试工作流程：  
1、设备厂商在[OpenHarmony兼容性平台](https://openatom.cn/atomavatar/#/login?redirect=%2Fauthorize%3Fresponse_type%3Dcode%26client_id%3D6bdacef0a8bd11ec938bd9550d2decfd%26redirect_uri%3Dhttps%3A%2F%2Fcompatibility.openharmony.cn%2Fconsole%26appName%3DOpenHarmony%E8%AE%A4%E8%AF%81%E5%B9%B3%E5%8F%B0%26scope%3D0,1,2,3%26state%3D%2Fpersonal)注册企业账号，完成设备信息登记，将登记的设备信息写入设备，并完成依赖接口适配；  
2、设备厂商启动认证测试，上传xts测试报告；  
3、OpenHarmony认证云认证通过设备厂商产品信息，发放token到OpenHarmony兼容性平台；  
4、设备厂商从OpenHarmony兼容性平台获取token；  
5、设备厂商经三方产线将token烧录到OpenHarmony设备；  
6、设备证明部件与OpenHarmony认证云通信，对设备进行激活/认证，设备从OpenHarmony认证云获取认证结果，存储到本地；  
7、系统服务、系统应用等可通过设备证明部件提供的接口获取认证结果，并基于认证结果进行业务设计。  

工作流程图：
![](figures/image_002.png)

## 目录<a id="section200"></a>

```
/test/xts
├── device_attest               # 设备证明部件代码存放目录
│   └── build                   # 编译配置存放目录
│   └── common                  # 公共基础能力
│   └── figures                
│   └── interfaces              # 对外接口
│   └── sample                  # 对外接口示例
│   └── services                # 服务主体和业务逻辑代码
│       └── core                # 业务逻辑代码
│       └── devattest_ability   # 服务框架
│       └── etc                 # 启动配置文件存放目录
│       └── oem_adapter         # 设备厂商适配接口存放目录
│       └── sa_profile          # 进程配置文件存放目录
```

## 架构图<a id="section300"></a>

1、设备启动过程中，设备证明部件被init进程拉起，监控网络状态，设备联网后，读取token和系统参数，发起设备认证端云通信；  
2、端云通信采用https协议，设备证明部件将token和系统参数上传到OpenHarmony认证云，并获取认证结果和新token；  
3、设备证明部件将认证结果存储到沙箱目录，并更新token；  
4、设备证明部件对外提供认证结果查询接口，供其他模块判定设备是否已通过认证，比如系统服务、系统应用等。  

![](figures/image_001.png)

## 约束<a id="section400"></a>

**表 1 设备证明部件集成依赖库** 
| 库名称    | 版本号           | 功能描述                                        | 仓库路径                                     |
| --------- | ---------------- | ----------------------------------------------- | ---------------------------------------- |
| mbedtls   | 2.16.11          | 供嵌入式设备使用的一个 TLS 协议的轻量级实现库。 | third_party\mbedtls           |
| OpenSSL   | 1.1.1          | 传输层安全（TLS）协议（包括SSLv3）以及通用密码库。 | third_party\openssl           |
| cJSON     | 1.7.15           | JSON 文件解析库。                               | third_party\cJSON |
| libsec    | 1.1.10           | 安全函数库。                                    | bounds_checking_function      |
| parameter | OpenHarmony 1.0 release及之后版本 | 获取设备信息的系统接口。                        | base\startup\init\interfaces\innerkits\include\syspara\parameter.h                    |

## 对外接口<a id="section500"></a>

**表 2 设备证明部件对外接口**
| **接口名**                                              | **描述**     |
| ------------------------------------------------------- | ------------ |
| int32_t  GetAttestStatus(AttestResultInfo* attestResultInfo); | 获取设备认证结果 |

设备证明部件开机自启动，网络连接成功后，会进入设备证明部件主流程。通过调用GetAttestStatus接口，获取设备认证结果。  
调用可查看sample示例

## 编译指令<a id="section600"></a>
以rk3568为例
```sh
./build.sh --product-name=rk3568 system_size=standard
```
编译成功后会在out/rk3568/packages/phone/system/lib路径下生成libdevattest_core.z.so、libdevattest_sdk.z.so、libdevattest_service.z.so、libdevice_attest_oem_adapter.z.so四个动态库

## 相关仓<a id="section700"></a>

**xts\_device\_attest**

[xts\_device\_attest\_lite](https://gitee.com/openharmony-sig/xts_device_attest_lite/)