# SDF接口

**已对齐[《GM/T 0018-2023》]([gmbz.org.cn/main/viewfile/20240628173907475462.html](http://www.gmbz.org.cn/main/viewfile/20240628173907475462.html))**

通过构建SDF抽象层，为密码库上层应用开发屏蔽厂商差异。标准的SDF接口现有73个。

**调用链关系(GmSSL)**
→ sdf.c 的便捷函数 
→ sdf_lib.c 的标准 SDF_* 
→ 方法表 SDF_METHOD 
→ 厂商动态库函数。

**调用链关系(Tongsuo)**

tsapi_lib.c 中的高层 TSAPI_ 函数
→ 调用 TSAPI_SDF_ 包装（声明见 sdf.h）
→ sdf_lib.c 的同名实现
→ sdf_get_method() 选取方法表：


### 设备管理类函数(8)
设备管理类函数提供设备打开与关闭、会话创建与关闭、设备信息获取、随机数产生、私钥权限获取与释放功能
- **SDF_OpenDevice**
	
- **SDF_CloseDevice**
	
- **SDF_OpenSession**
	
- **SDF_CloseSession**
	
- **SDF_GetDeviceInfo**
	
- **SDF_GenerateRandom**
	
- **SDF_GetPrivateKeyAccessRight**
	
- **SDF_ReleasePrivateKeyAccessRight**
### 密钥管理类函数(16)

- **SDF_ExportSignPublicKey_RSA**
导出RSA签名公钥
- **SDF_ExportEncPublic_RSA**
导出RSA加密公钥
- **SDF_GenerateKeyWithIPK_RSA**
生成会话密钥并用内部RSA公钥加密
- **SDF_GenerateKeyWithEPK_RSA**
生成会话密钥并用外部RSA公钥加密
- **SDF_ImportKeyWithISK_RSA**
导入会话密钥并用内部RSA私钥解密
- **SDF_ExportSignPublicKey_ECC**
导出ECC签名公钥
- **SDF_ExportEncPublicKey_ECC**
导出ECC加密公钥
- **SDF_GenerateKeyWithIPK_ECC**
生成会话密钥并用内部ECC公钥加密输出
- **SDF_GenerateKeyWithEPK_ECC**
生成会话密钥并用外部ECC公钥加密输出
- **SDF_ImportKeyWithISK_ECC**
导入会话密钥并用内部ECC私钥解密
- **SDF_GenerateAgreementDataWithECC**
生成密钥协商参数并输出
- **SDF_GenerateKeyWithECC**
计算会话密钥
- **SDF_GenerateAgreementDataAndKeyWithECC**
产生协商数据并计算会话密钥
- **SDF_GenerateKeyWithKEK**
生成会话密钥并用密钥加密密钥加密输出
- **SDF_ImportKeyWithKEK**
导入会话密钥并用密钥加密密钥解密
- **SDF_DestroyKey**
销毁会话密钥





### 非对称算法运算类函数(7)
非对称算法运算类函数提供RSA公私钥运算、ECC签名验证和加密功能

- **SDF_ExternalPublicKeyOperation_RSA**
  外部公钥RSA运算
- **SDF_InternalPublicKeyOperation_RSA**
  内部公钥RSA运算
- **SDF_InternalPrivateKeyOperation_RSA**
  内部私钥RSA运算
- **SDF_ExternalVerify_ECC**
  外部公钥ECC验证
- **SDF_InternalSign_ECC**
  内部私钥ECC签名
- **SDF_InternalVerify_ECC**
  内部公钥ECC验证
- **SDF_ExternalEncrypt_ECC**
  外部公钥ECC加密

### 对称算法运算类函数(20)
对称算法运算类函数提供对称加解密和MAC计算功能，产品支持可鉴别加解密时，可鉴别加解密相关接口函数应符合6.5.5、6.5.6及6.5.16~6.5.21的定义

- **SDF_Encrypt**

  单包对称加密

- **SDF_Decrypt**

  单包对称解密

- **SDF_CalculateMAC**

  计算单包MAC

- **SDF_AuthEnc**

  单包可鉴别加密

- **SDF_AuthDec**

  单包可鉴别解密

- **SDF_EncryptInit**

  多包对称加密初始化

- **SDF_EncryptUpdate**

  多包对称加密

- **SDF_EncryptFinal**

  多包对称加密结束

- **SDF_DncryptInit**

  多包对称解密初始化

- **SDF_DecryptUpdate**

  多包对称解密

- **SDF_DecryptFinal**

  多包对称解密结束

- **SDF_CalculateMACInit**

  多包MAC初始化

- **SDF_CalculateMACUpdate**

  多包MAC计算

- **SDF_CalculateMACFinal**

  多包MAC结束

- **SDF_AuthEncInit**

  多包可鉴别加密初始化

- **SDF_AuthEncUpdate**

  多包可鉴别加密

- **SDF_AuthEncFinal**

  多包可鉴别加密结束

- **SDF_AuthDecInit**

  多包可鉴别解密初始化

- **SDF_AuthDecUpdate**

  多包可鉴别解密

- **SDF_AuthDecFinal**

  多包可鉴别解密结束

  

### 杂凑运算类函数(6)
  杂凑运算类函数提供杂凑运算功能

- **SDF_HMACInit**
带密钥的杂凑运算初始化

- **SDF_HMACUpdate**
带密钥的多包杂凑运算

- **SDF_HMACFinal**
带密钥的杂凑运算结束

- **SDF_HashInit**
杂凑运算初始化

- **SDF_HashUpdate**
多包杂凑运算

- **SDF_HashFinal**
杂凑运算结束

  

### 用户文件操作类函数(4)
  用户文件操作类函数提供文件的创建、读写和删除功能

- **SDF_CreateFile**
创建文件
- **SDF_ReadFile**
读取文件
- **SDF_WriteFile**
写文件
- **SDF_DeleteFile**
删除文件

### 验证调试类函数(12)
  验证调试类函数仅用于在调试、测试、检测场景下对产品的算法和功能进行验证，不用于实际密码服务

- **SDF_GenerateKeyPair_RSA**
产生RSA非对称密钥对并输出
- **SDF_GenerateKeyPair_ECC**
产生ECC非对称密钥对并输出	
- **SDF_ExternalPrivateKeyOperation_RSA**
外部私钥RSA运算
- **SDF_ExternalSign_ECC**
外部私钥ECC签名
- **SDF_ExternalDecrypt_ECC**
外部私钥ECC解密
- **SDF_ExternalSign_SM9**
外部私钥SM9签名
- **SDF_ExternalDecrypt_SM9**
外部私钥SM9解密
- **SDF_ExternalKeyEncrypt**
外部密钥单包对称加密

- **SDF_ExternalKeyDecrypt**

   外部密钥对称解密

- **SDF_ExternalKeyEncryptInit**

  外部密钥多包对称加密初始化

- **SDF_ExternalKeyDecryptInit**

  外部密钥队报对称解密初始化

- **SDF_ExternalKeyHMACInit**

  带外部密钥的杂凑运算初始化