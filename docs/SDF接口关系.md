### SDF接口中，业务流程/依赖关系总结：

### 1.能返回公钥结构的函数

- SDF_ExportSignPublicKey_RSA
- SDF_ExportEncPublicKey_RSA

- SDF_ExportSignPublicKey_ECC
- SDF_ExportEncPublicKey_ECC

### 2.能返回会话密钥句柄的函数

- SDF_GenerateKeyWithIPK_RSA

- SDF_GenerateKeyWithEPK_RSA

- SDF_ImportKeyWithISK_RSA

- SDF_GenerateKeyWithIPK_ECC

  - 生成会话密钥并用内部ECC公钥加密

    **=>生成的会话密钥用于在内部系统的通信**

- SDF_GenerateKeyWithEPK_ECC

  - SDF_ExportEncPublicKey_ECC导出内部ECC加密公钥

    **=>模拟导出内部ECC公钥，作为外部公钥**

  - 用导入的外部公钥生成会话密钥

  - 将外部公钥导入，生成会话密钥

    **=>生成的会话密钥用于两个系统间通信**

- SDF_ImportKeyWithISK_ECC

  - SDF_ExportEncPublicKey_ECC导出内部ECC加密公钥

    **=>模拟导出内部ECC公钥，作为另一台设备的外部公钥**

  - SDF_GenerateKeyWithEPK_ECC用ECC加密公钥生成会话密钥

    **=>模拟另一台外部设备生成会话密钥**

  - SDF_GetPrivateKeyAccessRight获取内部私钥使用权限

  - 将模拟的外部会话密钥导入，并用内部ECC加密私钥进行解密，

    **=>获得对称加密密钥句柄，建立两个系统间的通信基础**

- SDF_GenerateKeyWithKEK

  - SDF_GetPrivateKeyAccessRight获取内部密钥加密密钥使用权

  - 生成会话密钥并用密钥加密密钥加密输出

    **=>生成的会话密钥用于系统内通信**

- SDF_ImportKeyWithKEK

  - SDF_GetPrivateKeyAccessRight获取内部密钥加密密钥的使用权

  - 导入会话密钥并用密钥加密密钥解密

    **=>导入会话密钥，建立系统内的通信基础**

- SDF_GenerateKeyWithECC(密钥协商)

  密钥协商完成后，协商句柄被销毁。返回会话密钥句柄。

  总流程：`GenerateKeyWithECC` 由**发起方**调用的。

  在SM2密钥协商流程中，发起方先调用 `GenerateAgreementDataWithECC` 生成自己的协商参数，响应方调用 `GenerateAgreementDataAndKeyWithECC` 生成自己的协商参数和会话密钥。

  然后，发起方收到响应方的协商参数后，调用 `GenerateKeyWithECC`，结合双方参数计算出会话密钥。

  - SDF_GenerateAgreementDataWithECC

    - SponsorID/SponsorIDLength：协商参数
    - ISKIndex/KeyBits：发送方长期公钥的索引/长度

    - **pSponsorPublicKey**：接口会自动填充为发起方的长期ECC公钥（由ISKIndex指定）。
    - **pSponsorTmpPublicKey**：接口会自动生成临时密钥对，并填充临时公钥。
    - &phAgreementHandle：协商句柄

  - SDF_GenerateAgreementDataAndKeyWithECC

    - 接收发送方的协商参数，发送接收方的协商参数，长期公钥，临时公钥
    - 接收会话密钥句柄

### 4.签名/验签的函数

- SDF_InternalSign_ECC
  - mock数据message[]
  - 获取内部私钥索引及使用权限(SDF_GetPrivateKeyAccessRight)
  - SDF_HashInit自动SM2预处理
  - SDF_HashUpdate
  - SDF_HashFinal
  - 将"SM2预处理+SM3”后的摘要用于签名/验签

- SDF_ExternalVerify_ECC

  - 获取外部ECC公钥ExportSignPublicKey_ECC

  - SDF_InternalSign_ECC准备好的签名

