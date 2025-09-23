/*
* File: swsds.h
* Copyright (c) SWXA 2009
*
* v1.00.0001  2009.07.15   yaahao     
*/

#ifndef _SW_SDS_H_
#define _SW_SDS_H_ 1

#ifdef __cplusplus
	extern "C"{
#endif

#define GMT0018_2012		1

/*数据类型定义*/
typedef char				SGD_CHAR;
typedef char				SGD_INT8;
typedef short				SGD_INT16;
typedef int					SGD_INT32;
typedef long long			SGD_INT64;
typedef unsigned char		SGD_UCHAR;
typedef unsigned char		SGD_UINT8;
typedef unsigned short		SGD_UINT16;
typedef unsigned int		SGD_UINT32;
typedef unsigned long long	SGD_UINT64;
typedef unsigned int		SGD_RV;
typedef void*				SGD_OBJ;
typedef int					SGD_BOOL;
typedef void*				SGD_HANDLE;

/*设备信息*/
typedef struct DeviceInfo_st{
	unsigned char IssuerName[40];
	unsigned char DeviceName[16];
	unsigned char DeviceSerial[16];
	unsigned int  DeviceVersion;
	unsigned int  StandardVersion;
	unsigned int  AsymAlgAbility[2];
	unsigned int  SymAlgAbility;
	unsigned int  HashAlgAbility;
	unsigned int  BufferSize;
} DEVICEINFO;

/*设备信息*/
typedef struct DeviceInfoAll_st{
	unsigned char IssuerName[40];
	unsigned char DeviceName[16];    //国密认证型号 
	unsigned char DeviceSerial[16];
	unsigned int  DeviceVersion;
	unsigned int  StandardVersion;
	unsigned int  AsymAlgAbility[2];
	unsigned int  SymAlgAbility;
	unsigned int  HashAlgAbility;
	unsigned int  BufferSize;
	unsigned char SW_Serial[28];     //内部型号

}DEVICEINFOALL_INT;

/*RSA密钥*/
#define RSAref_MAX_BITS    2048
#define RSAref_MAX_LEN     ((RSAref_MAX_BITS + 7) / 8)
#define RSAref_MAX_PBITS   ((RSAref_MAX_BITS + 1) / 2)
#define RSAref_MAX_PLEN    ((RSAref_MAX_PBITS + 7)/ 8)

typedef struct RSArefPublicKey_st
{
	unsigned int  bits;
	unsigned char m[RSAref_MAX_LEN];
	unsigned char e[RSAref_MAX_LEN];
} RSArefPublicKey;

typedef struct RSArefPrivateKey_st
{
	unsigned int  bits;
	unsigned char m[RSAref_MAX_LEN];
	unsigned char e[RSAref_MAX_LEN];
	unsigned char d[RSAref_MAX_LEN];
	unsigned char prime[2][RSAref_MAX_PLEN];
	unsigned char pexp[2][RSAref_MAX_PLEN];
	unsigned char coef[RSAref_MAX_PLEN];
} RSArefPrivateKey;

#define ExRSAref_MAX_BITS		4096
#define ExRSAref_MAX_LEN		((ExRSAref_MAX_BITS + 7) / 8)
#define ExRSAref_MAX_PBITS		((ExRSAref_MAX_BITS + 1) / 2)
#define ExRSAref_MAX_PLEN		((ExRSAref_MAX_PBITS + 7) / 8)

typedef struct RSArefPublicKeyEx_st
{
	unsigned int  bits;
	unsigned char m[ExRSAref_MAX_LEN];
	unsigned char e[ExRSAref_MAX_LEN];
} RSArefPublicKeyEx;

typedef struct RSArefPrivateKeyEx_st
{
	unsigned int  bits;
	unsigned char m[ExRSAref_MAX_LEN];
	unsigned char e[ExRSAref_MAX_LEN];
	unsigned char d[ExRSAref_MAX_LEN];
	unsigned char prime[2][ExRSAref_MAX_PLEN];
	unsigned char pexp[2][ExRSAref_MAX_PLEN];
	unsigned char coef[ExRSAref_MAX_PLEN];
} RSArefPrivateKeyEx;


/*2012版密码设备应用接口规范ECC密钥数据结构定义*/

#define ECCref_MAX_BITS					512 
#define ECCref_MAX_LEN					((ECCref_MAX_BITS+7) / 8)
#define ECCref_MAX_CIPHER_LEN			136

typedef struct ECCrefPublicKey_st
{
	unsigned int  bits;
	unsigned char x[ECCref_MAX_LEN];
	unsigned char y[ECCref_MAX_LEN];
} ECCrefPublicKey;

typedef struct ECCrefPrivateKey_st
{
	unsigned int  bits;
	unsigned char K[ECCref_MAX_LEN];
} ECCrefPrivateKey;

/*ECC 密文*/
typedef struct ECCCipher_st
{
	unsigned char x[ECCref_MAX_LEN];
	unsigned char y[ECCref_MAX_LEN];
	unsigned char M[32];
	unsigned int  L;
	unsigned char C[1];
} ECCCipher;

/*ECC 签名*/
typedef struct ECCSignature_st
{
	unsigned char r[ECCref_MAX_LEN];
	unsigned char s[ECCref_MAX_LEN];
} ECCSignature;

#define SM9ref_MAX_BITS		256
#define SM9ref_MAX_LEN		((SM9ref_MAX_BITS+7) / 8)

#define MAX_SM9_ID_LENGTH					128

typedef struct SM9refSignMasterPrivateKey_st
{
	unsigned int bits;
	unsigned char s[SM9ref_MAX_LEN];
} SM9refSignMasterPrivateKey;

typedef struct SM9refSignMasterPublicKey_st
{
	unsigned int bits;
	unsigned char xa[SM9ref_MAX_LEN]; //X低维坐标
	unsigned char xb[SM9ref_MAX_LEN]; //X高维坐标
	unsigned char ya[SM9ref_MAX_LEN]; //Y低维坐标
	unsigned char yb[SM9ref_MAX_LEN]; //Y高维坐标
} SM9refSignMasterPublicKey;

typedef struct SM9refSignMasterKeyPair_st
{
	SM9refSignMasterPrivateKey MasterPrivateKey;
	SM9refSignMasterPublicKey MasterPublicKey;
	unsigned char MasterKeyPairG[1536];
} SM9refSignMasterKeyPair;

typedef struct SM9refEncMasterPrivateKey_st
{
	unsigned int bits;
	unsigned char s[SM9ref_MAX_LEN];
} SM9refEncMasterPrivateKey;

typedef struct SM9refEncMasterPublicKey_st
{
	unsigned int bits;
	unsigned char x[SM9ref_MAX_LEN];
	unsigned char y[SM9ref_MAX_LEN];
} SM9refEncMasterPublicKey;

typedef struct SM9refEncMasterKeyPair_st
{
	SM9refEncMasterPrivateKey MasterPrivateKey;
	SM9refEncMasterPublicKey MasterPublicKey;
	unsigned char MasterKeyPairG[384];
} SM9refEncMasterKeyPair;

typedef struct SM9refPublicUserID_st
{
	unsigned int IDLen;
	unsigned char ID[MAX_SM9_ID_LENGTH];
} SM9refPublicUserID;

typedef struct SM9refSignUserPrivateKey_st
{
	unsigned int bits;
	unsigned char x[SM9ref_MAX_LEN];
	unsigned char y[SM9ref_MAX_LEN];
} SM9refSignUserPrivateKey;

typedef struct SM9refSignUserKeyPair_st
{
	SM9refSignUserPrivateKey PrivateKey;
	SM9refPublicUserID PublicUserID;
} SM9refSignUserKeyPair;

typedef struct SM9refEncUserPrivateKey_st
{
	unsigned int bits;
	unsigned char xa[SM9ref_MAX_LEN]; //X低维坐标
	unsigned char xb[SM9ref_MAX_LEN]; //X高维坐标
	unsigned char ya[SM9ref_MAX_LEN]; //Y低维坐标
	unsigned char yb[SM9ref_MAX_LEN]; //Y高维坐标
} SM9refEncUserPrivateKey;

typedef struct SM9refEncUserKeyPair_st
{
	SM9refEncUserPrivateKey PrivateKey;
	SM9refPublicUserID PublicUserID;
} SM9refEncUserKeyPair;

typedef struct SM9Signature_st
{
	unsigned char h[SM9ref_MAX_LEN];
	unsigned char x[SM9ref_MAX_LEN];
	unsigned char y[SM9ref_MAX_LEN];
} SM9Signature;

typedef struct SM9Cipher_st
{
	unsigned char x[SM9ref_MAX_LEN];
	unsigned char y[SM9ref_MAX_LEN];
	unsigned char h[SM9ref_MAX_LEN];
	unsigned int L;
	unsigned char C[1024];
} SM9Cipher;

typedef struct SM9refKeyPackage_st
{
	unsigned char x[SM9ref_MAX_LEN];
	unsigned char y[SM9ref_MAX_LEN];
} SM9refKeyPackage;

typedef struct SM9AgreementParam_st
{
	SGD_UINT32 nHandleFlag;
	unsigned char pucRandom[32];
	unsigned int uiRandomLength;
	unsigned char pucRA[64];
	unsigned int uiRALength;
} SM9AgreementParam;

//超融合
typedef struct LMKComponent_st
{
	unsigned int ComID;
	unsigned int R1;
	unsigned char KCCipher[32];
	unsigned int KCLen;
	ECCSignature Signature;
	ECCCipher RKCipher;
}LMKComponent, *PLMKComponent;

//电科院
typedef struct EPRIMAC_Head_st
{
	unsigned int Length;
	unsigned char Context[16];
}EPRIMAC_Head;

/*常量定义*/

#define MAX_KEK_COUNT					1024
#define MAX_RSA_KEY_PAIR_COUNT			32
#define MAX_ECC_KEY_PAIR_COUNT			2048
#define MAX_KEY_INFO_COUNT				1024

#define USER_PIN_LENGTH					8    //IC卡PIN口令

#define MAX_DATA_LENGTH					65536
#define MAX_DATA_KB_LENGTH_STR			"64K"


#define SGD_TRUE		0x00000001
#define SGD_FALSE		0x00000000

/*算法标识*/

#define SGD_SM1_ECB		0x00000101
#define SGD_SM1_CBC		0x00000102
#define SGD_SM1_CFB		0x00000104
#define SGD_SM1_OFB		0x00000108
#define SGD_SM1_MAC		0x00000110
#define SGD_SM1_CTR		0x00000120

#define SGD_SSF33_ECB	0x00000201
#define SGD_SSF33_CBC	0x00000202
#define SGD_SSF33_CFB	0x00000204
#define SGD_SSF33_OFB	0x00000208
#define SGD_SSF33_MAC	0x00000210
#define SGD_SSF33_CTR	0x00000220

#define SGD_SMS4_ECB	0x00000401
#define SGD_SMS4_CBC	0x00000402
#define SGD_SMS4_CFB	0x00000404
#define SGD_SMS4_OFB	0x00000408
#define SGD_SMS4_MAC	0x00000410
#define SGD_SMS4_CTR	0x00000420
#define SGD_SMS4_XTS	0x00000440

#define SGD_SM4_ECB		0x00000401
#define SGD_SM4_CBC		0x00000402
#define SGD_SM4_CFB		0x00000404
#define SGD_SM4_OFB		0x00000408
#define SGD_SM4_MAC		0x00000410
#define SGD_SM4_CTR		0x00000420
#define SGD_SM4_XTS		0x00000440

#define SGD_ZUC_EEA3	0x00000801	//ZUC祖冲之机密性算法128-EEA3
#define SGD_ZUC_EIA3	0x00000802	//ZUC祖冲之完整性算法128-EIA3

#define SGD_SM7_ECB		0x00001001
#define SGD_SM7_CBC		0x00001002
#define SGD_SM7_CFB		0x00001004
#define SGD_SM7_OFB		0x00001008
#define SGD_SM7_MAC		0x00001010
#define SGD_SM7_CTR		0x00001020

#define SGD_DES_ECB		0x00002001
#define SGD_DES_CBC		0x00002002
#define SGD_DES_CFB		0x00002004
#define SGD_DES_OFB		0x00002008
#define SGD_DES_MAC		0x00002010
#define SGD_DES_CTR		0x00002020

#define SGD_3DES_ECB	0x00004001
#define SGD_3DES_CBC	0x00004002
#define SGD_3DES_CFB	0x00004004
#define SGD_3DES_OFB	0x00004008
#define SGD_3DES_MAC	0x00004010
#define SGD_3DES_CTR	0x00004020

#define SGD_AES_ECB		0x00008001
#define SGD_AES_CBC		0x00008002
#define SGD_AES_CFB		0x00008004
#define SGD_AES_OFB		0x00008008
#define SGD_AES_MAC		0x00008010
#define SGD_AES_CTR		0x00008020

#define SGD_SM6_ECB		0x00010001
#define SGD_SM6_CBC		0x00010002
#define SGD_SM6_CFB		0x00010004
#define SGD_SM6_OFB		0x00010008
#define SGD_SM6_MAC		0x00010010
#define SGD_SM6_CTR		0x00010020

#define SGD_RSA			0x00010000
#define SGD_RSA_SIGN	0x00010100
#define SGD_RSA_ENC		0x00010200

#define SGD_SM2			0x00020100
#define SGD_SM2_1		0x00020200
#define SGD_SM2_2		0x00020400
#define SGD_SM2_3		0x00020800

#define SGD_SM3			0x00000001
#define SGD_SHA1		0x00000002
#define SGD_SHA256		0x00000004
#define SGD_SHA512		0x00000008
#define SGD_SHA384		0x00000010
#define SGD_SHA224		0x00000020
#define SGD_MD5			0x00000080

#define SGD_SYMM_ALG_MASK		0xFFFFFF00
#define SGD_SYMM_ALG_MODE_MASK  0x000000FF

#define SGD_ASYMM_ALG_MASK		0xFFFF0000


/*标准错误码定义*/
#define SDR_OK					0x0						   /*成功*/
#define SDR_BASE				0x01000000
#define SDR_UNKNOWERR			(SDR_BASE + 0x00000001)	   /*未知错误*/
#define SDR_NOTSUPPORT			(SDR_BASE + 0x00000002)	   /*不支持*/
#define SDR_COMMFAIL			(SDR_BASE + 0x00000003)    /*通信错误*/
#define SDR_HARDFAIL			(SDR_BASE + 0x00000004)    /*硬件错误*/
#define SDR_OPENDEVICE			(SDR_BASE + 0x00000005)    /*打开设备错误*/
#define SDR_OPENSESSION			(SDR_BASE + 0x00000006)    /*打开会话句柄错误*/
#define SDR_PARDENY				(SDR_BASE + 0x00000007)    /*权限不满足*/
#define SDR_KEYNOTEXIST			(SDR_BASE + 0x00000008)    /*密钥不存在*/
#define SDR_ALGNOTSUPPORT		(SDR_BASE + 0x00000009)    /*不支持的算法*/
#define SDR_ALGMODNOTSUPPORT	(SDR_BASE + 0x0000000A)    /*不支持的算法模式*/
#define SDR_PKOPERR				(SDR_BASE + 0x0000000B)    /*公钥运算错误*/
#define SDR_SKOPERR				(SDR_BASE + 0x0000000C)    /*私钥运算错误*/
#define SDR_SIGNERR				(SDR_BASE + 0x0000000D)    /*签名错误*/
#define SDR_VERIFYERR			(SDR_BASE + 0x0000000E)    /*验证错误*/
#define SDR_SYMOPERR			(SDR_BASE + 0x0000000F)    /*对称运算错误*/
#define SDR_STEPERR				(SDR_BASE + 0x00000010)    /*步骤错误*/
#define SDR_FILESIZEERR			(SDR_BASE + 0x00000011)    /*文件大小错误或输入数据长度非法*/
#define SDR_FILENOEXIST			(SDR_BASE + 0x00000012)    /*文件不存在*/
#define SDR_FILEOFSERR			(SDR_BASE + 0x00000013)    /*文件操作偏移量错误*/
#define SDR_KEYTYPEERR			(SDR_BASE + 0x00000014)    /*密钥类型错误*/
#define SDR_KEYERR				(SDR_BASE + 0x00000015)    /*密钥错误*/

/*============================================================*/
/*扩展错误码*/
#define SWR_BASE				(SDR_BASE + 0x00010000)	/*自定义错误码基础值*/
#define SWR_INVALID_USER		(SWR_BASE + 0x00000001)	/*无效的用户名*/
#define SWR_INVALID_AUTHENCODE	(SWR_BASE + 0x00000002)	/*无效的授权码*/
#define SWR_PROTOCOL_VER_ERR	(SWR_BASE + 0x00000003)	/*不支持的协议版本*/
#define SWR_INVALID_COMMAND		(SWR_BASE + 0x00000004)	/*错误的命令字*/
#define SWR_INVALID_PARAMETERS	(SWR_BASE + 0x00000005)	/*参数错误或错误的数据包格式*/
#define SWR_FILE_ALREADY_EXIST	(SWR_BASE + 0x00000006)	/*已存在同名文件*/
#define SWR_SYNCH_ERR			(SWR_BASE + 0x00000007)	/*多卡同步错误*/
#define SWR_SYNCH_LOGIN_ERR		(SWR_BASE + 0x00000008)	/*多卡同步后登录错误*/

#define SWR_SOCKET_TIMEOUT		(SWR_BASE + 0x00000100)	/*超时错误*/
#define SWR_CONNECT_ERR			(SWR_BASE + 0x00000101)	/*连接服务器错误*/
#define SWR_SET_SOCKOPT_ERR		(SWR_BASE + 0x00000102)	/*设置Socket参数错误*/
#define SWR_SOCKET_SEND_ERR		(SWR_BASE + 0x00000104)	/*发送LOGINRequest错误*/
#define SWR_SOCKET_RECV_ERR		(SWR_BASE + 0x00000105)	/*发送LOGINRequest错误*/
#define SWR_SOCKET_RECV_0		(SWR_BASE + 0x00000106)	/*发送LOGINRequest错误*/

#define SWR_SEM_TIMEOUT			(SWR_BASE + 0x00000200)	/*超时错误*/
#define SWR_NO_AVAILABLE_HSM	(SWR_BASE + 0x00000201)	/*没有可用的加密机*/
#define SWR_NO_AVAILABLE_CSM	(SWR_BASE + 0x00000202)	/*加密机内没有可用的加密模块*/

#define SWR_CONFIG_ERR			(SWR_BASE + 0x00000301)	/*配置文件错误*/

/*============================================================*/
/*密码卡错误码*/
#define SWR_CARD_BASE					(SDR_BASE + 0x00020000)			/*密码卡错误码*/
#define SWR_CARD_UNKNOWERR				(SWR_CARD_BASE + 0x00000001)	//未知错误
#define SWR_CARD_NOTSUPPORT				(SWR_CARD_BASE + 0x00000002)	//不支持的接口调用
#define SWR_CARD_COMMFAIL				(SWR_CARD_BASE + 0x00000003)	//与设备通信失败
#define SWR_CARD_HARDFAIL				(SWR_CARD_BASE + 0x00000004)	//运算模块无响应
#define SWR_CARD_OPENDEVICE				(SWR_CARD_BASE + 0x00000005)	//打开设备失败
#define SWR_CARD_OPENSESSION			(SWR_CARD_BASE + 0x00000006)	//创建会话失败
#define SWR_CARD_PARDENY				(SWR_CARD_BASE + 0x00000007)	//无私钥使用权限
#define SWR_CARD_KEYNOTEXIST			(SWR_CARD_BASE + 0x00000008)	//不存在的密钥调用
#define SWR_CARD_ALGNOTSUPPORT			(SWR_CARD_BASE + 0x00000009)	//不支持的算法调用
#define SWR_CARD_ALGMODNOTSUPPORT		(SWR_CARD_BASE + 0x00000010)	//不支持的算法调用
#define SWR_CARD_PKOPERR				(SWR_CARD_BASE + 0x00000011)	//公钥运算失败
#define SWR_CARD_SKOPERR				(SWR_CARD_BASE + 0x00000012)	//私钥运算失败
#define SWR_CARD_SIGNERR				(SWR_CARD_BASE + 0x00000013)	//签名运算失败
#define SWR_CARD_VERIFYERR				(SWR_CARD_BASE + 0x00000014)	//验证签名失败
#define SWR_CARD_SYMOPERR				(SWR_CARD_BASE + 0x00000015)	//对称算法运算失败
#define SWR_CARD_STEPERR				(SWR_CARD_BASE + 0x00000016)	//多步运算步骤错误
#define SWR_CARD_FILESIZEERR			(SWR_CARD_BASE + 0x00000017)	//文件长度超出限制
#define SWR_CARD_FILENOEXIST			(SWR_CARD_BASE + 0x00000018)	//指定的文件不存在
#define SWR_CARD_FILEOFSERR				(SWR_CARD_BASE + 0x00000019)	//文件起始位置错误
#define SWR_CARD_KEYTYPEERR				(SWR_CARD_BASE + 0x00000020)	//密钥类型错误
#define SWR_CARD_KEYERR					(SWR_CARD_BASE + 0x00000021)	//密钥错误
#define SWR_CARD_BUFFER_TOO_SMALL		(SWR_CARD_BASE + 0x00000101)	//接收参数的缓存区太小
#define SWR_CARD_DATA_PAD				(SWR_CARD_BASE + 0x00000102)	//数据没有按正确格式填充，或解密得到的脱密数据不符合填充格式
#define SWR_CARD_DATA_SIZE				(SWR_CARD_BASE + 0x00000103)	//明文或密文长度不符合相应的算法要求
#define SWR_CARD_CRYPTO_NOT_INIT		(SWR_CARD_BASE + 0x00000104)	//该错误表明没有为相应的算法调用初始化函数

#define SWR_CARD_PUBKEY					(SWR_CARD_BASE + 0x80000007)	//SM2公钥错误

//01/03/09版密码卡权限管理错误码
#define SWR_CARD_MANAGEMENT_DENY		(SWR_CARD_BASE + 0x00001001)	//管理权限不满足
#define SWR_CARD_OPERATION_DENY			(SWR_CARD_BASE + 0x00001002)	//操作权限不满足
#define SWR_CARD_DEVICE_STATUS_ERR		(SWR_CARD_BASE + 0x00001003)	//当前设备状态不满足现有操作
#define SWR_CARD_LOGIN_ERR				(SWR_CARD_BASE + 0x00001011)	//登录失败
#define SWR_CARD_USERID_ERR				(SWR_CARD_BASE + 0x00001012)	//用户ID数目/号码错误
#define SWR_CARD_PARAMENT_ERR			(SWR_CARD_BASE + 0x00001013)	//参数错误

//05/06版密码卡权限管理错误码
#define SWR_CARD_MANAGEMENT_DENY_05		(SWR_CARD_BASE + 0x00000801)	//管理权限不满足
#define SWR_CARD_OPERATION_DENY_05		(SWR_CARD_BASE + 0x00000802)	//操作权限不满足
#define SWR_CARD_DEVICE_STATUS_ERR_05	(SWR_CARD_BASE + 0x00000803)	//当前设备状态不满足现有操作
#define SWR_CARD_LOGIN_ERR_05			(SWR_CARD_BASE + 0x00000811)	//登录失败
#define SWR_CARD_USERID_ERR_05			(SWR_CARD_BASE + 0x00000812)	//用户ID数目/号码错误
#define SWR_CARD_PARAMENT_ERR_05		(SWR_CARD_BASE + 0x00000813)	//参数错误

/*============================================================*/
/*读卡器错误*/
#define SWR_CARD_READER_BASE				(SDR_BASE + 0x00030000)	//	读卡器类型错误
#define SWR_CARD_READER_PIN_ERROR			(SWR_CARD_READER_BASE + 0x000063CE)  //口令错误
#define SWR_CARD_READER_NO_CARD				(SWR_CARD_READER_BASE + 0x0000FF01)	 //	IC未插入
#define SWR_CARD_READER_CARD_INSERT			(SWR_CARD_READER_BASE + 0x0000FF02)	 //	IC插入方向错误或不到位
#define SWR_CARD_READER_CARD_INSERT_TYPE	(SWR_CARD_READER_BASE + 0x0000FF03)	 //	IC类型错误

/*============================================================*/
//电科院定制扩展错误码
#define EPRI_BASE					(SDR_BASE + 0x00050000)  //电科院定制拓展
#define EPRI_PLAINK0INDEX			(EPRI_BASE + 0x00000001) //K0索引不正确
#define EPRI_K0NOTEXIST			    (EPRI_BASE + 0x00000002) //K0不存在
#define EPRI_KEYLENERR				(EPRI_BASE + 0x00000003) //密钥长度错误
#define EPRI_KEYINDEXERR			(EPRI_BASE + 0x00000004) //密钥索引超出范围
#define EPRI_KEYPADDINGERR			(EPRI_BASE + 0x00000005) //密钥补丁格式错误
#define EPRI_NOTEXPORT				(EPRI_BASE + 0x00000006) //不支持导出
#define EPRI_MUSTDECENT				(EPRI_BASE + 0x00000007) //密钥必须分散
#define EPRI_NOTENCRPTKEY			(EPRI_BASE + 0x00000008) //不具备普通、加密属性
#define EPRI_NOTDECRPTKEY			(EPRI_BASE + 0x00000009) //不具备普通、解密属性
#define EPRI_MACVERIFYERR			(EPRI_BASE + 0x0000000a) //MAC验证错误
#define EPRI_PUBKEYSTORAGEERR		(EPRI_BASE + 0x0000000b) //更新SM2密钥公钥存储错误
#define EPRI_KEYEXIST				(EPRI_BASE + 0x0000000c) //密钥已存在
#define EPRI_MALLOCERR				(EPRI_BASE + 0x0000000d) //申请内存出错

/*设备管理类函数*/
SGD_RV SDF_OpenDevice(SGD_HANDLE *phDeviceHandle);
SGD_RV SDF_CloseDevice(SGD_HANDLE hDeviceHandle);
SGD_RV SDF_OpenSession(SGD_HANDLE hDeviceHandle, SGD_HANDLE *phSessionHandle);
SGD_RV SDF_CloseSession(SGD_HANDLE hSessionHandle);
SGD_RV SDF_GetDeviceInfo(SGD_HANDLE hSessionHandle, DEVICEINFO *pstDeviceInfo);
SGD_RV SDF_GenerateRandom(SGD_HANDLE hSessionHandle, SGD_UINT32  uiLength, SGD_UCHAR *pucRandom);
SGD_RV SDF_GetPrivateKeyAccessRight(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex,SGD_UCHAR *pucPassword, SGD_UINT32  uiPwdLength);
SGD_RV SDF_ReleasePrivateKeyAccessRight(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex);
SGD_RV SDF_GetFirmwareVersion(SGD_HANDLE hSessionHandle, SGD_UCHAR * sFirmware, SGD_UINT32 * ulFirmwareLen);
SGD_RV SDF_GetLibraryVersion(SGD_HANDLE hSessionHandle, SGD_UCHAR * sLibraryVersion, SGD_UINT32 * ulLibraryVersionLen);

/*密钥管理类函数*/
SGD_RV SDF_GenerateKeyPair_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyBits, RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey);
SGD_RV SDF_ExportSignPublicKey_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex, RSArefPublicKey *pucPublicKey);
SGD_RV SDF_ExportEncPublicKey_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex, RSArefPublicKey *pucPublicKey);
SGD_RV SDF_GenerateKeyWithIPK_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiIPKIndex, SGD_UINT32 uiKeyBits, SGD_UCHAR *pucKey, SGD_UINT32 *puiKeyLength, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_GenerateKeyWithEPK_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits, RSArefPublicKey *pucPublicKey, SGD_UCHAR *pucKey, SGD_UINT32 *puiKeyLength, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_ImportKeyWithISK_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_ExchangeDigitEnvelopeBaseOnRSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, RSArefPublicKey *pucPublicKey, SGD_UCHAR *pucDEInput, SGD_UINT32 uiDELength, \
										  SGD_UCHAR *pucDEOutput, SGD_UINT32  *puiDELength);

SGD_RV SDF_ImportKey(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_DestroyKey(SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle);
SGD_RV SDF_GetSymmKeyHandle(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_GenerateKeyWithKEK(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits, SGD_UINT32 uiAlgID,SGD_UINT32 uiKEKIndex, SGD_UCHAR *pucKey, SGD_UINT32 *puiKeyLength, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_ImportKeyWithKEK(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, SGD_UINT32 uiKEKIndex, SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength, SGD_HANDLE *phKeyHandle);

SGD_RV SDF_GenerateKeyPair_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID,SGD_UINT32  uiKeyBits, ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey);
SGD_RV SDF_ExportSignPublicKey_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex, ECCrefPublicKey *pucPublicKey);
SGD_RV SDF_ExportEncPublicKey_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32  uiKeyIndex, ECCrefPublicKey *pucPublicKey);
SGD_RV SDF_GenerateAgreementDataWithECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UINT32 uiKeyBits, SGD_UCHAR *pucSponsorID, SGD_UINT32 uiSponsorIDLength, \
										ECCrefPublicKey *pucSponsorPublicKey, ECCrefPublicKey *pucSponsorTmpPublicKey, SGD_HANDLE *phAgreementHandle);
SGD_RV SDF_GenerateKeyWithECC(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucResponseID, SGD_UINT32 uiResponseIDLength, ECCrefPublicKey *pucResponsePublicKey, \
							  ECCrefPublicKey *pucResponseTmpPublicKey, SGD_HANDLE hAgreementHandle, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_GenerateAgreementDataAndKeyWithECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UINT32 uiKeyBits, SGD_UCHAR *pucResponseID, SGD_UINT32 uiResponseIDLength, \
											  SGD_UCHAR *pucSponsorID, SGD_UINT32 uiSponsorIDLength, ECCrefPublicKey *pucSponsorPublicKey, ECCrefPublicKey *pucSponsorTmpPublicKey, \
											  ECCrefPublicKey  *pucResponsePublicKey, ECCrefPublicKey  *pucResponseTmpPublicKey, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_GenerateKeyWithIPK_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiIPKIndex, SGD_UINT32 uiKeyBits, ECCCipher *pucKey, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_GenerateKeyWithEPK_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, ECCCipher *pucKey, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_ImportKeyWithISK_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, ECCCipher *pucKey, SGD_HANDLE *phKeyHandle);
SGD_RV SDF_ExchangeDigitEnvelopeBaseOnECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, ECCCipher *pucEncDataIn, \
										  ECCCipher *pucEncDataOut);

/*非对称密码运算函数*/
SGD_RV SDF_ExternalPublicKeyOperation_RSA(SGD_HANDLE hSessionHandle, RSArefPublicKey *pucPublicKey, SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength, SGD_UCHAR *pucDataOutput, \
										  SGD_UINT32 *puiOutputLength);
SGD_RV SDF_ExternalPrivateKeyOperation_RSA(SGD_HANDLE hSessionHandle, RSArefPrivateKey *pucPrivateKey, SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength, SGD_UCHAR *pucDataOutput, \
										   SGD_UINT32 *puiOutputLength);
#ifndef GMT0018_2012
SGD_RV SDF_InternalPublicKeyOperation_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UINT32 uiKeyUsage, SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength, \
	SGD_UCHAR *pucDataOutput, SGD_UINT32  *puiOutputLength);
SGD_RV SDF_InternalPrivateKeyOperation_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UINT32 uiKeyUsage, SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength, \
	SGD_UCHAR *pucDataOutput, SGD_UINT32 *puiOutputLength);
#else
SGD_RV SDF_InternalPublicKeyOperation_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength, \
	SGD_UCHAR *pucDataOutput, SGD_UINT32  *puiOutputLength);
SGD_RV SDF_InternalPrivateKeyOperation_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength, \
	SGD_UCHAR *pucDataOutput, SGD_UINT32 *puiOutputLength);
SGD_RV SDF_InternalPublicKeyOperation_RSA_Ex(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UINT32 uiKeyUsage, SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength, \
	SGD_UCHAR *pucDataOutput, SGD_UINT32  *puiOutputLength);
SGD_RV SDF_InternalPrivateKeyOperation_RSA_Ex(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UINT32 uiKeyUsage, SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength, \
	SGD_UCHAR *pucDataOutput, SGD_UINT32 *puiOutputLength);
#endif
SGD_RV SDF_ExternalSign_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPrivateKey *pucPrivateKey, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCSignature *pucSignature);
SGD_RV SDF_ExternalVerify_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, SGD_UCHAR *pucDataInput, SGD_UINT32 uiInputLength, ECCSignature *pucSignature);
SGD_RV SDF_InternalSign_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCSignature *pucSignature);
SGD_RV SDF_InternalVerify_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCSignature *pucSignature);
SGD_RV SDF_ExternalEncrypt_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCCipher *pucEncData);
SGD_RV SDF_ExternalDecrypt_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPrivateKey *pucPrivateKey, ECCCipher *pucEncData, SGD_UCHAR *pucData, SGD_UINT32 *puiDataLength);
SGD_RV SDF_InternalEncrypt_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiIPKIndex, SGD_UINT32 uiAlgID, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, ECCCipher *pucEncData);
SGD_RV SDF_InternalDecrypt_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UINT32 uiAlgID, ECCCipher *pucEncData, SGD_UCHAR *pucData, SGD_UINT32 *puiDataLength);

/*对称密码运算函数*/
SGD_RV SDF_Encrypt(SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, SGD_UCHAR *pucEncData, \
				   SGD_UINT32 *puiEncDataLength);
SGD_RV SDF_Decrypt(SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV, SGD_UCHAR *pucEncData, SGD_UINT32 uiEncDataLength, SGD_UCHAR *pucData, \
				   SGD_UINT32 *puiDataLength);
SGD_RV SDF_CalculateMAC(SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle, SGD_UINT32 uiAlgID, SGD_UCHAR *pucIV, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, SGD_UCHAR *pucMAC, \
						SGD_UINT32 *puiMACLength);

/*杂凑运算函数*/
SGD_RV SDF_HashInit(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, ECCrefPublicKey *pucPublicKey, SGD_UCHAR *pucID, SGD_UINT32 uiIDLength);
SGD_RV SDF_HashUpdate(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength);
SGD_RV SDF_HashFinal(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucHash, SGD_UINT32 *puiHashLength);

/*HMAC运算函数*/
SGD_RV SDF_CalculateHMAC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, SGD_UCHAR *pucKey, SGD_UINT32 uiKeyLength, SGD_UCHAR *pucData, SGD_UINT32 uiDataLength, SGD_UCHAR *pucMAC, SGD_UINT32 *puiMACLength);
SGD_RV SDF_HMAC_Init(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID, SGD_UINT32 uiKeyIndex, SGD_UCHAR* pucKey, SGD_UINT32 uiKeyLength);
SGD_RV SDF_HMAC_Update(SGD_HANDLE hSessionHandle, SGD_UCHAR* pucData, SGD_UINT32 uiDataLength);
SGD_RV SDF_HMAC_Final(SGD_HANDLE hSessionHandle, SGD_UCHAR* pucMAC, SGD_UINT32* puiMACLength);

/*用户文件操作函数*/
SGD_RV SDF_CreateFile(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucFileName, SGD_UINT32 uiNameLen, SGD_UINT32 uiFileSize);
SGD_RV SDF_ReadFile(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucFileName, SGD_UINT32 uiNameLen, SGD_UINT32 uiOffset, SGD_UINT32 *puiReadLength, SGD_UCHAR *pucBuffer);
SGD_RV SDF_WriteFile(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucFileName, SGD_UINT32 uiNameLen, SGD_UINT32 uiOffset, SGD_UINT32 uiWriteLength, SGD_UCHAR *pucBuffer);
SGD_RV SDF_DeleteFile(SGD_HANDLE hSessionHandle, SGD_UCHAR *pucFileName, SGD_UINT32 uiNameLen);

/*SM9算法运算接口*/
int SDF_GenerateSignMasterPrivateKey_SM9(void *hSessionHandle, unsigned int uiKeyBits, SM9refSignMasterPublicKey *pucPublicKey,
	SM9refSignMasterPrivateKey *pucPrivateKey, unsigned char *pucPairG, unsigned int *puiPairGLen);
int SDF_GenerateEncMasterPrivateKey_SM9(void *hSessionHandle, unsigned int uiKeyBits, SM9refEncMasterPublicKey *pucPublicKey,
	SM9refEncMasterPrivateKey *pucPrivateKey,
	unsigned char *pucPairG,
	unsigned int *puiPairGLen);
int SDF_ExportSignMasterPublicKey_SM9(void *hSessionHandle, unsigned int uiKeyIndex, SM9refSignMasterPublicKey *pucPublicKey);
int SDF_ExportEncMasterPublicKey_SM9(void *hSessionHandle, unsigned int uiKeyIndex, SM9refEncMasterPublicKey *pucPublicKey);
int SDF_ExportSignMasterKeyPairG_SM9(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucPairG, unsigned int *puiPairGLen);
int SDF_ExportEncMasterKeyPairG_SM9(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucPairG, unsigned int *puiPairGLen);
int SDF_GenerateSignUserPrivateKey_SM9(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char hid, unsigned char *pucUserID, unsigned int uiUserIDLen,
	SM9refSignUserPrivateKey *pucPrivateKey);
int SDF_GenerateEncUserPrivateKey_SM9(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char hid, unsigned char *pucUserID, unsigned int uiUserIDLen,
	SM9refEncUserPrivateKey *pucPrivateKey);
int SDF_Sign_SM9(void *hSessionHandle, unsigned int uiKeyIndex, SM9refSignUserPrivateKey *pucPrivateKey,
	SM9refSignMasterPublicKey *pucMasterPublicKey, unsigned char *pucData, unsigned int uiDataLength, SM9Signature *pucSignature);
int SDF_Verify_SM9(void * hSessionHandle, unsigned char hid, unsigned char *pucUserID, unsigned int uiUserIDLen,
	SM9refSignMasterPublicKey *pucMasterPublicKey, unsigned char *pucData, unsigned int uiDataLength, SM9Signature *pucSignature);
int SDF_SignEx_SM9(void *hSessionHandle, unsigned int uiKeyIndex, SM9refSignUserPrivateKey *pucPrivateKey, SM9refSignMasterPublicKey *pucMasterPublicKey,
	unsigned char *pucPairG, unsigned int uiPairGLen, unsigned char *pucData, unsigned int uiDataLength, SM9Signature *pucSignature);
int SDF_VerifyEx_SM9(void *hSessionHandle, unsigned char hid, unsigned char *pucUserID, unsigned int uiUserIDLen, SM9refSignMasterPublicKey *pucMasterPublicKey,
	unsigned char *pucPairG, unsigned int uiPairGLen, unsigned char *pucData, unsigned int uiDataLength, SM9Signature *pucSignature);
int SDF_Encrypt_SM9(void *hSessionHandle, unsigned int uiEncMode, unsigned char hid, unsigned char *pucUserID, unsigned int uiUserIDLen, SM9refEncMasterPublicKey *pucMasterPublicKey,
	unsigned char *pucData, unsigned int uiDataLength, SM9Cipher *pucCipher);
int SDF_Decrypt_SM9(void *hSessionHandle, unsigned int uiEncMode, unsigned char *pucUserID, unsigned int uiUserIDLen, unsigned int uiKeyIndex, SM9refEncUserPrivateKey *pucPrivateKey,
	SM9Cipher *pucCipher, unsigned char *pucPlainData, unsigned int *puiPlainDataLength);
int SDF_EncryptEx_SM9(void *hSessionHandle, unsigned int uiEncMode, unsigned char hid, unsigned char *pucUserID, unsigned int uiUserIDLen, SM9refEncMasterPublicKey *pucMasterPublicKey,
	unsigned char *pucPairG, unsigned int uiPairGLen, unsigned char *pucData, unsigned int uiDataLength, SM9Cipher *pucCipher);
int SDF_Encap_SM9(void *hSessionHandle, unsigned char hid, unsigned char *pucUserID, unsigned int uiUserIDLen, SM9refEncMasterPublicKey *pucMasterPublicKey,
	unsigned int uiKeyLen, unsigned char *pucKey, SM9refKeyPackage *pucKeyPackage);
int SDF_Decap_SM9(void *hSessionHandle, unsigned char *pucUserID, unsigned int uiUserIDLen, unsigned int uiKeyIndex, SM9refEncUserPrivateKey *pucPrivateKey,
	SM9refKeyPackage *pucKeyPackage, unsigned int uiKeyLen, unsigned char *pucKey);
int SDF_GenerateAgreementDataWithSM9(void *hSessionHandle, unsigned char hid, unsigned char *pucResponseID, unsigned int uiResponseIDLength, SM9refEncMasterPublicKey *pucPublicKey,
	SM9refEncMasterPublicKey *pucTmpPublicKey, void **phAgreementHandle);
int SDF_GenerateAgreementDataAndKeyWithSM9(void *hSessionHandle, unsigned int uiKeyLen, unsigned char hid, unsigned char *pucResponseID, unsigned int uiResponseIDLen,
	unsigned char *pucSponsorID, unsigned int uiSponsorIDLen, unsigned int uiKeyIndex, SM9refEncUserPrivateKey *pucResponsePrivateKey, SM9refEncMasterPublicKey *pucPublicKey,
	SM9refEncMasterPublicKey *pucSponsorTmpPublicKey, SM9refEncMasterPublicKey *pucResponseTmpPublicKey, unsigned char *pucHashSB, unsigned int *puiSBLen, unsigned char *pucHashS2,
	unsigned int *puiS2Len, void **phKeyHandle);
int SDF_GenerateKeyWithSM9(void *hSessionHandle, unsigned int uiKeyLen, unsigned char hid, unsigned char *pucSponsorID, unsigned int uiSponsorIDLength,
	unsigned char *pucResponseID, unsigned int uiResponseIDLength, unsigned int uiKeyIndex, SM9refEncUserPrivateKey *pucSponsorPrivateKey, SM9refEncMasterPublicKey *pucPublicKey,
	SM9refEncMasterPublicKey *pucResponseTmpPublicKey, unsigned char *pucHashSB, unsigned int uiSBLen, unsigned char *pucHashSA, unsigned int *puiSALen, void *hAgreementHandle, 
	void **phKeyHandle);
int SDF_GenerateKeyVerifySM9(void *hSessionHandle, unsigned char *pucHashS2, unsigned int uiS2Len, unsigned char *pucHashSA, unsigned int uiSALen);

#ifdef __cplusplus
}
#endif

#endif /*#ifndef _SW_SDS_H_*/