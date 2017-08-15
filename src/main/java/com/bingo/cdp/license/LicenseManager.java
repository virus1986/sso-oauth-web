package com.bingo.cdp.license;

import java.io.File;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;

import org.apache.commons.codec.binary.Base64;

import com.bingo.cdp.exception.LicenseContentException;
import com.bingo.cdp.util.DateUtil;
import com.bingo.cdp.util.EValidationResult;
import com.bingo.cdp.util.FileUtil;
import com.bingo.cdp.util.LicensePropertiesUtil;
import com.bingo.cdp.util.RSACoder;

/**
 * license管理类，包含license创建、验证等功能
 *
 * @author mason
 *
 */
public class LicenseManager {

    /**
     * 需要调用者实现的处理接口
     */
    private IHandler4License handler4License;
    /**
     * 证书内容
     */
    private LicenseContent content;

    /**
     * 构造函数，根据传入的文件会构建license内容
     *
     * @param licenseFile
     *            license文件
     * @param handler4License
     *            处理接口
     * @throws Exception
     *             创建license内容时抛出的异常
     */
    public LicenseManager(File licenseFile,IHandler4License handler4License) throws Exception {
        this.handler4License = handler4License;
        madeLicenseContentFromFile(licenseFile);
    }

    /**
     * 获取License的内容
     * @return
     */
    public LicenseContent getLicense(){
        return content;
    }

    /**
     * 设置License的验证处理器
     * @param handler4License
     */
    public void setLicenseVerifyHandler(IHandler4License handler4License){
        this.handler4License = handler4License;
    }

    /**
     * 已编码的公钥字符串，用于生成公钥
     */
    private static final String publicKeyEncodedStr = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCXc5PQ/sksWv4QBY7sUPR8QrPCjfqyF6eMgBDSHONocnyDx5stQB2vWEe2U55t73jygeJxFAOgeCdaWnCH3XlKu6QoRFIN3wakTN9A+1dWjrwHcOIECU0fci9P5evK15K5uQ3pmK+YlrlsFUYTgHKK2li481kWnf1V0LLPaUMHYwIDAQAB";

    /**
     * 根据参数创建license
     *
     * @param privateKeyEncodedStr
     *            私钥字符串
     * @param customName
     *            用户名称
     * @param licenseType
     *            license类型
     * @param expirationDate
     *            试用结束日期
     * @param userAmount
     *            用户数
     * @param dbUrl
     *            数据库连接地址
     * @throws Exception
     *             异常处理
     */
    public static LicenseContent create(String privateKeyEncodedStr, String customName, String licenseType,
                                        Date expirationDate, int userAmount,String dbUrl,String sql) throws Exception {
        // private key 不能为null
        if (privateKeyEncodedStr == null || privateKeyEncodedStr.isEmpty()) {
            throw new LicenseContentException("private key is null");
        }

        // 构建证书内容
        LicenseContent content = new LicenseContent();
        content.setCustomName(customName);
        content.setLicenseType(licenseType);
        content.setIssuedDate(DateUtil.yyyy_MM_dd2String(new Date()));
        content.setExpirationDate(DateUtil.yyyy_MM_dd2String(expirationDate));
        content.setUserAmount(userAmount);
        content.setDbUrl(dbUrl);
        content.setSql(sql);
        // 默认未验证
        content.setValid(false);
        content.seteValidationResult(EValidationResult.NOT_VALID_YET);

        // 验证用户输入的内容
        EValidationResult ev = validate4LicenseCreate(content);
        // 若不是NOT_VALID_YET，则抛出异常
        if (!ev.equals(EValidationResult.NOT_VALID_YET)) {
            throw new LicenseContentException(ev.toString());
        }
        // 获取私钥
        byte[] privateKey = Base64.decodeBase64(privateKeyEncodedStr);
        PrivateKey priKey = RSACoder.getPrivateKeyObject(privateKey);

        // 签名并保存至对象
        String signatureStr = sign(content, priKey);
        content.setSignature(signatureStr);

        return content;
    }

    /**
     * 使用私钥对内容进行签名
     *
     * @param content
     *            license内容对象
     * @param signingKey
     *            私钥
     * @param signingEngine
     *            签名引擎
     * @return 返回签名结果
     * @throws InvalidKeyException
     *             私钥无效
     * @throws SignatureException
     *             签名异常
     * @throws NoSuchAlgorithmException
     *             签名算法异常
     */
    private static String sign(LicenseContent content, PrivateKey signingKey)
            throws InvalidKeyException, SignatureException, NoSuchAlgorithmException {
        String str4Signature = LicensePropertiesUtil.madeLicenseString4Signature(content);
        byte[] contentByte = str4Signature.getBytes(Charset.forName("utf-8"));
        // 获取签名对象
        Signature signingEngine = RSACoder.getSignature();
        // 用密钥初始化这个签名引擎用于进行签名操作
        signingEngine.initSign(signingKey);
        // 签名
        signingEngine.update(contentByte);
        // 签名后的内容用base64编码
        return Base64.encodeBase64String(signingEngine.sign());
    }

    /**
     * 验证license
     *
     * @param licenseFile
     *            license文件
     * @return 返回证书内容对象
     * @throws Exception
     *             验证异常
     */
    public LicenseContent verify() throws Exception {

        String str4Signature = LicensePropertiesUtil.madeLicenseString4Signature(content);

        // 获取公钥
        byte[] publicKey = Base64.decodeBase64(publicKeyEncodedStr);
        PublicKey pubKey = RSACoder.getPublicKeyObject(publicKey);

        // 签名验证
        boolean isSignatureOk = verify(str4Signature, content.getSignature(), pubKey);
        // 签名通过后进行内容验证
        if (isSignatureOk) {
            int userNum = handler4License.getTotalUserNum();
            EValidationResult ev = validate4Client(content, userNum);
            content.seteValidationResult(ev);
            // 设置验证成功
            if (ev == EValidationResult.VALID) {
                content.setValid(true);
            } else {
                content.setValid(false);
            }
        } else {
            content.setValid(false);
            content.seteValidationResult(EValidationResult.WRONG_SIGNATUR);
        }

        // 返回内容
        return content;
    }

    /**
     * 验证签名
     *
     * @param str4Signature
     *            需要签名的内容
     * @param originSignature
     *            原签名
     * @param verificationKey
     *            公钥
     * @return 返回验证是否成功
     * @throws NoSuchAlgorithmException
     *             算法异常
     * @throws InvalidKeyException
     *             无效公钥
     * @throws SignatureException
     *             签名异常
     */
    private boolean verify(String str4Signature, String originSignature, PublicKey verificationKey)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        // 获取签名对象
        Signature verificationEngine = RSACoder.getSignature();
        // 用公钥签名验证
        verificationEngine.initVerify(verificationKey);
        verificationEngine.update(str4Signature.getBytes(Charset.forName("utf-8")));
        byte[] originSigData = Base64.decodeBase64(originSignature);
        // 验证签名
        return verificationEngine.verify(originSigData);
    }

    /**
     * 返回创建license时内容正确性
     *
     * @param content
     *            证书内容
     * @return 返回验证结果，默认是NOT_VALID_YET，未开始验证，其它为异常结果
     */
    protected static EValidationResult validate4LicenseCreate(LicenseContent content) {
        String customName = content.getCustomName();
        String licenseType = content.getLicenseType();
        String expirationDate = content.getExpirationDate();
        int userAmount = content.getUserAmount();

        if (customName == null || customName.isEmpty())
            return EValidationResult.NULL_CUSTOM_NAME;
        if (licenseType == null || licenseType.isEmpty())
            return EValidationResult.NULL_LICENSE_TYPE;
        if (expirationDate == null)
            return EValidationResult.NULL_END_TRIAL_DATE;
        if (userAmount < 0)
            return EValidationResult.WRONG_USER_AMOUNT;

        // 默认返回未验证
        return EValidationResult.NOT_VALID_YET;
    }

    /**
     * 验证客户端license的内容
     *
     * @param content
     *            license内容
     * @return 返回验证结果枚举
     */
    protected static EValidationResult validate4Client(LicenseContent content, int currentUserNum) {
        String expirationDateStr = content.getExpirationDate();
        Date expirationDate;
        try {
            expirationDate = DateUtil.yyyy_MM_dd2Date(expirationDateStr);
        } catch (ParseException e) {
            return EValidationResult.NOT_VALID_CONTENT;
        }

        // 判断当前时间是否在有效期内
        Date now = new Date();
        if (now.after(expirationDate)) {
            return EValidationResult.EXPIRED;
        }
        // 人数是否超过证书限定值
        if (currentUserNum > content.getUserAmount()) {
            return EValidationResult.LIMITED_USERS;
        }

        // 默认正常
        return EValidationResult.VALID;
    }

    /**
     * 从文件创建证书内容
     *
     * @param licenseFile
     *            证书文件
     */
    private void madeLicenseContentFromFile(File licenseFile) throws Exception {
        HashMap<String, String> licenseDataMap = FileUtil.readProperties(licenseFile.getAbsolutePath());
        // 证书内容对象
        LicenseContent content = new LicenseContent();
        String customName = licenseDataMap.get(LicensePropertiesUtil.CUSTOM_NAME_KEY);
        String licenseType = licenseDataMap.get(LicensePropertiesUtil.LICENSE_TYPE_KEY);
        String issuedDate = licenseDataMap.get(LicensePropertiesUtil.ISSUED_DATE_KEY);
        String expirationDate = licenseDataMap.get(LicensePropertiesUtil.EXPIRATION_DATE_KEY);
        int userAmount = Integer.parseInt(licenseDataMap.get(LicensePropertiesUtil.USER_AMOUNT_KEY));
        String dbUrl = licenseDataMap.get(LicensePropertiesUtil.DB_URL_KEY);
        String originSignature = licenseDataMap.get(LicensePropertiesUtil.SIGNATURE_KEY);
        String sql=licenseDataMap.get(LicensePropertiesUtil.SQL_KEY);

        content.setSignature(originSignature);
        content.setCustomName(customName);
        content.setLicenseType(licenseType);
        content.setIssuedDate(issuedDate);
        content.setExpirationDate(expirationDate);
        content.setUserAmount(userAmount);
        content.setDbUrl(dbUrl);
        content.setSql(sql);

        this.content = content;
    }
}
