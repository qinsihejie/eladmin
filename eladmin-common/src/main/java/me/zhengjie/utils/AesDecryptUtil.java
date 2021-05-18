package me.zhengjie.utils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;

/**
 * @author bmeng
 * @version 1.0
 */
public class AesDecryptUtil {
    /**
     * 暗号化のタイプ
     */
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";

    /**
     * The constant MODE_ECB.
     */
    public static final int MODE_ECB = 1;

    /**
     * The constant MODE_CBC.
     */
    public static final int MODE_CBC = 2;

    private static byte[] inivec = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00 };

    public static void main(String[] args) throws Exception {
    }

    /**
     * AES復号化
     *
     * @param string
     * @throws Exception
     */
    @SuppressWarnings("unchecked")
    public static String decryptStr(String string, String iv, String hexAeskey) throws Exception {
        byte[] vi = iv.getBytes();

        // AES復号化処理
        try {
            byte[] signature = AesDecryptUtil.hexStringToBytes(string);
            byte[] aesKey = AesDecryptUtil.hexStringToBytes(hexAeskey);

            return new String(AesDecryptUtil.decrypt(AesDecryptUtil.MODE_CBC, vi, aesKey.length * 8, aesKey,
                    signature, signature.length));
        } catch (Exception e) {
            return "ERR";
        }
    }

    /**
     * AES暗号化
     *
     * @param string
     * @throws Exception
     */
    @SuppressWarnings("unchecked")
    public static String encryptStr(String string, String iv, String hexAesKey) throws Exception {
        byte[] vi = iv.getBytes();

        // AES復号化処理
        String result = "";
        try {
            byte[] aesKey = AesDecryptUtil.hexStringToBytes(hexAesKey);
            result = AesDecryptUtil.encrypt(aesKey, vi, string).concat("_0").concat("21");
        } catch (Exception e) {
            throw new IOException("暗号化失敗しました。", e);
        }
        return result;
    }

    public static void encodeSlip() throws Exception {
        //        byte[] iv = ("62090003" + "28131354").getBytes("MS932");
//        byte[] keys = "json_gmofg200528".getBytes("MS932");
        byte[] iv = ("03212346" + "22092324").getBytes("MS932");
        byte[] keys = "json_gmofg190922".getBytes("MS932");
//        byte[] keys = AesDecryptUtil.hexStringToBytes(key);
//        for (int i = 0; i < keys.length; i++) {
//            keys[i] = (byte) (keys[i] ^ 0x5a);
//        }
        byte[] transactInfo = "{\"DenpyoInfo\":{\"KessaiSyubeu\":\"02\",\"ReceiptTitle\":\"CREDIT CARD SALES SLIP\",\"MerchantName\":\"加盟店Name\\r\\n002-1111-222\",\"CardInfoResource\":\"MS\",\"CardCompanyCode\":\"UCGROUP\",\"Uriba\":\"Kyoto\",\"Kakariin\":\"fubuki\",\"TerminalSeqNo\":\"00001\",\"CancelTerminalSeqNo\":\"00001\",\"Riyoubi\":\"20190922084812\",\"MemberShipNo\":\"124121******1231\",\"kanaName\":\"fubuki\",\"YukoKigen\":\"0908\",\"TerminalID\":\"6406503212345\",\"ProcessSeqNo\":\"00107\",\"ServiceCode\":\"1\",\"TorikeshiKubun\":\"1\",\"ShiharaiKubun\":\"10\",\"ShiharaiKaisu\":\"21\",\"ToriatukaiKubun\":\"120\",\"ItemCode\":\"2270\",\"Amount\":\"0009999\",\"TaxAmount\":\"2700\",\"Goukei\":\"30000\",\"SignatureFlag\":\"1\",\"Annai\":\"this is annaiです\",\"Signature\":\"\"},\"IcInfo\":{\"BrandName\":\"123456789\",\"CardSeqNo\":\"666\",\"Aid\":\"4F\",\"ApplicationLabel\":\"VISADEBIT\",\"ATC\":\"9f36\",\"ARC\":\"8A\",\"TC\":\"9F26\",\"TVR\":\"95\",\"CVR\":\"9F34\",\"CardNoCheckReason\":\"fumein\"},\"SonotaInfo\":{\"MerchantInfo\":\"chino\",\"MerchantGyosyu\":\"eve\"},\"GinrenInfo\":{\"BankNames\":\"SoftBank\",\"CupNo\":\"940201\",\"CupSendDate\":\"190201\"},\"DccInfo\":{\"MarkUp\":\"1.8\",\"CurrencyAbbreviation\":\"dollar\",\"ExchangeRateUnit\":\"1\",\"ExchangeRate\":\"18\",\"TransactionCurrency\":\"1180\",\"Disclaimer\":\"11234\",\"DisclaimerLength\":\"444\"}}".getBytes("MS932");
        System.out.println(AesDecryptUtil.bytesToHexString(vpadEncrypt(2, iv,
                keys.length * 8, keys, transactInfo, transactInfo.length)));
    }

    /**
     * AES復号化処理（Paddingなし）*
     *
     * @param ciMode ブロック暗号化モード指定（MODE_ECB、MODE_CBC）*
     * @param iv     MODE_CBCの為の初期化ベクトル指定（16 bytesのデータ）（NULL指定の場合、すべて 0 を設定）*
     * @param keylen 鍵長指定（ビット長：128、192、256 の何れか）*
     * @param key    暗号化／復号化の鍵の構成要素指定*
     * @param in     入力データのアドレス指定（暗号化する元データ）*
     * @param ilen   入力データの長さ（octets:8 ビットを1組→バイト）*
     * @return the byte [ ]
     * @throws Exception 内部処理異常
     */
    public static byte[] vnopadDecrypt(int ciMode, byte[] iv, int keylen,
                                       byte[] key, byte[] in, int ilen) throws Exception {
        // ブロック暗号化モード指定（MODE_ECB、MODE_CBC）が不正
        if (ciMode != MODE_ECB && ciMode != MODE_CBC) {
            return null;
        }
        // 鍵長の指定が不正
        if (keylen != 128 && keylen != 192 && keylen != 256) {
            return null;
        }
        // 鍵構成要素アドレス指定が不正（NULL）
        if (key == null) {
            return null;
        }
        // if(outDEC == null){return -10; }
        // 正常終了（inがNULL、または、ilen<=0 の場合）
        if (in == null || ilen == 0) {
            return null;
        }
        // 入力データ長異常（ブロック長で割り切れない） TODO
        if ((ilen & 0x0f) != 0) {
            return null;
        }

        // MODE_CBCの為の初期化ベクトル指定（16bytesのデータ）（NULL指定の場合、すべて 0 を設定）
        IvParameterSpec ivSpec;
        if (iv == null) {
            ivSpec = new IvParameterSpec(inivec);
        } else {
            ivSpec = new IvParameterSpec(iv);
        }

        // ブロック暗号化モード指定
        Cipher cipher;
        if (ciMode == MODE_ECB) {
            ivSpec = null;
            cipher = Cipher.getInstance("AES/ECB/NoPadding");
        } else {
            cipher = Cipher.getInstance("AES/CBC/NoPadding");
        }

        // 復号化の鍵
        Key keySpec = new SecretKeySpec(key, "AES");

        // 復号化
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(in);
    }

    /**
     * AES暗号化処理（Paddingなし）
     *
     * @param ciMode the ci mode
     * @param iv     the iv
     * @param keylen the keylen
     * @param key    the key
     * @param in     the in
     * @param ilen   the ilen
     * @return the byte [ ]
     * @throws Exception the exception
     */
    public static byte[] vnopadEncrypt(int ciMode, byte[] iv, int keylen,
                                       byte[] key, byte[] in,
                                       int ilen) throws Exception {
        // ブロック暗号化モード指定（MODE_ECB、MODE_CBC）が不正
        if (ciMode != MODE_ECB && ciMode != MODE_CBC) {
            return null;
        }
        // 鍵長の指定が不正
        if (keylen != 128 && keylen != 192 && keylen != 256) {
            return null;
        }
        // 鍵構成要素アドレス指定が不正（NULL）
        if (key == null) {
            return null;
        }
        // if(outEN == null) {return -10; }
        // 正常終了（inがNULL、または、ilen<=0 の場合）
        if (in == null || ilen == 0) {
            return null;
        }
        // 入力データ長異常（ブロック長で割り切れない） TODO
        if ((ilen & 0x0f) != 0) {
            return null;
        }

        // MODE_CBCの為の初期化ベクトル指定（16bytesのデータ）（NULL指定の場合、すべて 0 を設定）
        IvParameterSpec ivSpec;
        if (iv == null) {
            ivSpec = new IvParameterSpec(inivec);
        } else {
            ivSpec = new IvParameterSpec(iv);
        }

        // ブロック暗号化モード指定（MODE_ECB、MODE_CBC）
        Cipher cipher;
        if (ciMode == MODE_ECB) {
            cipher = Cipher.getInstance("AES/ECB/NoPadding");
        } else {
            cipher = Cipher.getInstance("AES/CBC/NoPadding");
        }

        // 暗号化の鍵
        Key keySpec = new SecretKeySpec(key, "AES");

        // 暗号化
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(in);
    }

    /**
     * Convert hex string to byte[]
     *
     * @param hexString the hex string
     * @return byte[] byte [ ]
     */
    public static byte[] hexStringToBytes(String hexString) {
        if (hexString == null || "".equals(hexString)) {
            return new byte[0];
        }
        hexString = hexString.toUpperCase(Locale.JAPANESE);
        int length = hexString.length() / 2;
        char[] hexChars = hexString.toCharArray();
        byte[] d = new byte[length];
        for (int i = 0; i < length; i++) {
            int pos = i * 2;
            d[i] = (byte) (charToByte(hexChars[pos]) << 4 | (charToByte(hexChars[pos + 1])) & 0xff);
        }
        return d;
    }

    private static byte charToByte(char c) {
        return (byte) "0123456789ABCDEF".indexOf(c);
    }

    /**
     * Convert byte[] string to hex string
     *
     * @param src src
     * @return String string
     */
    public static String bytesToHexString(byte[] src) {
        StringBuilder sb = new StringBuilder();
        if (src == null || src.length <= 0) {
            return null;
        }
        for (byte b : src) {
            int v = b & 0xFF;
            String hv = Integer.toHexString(v).toUpperCase();
            if (hv.length() < 2) {
                sb.append(0);
            }
            sb.append(hv);
        }
        return sb.toString();
    }

    /**
     * AES暗号化処理（Paddingあり）
     *
     * @param ciMode ブロック暗号化モード指定（MODE_ECB、MODE_CBC）
     * @param iv     MODE_CBCの為の初期化ベクトル指定（16bytesのデータ） （NULL指定の場合、すべて 0 を設定）
     * @param keylen 鍵長指定（ビット長：128、192、256の何れか）
     * @param key    暗号化／復号化の鍵の構成要素指定
     * @param in     入力データのアドレス指定（暗号化する元データ）
     * @param ilen   入力データの長さ（octets:8ビットを1組→バイト）
     * @return int 出力データのバイト長
     * @throws Exception 内部処理異常
     */
    public static byte[] vpadEncrypt(int ciMode, byte[] iv, int keylen,
                                     byte[] key, byte[] in,
                                     int ilen) throws Exception {
        // ブロック暗号化モード指定（MODE_ECB、MODE_CBC）が不正
        if (ciMode != MODE_ECB && ciMode != MODE_CBC) {
            return null;
        }
        // 鍵長の指定が不正
        if (keylen != 128 && keylen != 192 && keylen != 256) {
            return null;
        }
        // 鍵構成要素アドレス指定が不正（NULL）
        if (key == null) {
            return null;
        }
        // if(outEN == null){return -10; }
        // 正常終了（inがNULL、または、ilen<=0 の場合）
        if (in == null || ilen == 0) {
            return null;
        }

        // MODE_CBCの為の初期化ベクトル指定（16bytesのデータ）（NULL指定の場合、すべて 0 を設定）
        IvParameterSpec ivSpec;
        if (iv == null) {
            ivSpec = new IvParameterSpec(inivec);
        } else {
            ivSpec = new IvParameterSpec(iv);
        }

        // ブロック暗号化モード（MODE_ECB、MODE_CBC）
        Cipher cipher;
        if (ciMode == MODE_ECB) {
            ivSpec = null;
            cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        } else {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        }

        // 暗号化の鍵
        Key keySpec = new SecretKeySpec(key, "AES");

        // 暗号化
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(in);
    }

    /**
     * AES復号化処理（Paddingあり）
     *
     * @param ciMode ブロック暗号化モード指定（MODE_ECB、MODE_CBC）
     * @param iv     MODE_CBCの為の初期化ベクトル指定（16bytesのデータ） （NULL指定の場合、すべて 0 を設定）
     * @param keylen 鍵長指定（ビット長：128、192、256の何れか）
     * @param key    暗号化／復号化の鍵の構成要素指定
     * @param in     入力データのアドレス指定（暗号化する元データ）
     * @param ilen   入力データの長さ（octets:8ビットを1組→バイト）
     * @return int 出力データのバイト長
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static byte[] decrypt(int ciMode, byte[] iv, int keylen, byte[] key, byte[] in, int ilen)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

        // ブロック暗号化モード指定（MODE_ECB、MODE_CBC）が不正
        if (ciMode != MODE_ECB && ciMode != MODE_CBC) {
            return new byte[0];
        }
        // 鍵長の指定が不正
        if (keylen != 128 && keylen != 192 && keylen != 256) {
            return new byte[0];
        }
        // 鍵構成要素アドレス指定が不正（NULL）
        if (key == null) {
            return new byte[0];
        }
        // 正常終了（inがNULL、または、ilen<=0 の場合）
        if (in == null || ilen == 0) {
            return new byte[0];
        }

        // MODE_CBCの為の初期化ベクトル指定（16bytesのデータ）（NULL指定の場合、すべて 0 を設定）
        IvParameterSpec ivSpec;
        if (iv == null) {
            ivSpec = new IvParameterSpec(inivec);
        } else {
            ivSpec = new IvParameterSpec(iv);
        }

        // ブロック暗号化モード（MODE_ECB、MODE_CBC）
        Cipher cipher;
        if (ciMode == MODE_ECB) {
            ivSpec = null;
            cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        } else {
            cipher = Cipher.getInstance(ALGORITHM);
        }

        // 復号化の鍵
        Key keySpec = new SecretKeySpec(key, "AES");

        // 復号化
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(in);
    }

    /**
     * AES暗号化
     * @param key
     * @param iv
     * @param data
     * @return
     * @throws Exception
     */
    @SuppressWarnings("unchecked")
    public static String encrypt(byte[] key, byte[] iv, String data) throws Exception {

        // AES暗号化処理
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        byte[] encData = cipher.doFinal(data.getBytes("MS932"));
        return bytes2Hex(encData);
    }

    /**
     * byte to hex
     * @param src
     * @return
     */
    public static String bytes2Hex(byte[] src) {
        char[] res = new char[src.length * 2];
        final char hexDigits[] = {
                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
        };
        for (int i = 0, j = 0; i < src.length; i++) {
            res[j++] = hexDigits[src[i] >>> 4 & 0x0f];
            res[j++] = hexDigits[src[i] & 0x0f];
        }
        return new String(res);
    }

}
