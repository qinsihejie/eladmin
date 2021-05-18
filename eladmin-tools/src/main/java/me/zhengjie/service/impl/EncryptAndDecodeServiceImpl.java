/*
 *  Copyright 2019-2020 Zheng Jie
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package me.zhengjie.service.impl;

import lombok.RequiredArgsConstructor;
import me.zhengjie.domain.EncryptAndDecodeConfig;
import me.zhengjie.service.EncryptAndDecodeService;
import me.zhengjie.utils.AesDecryptUtil;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.cache.annotation.CacheConfig;
import org.springframework.stereotype.Service;

/**
 * @author lfwang
 * @date 2021-05-06
 */
@Service
@RequiredArgsConstructor
@CacheConfig(cacheNames = "encryptAndDecode")
public class EncryptAndDecodeServiceImpl implements EncryptAndDecodeService {

    @Override
    public EncryptAndDecodeConfig encrypt(EncryptAndDecodeConfig encryptAndDecodeConfig) throws Exception {
        String type = encryptAndDecodeConfig.getType();
        String origin = encryptAndDecodeConfig.getOrigin();
        switch (type) {
            case "SHA256":
                encryptAndDecodeConfig.setResult(DigestUtils.sha256Hex(origin));
                break;
            case "MD5":
                encryptAndDecodeConfig.setResult(DigestUtils.md2Hex(origin));
                break;
            case "AES1":
                encryptAndDecodeConfig.setResult(AesDecryptUtil.encryptStr(origin, encryptAndDecodeConfig.getIvKey(),
                        encryptAndDecodeConfig.getAesKey()));
                break;
            case "AES2":
                byte[] iv = encryptAndDecodeConfig.getIvKey().getBytes("MS932");
                byte[] keys = encryptAndDecodeConfig.getAesKey().getBytes("MS932");
                encryptAndDecodeConfig.setResult(AesDecryptUtil.bytesToHexString(AesDecryptUtil.vpadEncrypt(2, iv,
                        keys.length * 8, keys, origin.getBytes("MS932"), origin.getBytes("MS932").length)));
                break;
            default:
                break;
        }
        return encryptAndDecodeConfig;
    }

    @Override
    public EncryptAndDecodeConfig decode(EncryptAndDecodeConfig encryptAndDecodeConfig) throws Exception {
        String type = encryptAndDecodeConfig.getType();
        switch (type) {
            case "AES1":
                encryptAndDecodeConfig.setResult(AesDecryptUtil.decryptStr(encryptAndDecodeConfig.getOrigin(),
                        encryptAndDecodeConfig.getIvKey(), encryptAndDecodeConfig.getAesKey()));
                break;
            default:
                break;
        }
        return encryptAndDecodeConfig;
    }
}
