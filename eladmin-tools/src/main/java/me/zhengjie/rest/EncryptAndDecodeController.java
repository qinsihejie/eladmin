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
package me.zhengjie.rest;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.RequiredArgsConstructor;
import me.zhengjie.annotation.Log;
import me.zhengjie.domain.EncryptAndDecodeConfig;
import me.zhengjie.service.EncryptAndDecodeService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 暗号化&复号化
 * @author lfwang
 * @date 2021/05/07
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("api/encryptAndDecode")
@Api(tags = "工具：暗号化&复号化")
public class EncryptAndDecodeController {

    private final EncryptAndDecodeService encryptAndDecodeService;

    @Log("暗号化")
    @PostMapping(value = "/encrypt")
    @ApiOperation("暗号化")
    public ResponseEntity<Object> encrypt(@Validated @RequestBody EncryptAndDecodeConfig encryptAndDecodeConfig) throws Exception {
        return new ResponseEntity<>(encryptAndDecodeService.encrypt(encryptAndDecodeConfig), HttpStatus.OK);
    }

    @Log("复号化")
    @PostMapping(value = "/decode")
    @ApiOperation("复号化")
    public ResponseEntity<Object> decode(@Validated @RequestBody EncryptAndDecodeConfig encryptAndDecodeConfig) throws Exception {
        return new ResponseEntity<>(encryptAndDecodeService.decode(encryptAndDecodeConfig), HttpStatus.OK);
    }
}
