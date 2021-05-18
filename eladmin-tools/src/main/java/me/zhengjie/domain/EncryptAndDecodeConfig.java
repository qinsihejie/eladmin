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
package me.zhengjie.domain;

import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import javax.validation.constraints.NotBlank;
import java.io.Serializable;

/**
 * 暗号化&复号化
 * @author lfwang
 * @date 2021-05-06
 */
@Data
public class EncryptAndDecodeConfig implements Serializable {

    @NotBlank
    @ApiModelProperty(value = "加密/解密选择", hidden = true)
    private String type;

    @NotBlank
    @ApiModelProperty(value = "加密/解密原字符")
    private String origin;

    @ApiModelProperty(value = "加密/解密结果")
    private String result;

    @ApiModelProperty(value = "ivKey")
    private String ivKey;

    @ApiModelProperty(value = "aesKey")
    private String aesKey;
}
