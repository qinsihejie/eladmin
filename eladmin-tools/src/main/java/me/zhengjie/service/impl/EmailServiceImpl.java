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
import me.zhengjie.domain.EmailConfig;
import me.zhengjie.domain.vo.EmailVo;
import me.zhengjie.exception.BadRequestException;
import me.zhengjie.repository.EmailRepository;
import me.zhengjie.service.EmailService;
import org.apache.commons.lang3.StringUtils;
import org.springframework.cache.annotation.CacheConfig;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.mail.Message;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeUtility;
import java.util.List;
import java.util.Optional;
import java.util.Properties;

/**
 * @author Zheng Jie
 * @date 2018-12-26
 */
@Service
@RequiredArgsConstructor
@CacheConfig(cacheNames = "email")
public class EmailServiceImpl implements EmailService {

    private final EmailRepository emailRepository;

    @Override
    @CachePut(key = "'id:1'")
    @Transactional(rollbackFor = Exception.class)
    public EmailConfig config(EmailConfig emailConfig, EmailConfig old) throws Exception {
        emailConfig.setId(1L);
//        if (!emailConfig.getPass().equals(old.getPass())) {
//            // 对称加密
//            emailConfig.setPass(EncryptUtils.desEncrypt(emailConfig.getPass()));
//        }
        emailConfig.setPass(emailConfig.getPass());
        return emailRepository.save(emailConfig);
    }

    @Override
    @Cacheable(key = "'id:1'")
    public EmailConfig find() {
        Optional<EmailConfig> emailConfig = emailRepository.findById(1L);
        return emailConfig.orElseGet(EmailConfig::new);
    }

    @Override
    @Transactional(rollbackFor = Exception.class)
    public void send(EmailVo emailVo, EmailConfig emailConfig) {
        if (emailConfig == null) {
            throw new BadRequestException("请先配置，再操作");
        }
        // 发送
        try {
            Properties prop = new Properties();
            prop.setProperty("mail.smtp.host", emailConfig.getHost());
            prop.setProperty("mail.transport.protocol", "smtp");
            prop.setProperty("mail.smtp.auth", "true");

            prop.setProperty("mail.smtp.port", emailConfig.getPort());
            Session session = Session.getDefaultInstance(prop, null);
            // メール情報を表示する
            Transport transport = session.getTransport("smtp");
            transport.connect(emailConfig.getHost(), emailConfig.getFromUser(), emailConfig.getPass());
            Message message = createSimpleMail(session, emailConfig.getFromUser(), emailVo.getTos(), emailVo.getTos(), emailVo.getSubject(), emailVo.getContent());
            transport.sendMessage(message, message.getAllRecipients());
            transport.close();
        } catch (Exception e) {
            throw new BadRequestException(e.getMessage());
        }
    }

    /**
     * テキストメールを作成
     *
     * @param session        Session
     * @param fromUserMail   送信者のメールアカウント
     * @param toUserMail     受信者のメールアカウント
     * @param title          メールのタイトル
     * @param messageContent メールの内容
     * @return メール
     * @throws Exception 例外
     */
    private static MimeMessage createSimpleMail(Session session, String fromUserMail, List<String> toUserMail,
                                                List<String> copyUserMail, String title, String messageContent) throws Exception {
        MimeMessage message = new MimeMessage(session);
        message.setFrom(new InternetAddress(fromUserMail));
        if (!toUserMail.isEmpty()) {
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(StringUtils.joinWith(",", toUserMail.toArray())));
        }
        if (!copyUserMail.isEmpty()) {
            message.setRecipients(Message.RecipientType.CC, InternetAddress.parse(StringUtils.joinWith(",", copyUserMail.toArray())));
        }
        message.setSubject(MimeUtility.encodeText(title, MimeUtility.mimeCharset("UTF-8"), null));
        message.setContent(messageContent, "text/html;charset=UTF-8");
        return message;
    }
}
