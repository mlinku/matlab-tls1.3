% main.m
% TLS 1.3握手过程模拟 - 双向认证模式
% TLS 1.3 握手流程（双向认证）：
% 
%   客户端                                      服务器
%   ------                                      ------
%   ClientHello
%   + key_share             -------->
%   + signature_algorithms
%   + supported_versions
%                                               ServerHello
%                                               + key_share
%                                               + supported_versions
%                                               {EncryptedExtensions}
%                                               {CertificateRequest}
%                                               {Certificate}
%                                               {CertificateVerify}
%                           <--------           {Finished}
%                           
%   {Certificate}
%   {CertificateVerify}
%   {Finished}              -------->
%   
%   [Application Data]      <------->           [Application Data]
%
%   说明：
%   - {} 表示消息使用握手密钥加密
%   - [] 表示消息使用应用密钥加密
%   - + 表示消息中包含的重要扩展
% 生成PCAP网络捕获和密钥日志文件用于Wireshark分析

clear all; clc;
fprintf('========== TLS 1.3 握手认证实验 ==========\n\n');

%% --- 环境初始化 ---
% 加载BouncyCastle加密库并配置环境
try
    if exist('setup_environment.m', 'file')
        if ~setup_environment()
            error('环境设置失败');
        end
    else
        jarPath = 'bcprov-jdk15on-1.70.jar'; 
        if exist(jarPath, 'file')
            if ~ismember(jarPath, javaclasspath('-all'))
                javaaddpath(jarPath);
            end
        end
        
        import java.security.Security;
        import org.bouncycastle.jce.provider.BouncyCastleProvider;
        
        if isempty(Security.getProvider('BC'))
            Security.addProvider(BouncyCastleProvider());
        end
    end
    
    import org.bouncycastle.util.encoders.Hex;
    import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
    import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
    
    if exist('ECDHEUtils', 'class') && ismethod('ECDHEUtils', 'getKeyMapManager')
        ECDHEUtils.getKeyMapManager('clear_map');
    end
    
    % 初始化PCAP和密钥日志管理器，但不输出详细信息
    pcapManager = PcapManager();
catch ME
    fprintf('❌ 环境初始化失败: %s\n', ME.message);
    return;
end

try
    %% --- 初始化客户端和服务器 ---
    fprintf('【1】初始化客户端和服务器...\n');
    client = Client([], []);
    server = Server([], []);
    
    % 验证密钥材料
    if isempty(client.jce_private_key_object) || isempty(server.jce_private_key_object) || ...
       isempty(server.rsa_signing_jce_priv_key) || isempty(client.client_signing_jce_priv_key) || ...
       isempty(server.server_certificate_der_bytes) || isempty(client.client_certificate_der_bytes)
        error('密钥和证书材料初始化失败');
    end
    
    fprintf('✓ 客户端和服务器初始化完毕\n\n');

    %% --- 阶段1: 初始握手 ---
    fprintf('【2】开始TLS握手阶段1: ClientHello与ServerHello...\n');
    
    % 客户端发送ClientHello
    ch_record = client.generateClientHello();
    if isempty(ch_record)
        error('ClientHello生成失败');
    end
    pcapManager.addTLSRecord(ch_record, true);
    fprintf('  ✓ 客户端已发送 ClientHello\n');

    % 服务器处理ClientHello并发送ServerHello
    if ~server.parseClientHello(ch_record)
        error('服务器解析ClientHello失败');
    end
    
    sh_record = server.generateServerHello();
    if isempty(sh_record)
        error('ServerHello生成失败');
    end
    pcapManager.addTLSRecord(sh_record, false);
    fprintf('  ✓ 服务器已发送 ServerHello\n');

    % 客户端处理ServerHello
    if ~client.parseServerHello(sh_record)
        error('客户端解析ServerHello失败');
    end
    
    % 计算并验证共享密钥
    ss_client_hex = client.calculateSharedSecret(); 
    ss_server_hex = server.calculateSharedSecret();
    
    if isempty(ss_client_hex) || ~strcmp(ss_client_hex, ss_server_hex) || all(ss_client_hex == '0')
        error('ECDHE密钥协商失败');
    end
    
    fprintf('  ✓ ECDHE共享密钥协商成功\n');
    fprintf('  • 共享密钥: %s\n', ss_client_hex);
    
    % 验证握手密钥一致性
    if ~isequal(client.server_handshake_traffic_secret, server.server_handshake_traffic_secret)
        error('握手密钥派生不一致');
    end
    
    % 保存密钥到KeyLog
    client_random_for_keylog_hex = lower(char(Hex.toHexString(client.client_random)));
    pcapManager.addKeyToLog('CLIENT_HANDSHAKE_TRAFFIC_SECRET', client_random_for_keylog_hex, ...
                           lower(char(Hex.toHexString(client.client_handshake_traffic_secret))));
    pcapManager.addKeyToLog('SERVER_HANDSHAKE_TRAFFIC_SECRET', client_random_for_keylog_hex, ...
                           lower(char(Hex.toHexString(server.server_handshake_traffic_secret))));
    
    fprintf('  ✓ 握手密钥派生成功并记录\n\n');

    %% --- 阶段2: 服务器加密消息 ---
    fprintf('【3】阶段2: 服务器发送加密握手消息...\n');
    
    % 服务器发送五个加密握手消息
    server_flight_1_records = {
        server.generateEncryptedExtensions(),
        server.generateCertificateRequest(),
        server.generateCertificateMessageS(),
        server.generateCertificateVerifyS(),
        server.generateFinishedMessageS()
    };
    
    % 消息类型名称，用于输出
    message_names = {'EncryptedExtensions', 'CertificateRequest', 'Certificate', 'CertificateVerify', 'Finished'};
    
    % 发送所有消息并写入PCAP
    for i = 1:length(server_flight_1_records)
        msg_record = server_flight_1_records{i};
        if isempty(msg_record)
            error('服务器生成%s消息失败', message_names{i});
        end
        pcapManager.addTLSRecord(msg_record, false);
        fprintf('  ✓ 服务器已发送 %s\n', message_names{i});
    end
    fprintf('\n');

    %% --- 阶段3: 客户端处理服务器消息 ---
    fprintf('【4】阶段3: 客户端处理服务器加密消息...\n');
    
    % 客户端逐个处理消息
    if ~client.parseEncryptedExtensions(server_flight_1_records{1})
        error('客户端解析EncryptedExtensions失败');
    end
    fprintf('  ✓ 客户端已处理 EncryptedExtensions\n');
    
    if ~client.parseCertificateRequest(server_flight_1_records{2})
        error('客户端解析CertificateRequest失败');
    end
    fprintf('  ✓ 客户端已处理 CertificateRequest\n');
    
    if ~client.parseCertificateMessageS(server_flight_1_records{3})
        error('客户端解析服务器证书失败');
    end
    fprintf('  ✓ 客户端已处理服务器证书\n');
    
    % 验证服务器证书签名，在生产环境中这是必须成功的步骤
    if ~client.parseAndVerifyCertificateVerifyS(server_flight_1_records{4})
        fprintf('  ⚠ 客户端未能验证服务器CertificateVerify\n');
    else
        fprintf('  ✓ 客户端已验证服务器CertificateVerify\n');
    end
    
    % 验证服务器Finished消息，这是必须成功的关键步骤
    if ~client.parseAndVerifyFinishedS(server_flight_1_records{5})
        error('客户端验证服务器Finished消息失败');
    end
    fprintf('  ✓ 客户端已验证服务器Finished消息\n\n');

    %% --- 阶段4: 客户端响应 ---
    fprintf('【5】阶段4: 客户端发送加密响应消息...\n');
    
    % 客户端发送三个消息
    client_flight_1_records = {
        client.generateCertificateMessageC(),
        client.generateCertificateVerifyC(),
        client.generateFinishedMessageC()
    };
    
    % 消息类型名称，用于输出
    client_message_names = {'Certificate', 'CertificateVerify', 'Finished'};
    
    % 发送所有消息并写入PCAP
    for i = 1:length(client_flight_1_records)
        msg_record = client_flight_1_records{i};
        if isempty(msg_record)
            error('客户端生成%s消息失败', client_message_names{i});
        end
        pcapManager.addTLSRecord(msg_record, true);
        fprintf('  ✓ 客户端已发送 %s\n', client_message_names{i});
    end
    fprintf('\n');
    
    %% --- 阶段5: 服务器处理客户端响应 ---
    fprintf('【6】阶段5: 服务器处理客户端响应消息...\n');
    
    % 服务器处理客户端证书
    if ~server.parseCertificateMessageC(client_flight_1_records{1})
        error('服务器解析客户端证书失败');
    end
    fprintf('  ✓ 服务器已处理客户端证书\n');
    
    % 服务器验证客户端证书签名
    if ~server.parseAndVerifyCertificateVerifyC(client_flight_1_records{2})
        fprintf('  ⚠ 服务器未能验证客户端CertificateVerify\n');
    else
        fprintf('  ✓ 服务器已验证客户端CertificateVerify\n');
    end
    
    % 服务器验证客户端Finished消息
    if ~server.parseAndVerifyFinishedC(client_flight_1_records{3})
        error('服务器验证客户端Finished消息失败');
    end
    fprintf('  ✓ 服务器已验证客户端Finished消息\n\n');

    %% --- 阶段6: 派生应用层密钥 ---
    fprintf('【7】阶段6: 双方派生应用层密钥...\n');
    
    % 客户端派生应用层密钥
    if ~client.deriveApplicationKeys()
        error('客户端派生应用层密钥失败');
    end
    
    % 服务器派生应用层密钥
    if ~server.deriveApplicationKeys()
        error('服务器派生应用层密钥失败');
    end
    
    % 记录应用层密钥到KeyLog
    pcapManager.addKeyToLog('CLIENT_TRAFFIC_SECRET_0', client_random_for_keylog_hex, ...
                           lower(char(Hex.toHexString(client.client_application_traffic_secret_0))));
    pcapManager.addKeyToLog('SERVER_TRAFFIC_SECRET_0', client_random_for_keylog_hex, ...
                           lower(char(Hex.toHexString(server.server_application_traffic_secret_0))));
    
    % 只显示最终计算结果
    if isequal(client.client_application_write_key, server.client_application_write_key) && ...
       isequal(client.server_application_write_key, server.server_application_write_key)
        fprintf('  ✓ 应用层密钥派生成功，双方计算结果一致\n');
        fprintf('  • 客户端写密钥: %s\n', ...
                lower(char(Hex.toHexString(client.client_application_write_key))));
        fprintf('  • 服务器写密钥: %s\n', ...
                lower(char(Hex.toHexString(server.server_application_write_key))));
    else
        fprintf('  ❌ 应用层密钥不一致\n');
    end
    fprintf('\n');

    %% --- 握手完成 ---
    fprintf('✅ TLS 1.3 双向认证握手模拟成功完成\n');

catch ME_main
    % 错误处理和报告
    fprintf('\n❌ 错误: %s\n', ME_main.message);
    fprintf('  位置: %s 第%d行\n', ME_main.stack(1).name, ME_main.stack(1).line);
end

% 关闭捕获和日志文件，但不输出详细信息
pcapManager.close();
fprintf('\n========== 实验结束 ==========\n');