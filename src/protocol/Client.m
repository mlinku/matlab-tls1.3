% Client.m
% TLS 1.3 客户端实现类，遵循RFC 8446规范
% 提供TLS 1.3握手过程中客户端端的全部功能，包括密钥交换、证书验证和双向认证
%
% 主要功能模块：
% 1. 握手消息生成与解析 (ClientHello, Certificate, CertificateVerify, Finished)
% 2. ECDHE密钥交换 (基于X25519曲线)
% 3. 密钥派生 (使用HKDF和SHA-256)
% 4. 消息加密解密 (使用AES-128-GCM)
% 5. 证书认证 (支持RSA-PSS和ECDSA签名)
%
classdef Client < handle
    properties (Access = public)
        % ========== 通信通道相关属性 ==========
        % 这两个属性预留给实际的网络通信实现使用
        send_channel  % 发送通道对象（预留接口，实际使用时需要替换为真实通信通道）
        recv_channel  % 接收通道对象（预留接口，实际使用时需要替换为真实通信通道）

        % ========== 握手消息累积器 ==========
        % 存储所有握手消息的字节序列，用于计算Transcript Hash
        % 格式: 每个消息为 [HandshakeType(1字节) + Length(3字节) + Content(N字节)]
        % 按照消息交换顺序依次拼接
        handshake_messages  % uint8行向量，累积的握手消息序列

        % ========== 客户端ECDHE密钥材料 ==========
        % 用于ECDHE密钥交换的相关密钥材料
        client_random       % [32字节] 客户端随机数，用于密钥派生和防重放攻击
        public_key_bytes    % [32字节] X25519原始公钥，发送给服务器用于密钥协商
        private_key_bytes   % [32字节] X25519原始私钥，保密存储，用于计算共享密钥
        jce_private_key_object  % Java Cryptography Extension私钥对象，用于调用底层加密API
        
        % ========== 客户端签名认证材料 ==========
        % 用于客户端证书认证的密钥和证书
        client_certificate_der_bytes  % [N字节] 客户端证书的DER编码字节，包含客户端身份信息
        client_signing_jce_priv_key   % JCE私钥对象，用于生成CertificateVerify签名
        
        % ========== 从服务器消息中解析得到的信息 ==========
        % 这些信息是从服务器发送的各种消息中提取出来的
        received_server_random        % [32字节] 服务器随机数，用于密钥派生
        echoed_session_id_len_byte    % [1字节] 服务器回显的会话ID长度
        echoed_session_id_val_bytes   % [N字节] 服务器回显的会话ID值
        selected_cipher_suite         % [2字节] 服务器选择的密码套件 (本实现支持0x1301)
        server_raw_public_key         % [32字节] 服务器的X25519公钥 (从KeyShare扩展获取)
        received_certificate_request_context  % [N字节] 证书请求上下文，需在客户端证书消息中回显
        received_sig_algs_from_cr     % cell数组，服务器支持的签名算法列表
        received_server_certificate_chain_der % cell数组，服务器证书链（每个元素是一个证书的DER字节）
        server_signing_jce_pub_key    % JCE公钥对象，从服务器证书中提取，用于验证CertificateVerify

        % ========== ECDHE共享密钥和派生密钥 ==========
        % 通过ECDHE密钥交换和HKDF派生得到的各种密钥
        shared_secret                 % [32字节] ECDHE共享密钥，客户端私钥与服务器公钥的DH结果
        handshake_secret_prk          % [32字节] 握手密钥PRK，HKDF-Extract的输出
        client_handshake_traffic_secret % [32字节] 客户端握手流量密钥，用于派生加密密钥
        server_handshake_traffic_secret % [32字节] 服务器握手流量密钥，用于派生解密密钥
        client_handshake_write_key    % [16字节] AES-128密钥，加密客户端握手消息
        client_handshake_write_iv     % [12字节] AES-GCM IV，加密客户端握手消息
        server_handshake_write_key    % [16字节] AES-128密钥，解密服务器握手消息
        server_handshake_write_iv     % [12字节] AES-GCM IV，解密服务器握手消息
        client_finished_key           % [32字节] 生成客户端Finished消息的HMAC密钥
        server_finished_key_for_verify % [32字节] 验证服务器Finished消息的HMAC密钥

        % ========== 应用层密钥相关属性 ==========
        % 握手完成后用于加密应用数据的密钥
        master_secret_prk             % [32字节] 主密钥PRK，从握手密钥派生
        client_application_traffic_secret_0 % [32字节] 客户端应用流量密钥
        server_application_traffic_secret_0 % [32字节] 服务器应用流量密钥
        client_application_write_key  % [16字节] 加密客户端应用数据的AES密钥
        client_application_write_iv   % [12字节] 加密客户端应用数据的IV
        server_application_write_key  % [16字节] 解密服务器应用数据的AES密钥
        server_application_write_iv   % [12字节] 解密服务器应用数据的IV

        % ========== 记录层序列号 ==========
        % 用于构造AES-GCM的nonce和防止重放攻击
        % 注意：握手阶段和应用数据阶段的序列号是独立计数的
        client_record_send_seq_num    % uint64，客户端发送的加密记录序列号
        server_record_recv_seq_num    % uint64，接收服务器加密记录的序列号
        
        % ========== ClientHello中发送的会话ID ==========
        % 用于验证服务器是否正确回显（TLS 1.3的兼容性机制）
        sent_session_id_len           % uint8，发送的会话ID长度
        sent_session_id_val           % [N字节] 发送的会话ID值
    end

    methods (Access = public)
        function obj = Client(send_channel, recv_channel)
            % 客户端类构造函数
            % 功能：初始化TLS 1.3客户端对象，包括生成密钥对、加载证书等
            % 参数:
            %   send_channel - 发送通道对象（可选，用于实际网络通信）
            %   recv_channel - 接收通道对象（可选，用于实际网络通信）
            % 返回:
            %   obj - 初始化完成的Client对象
            
            % ===== 步骤1: 设置通信通道 =====
            obj.send_channel = send_channel; 
            obj.recv_channel = recv_channel;
            
            % ===== 步骤2: 初始化握手消息缓冲区 =====
            % 创建一个空的uint8行向量，用于累积所有握手消息
            obj.handshake_messages = reshape(uint8([]), 1, 0);
            
            % ===== 步骤3: 生成ECDHE密钥对 =====
            % 使用X25519曲线生成临时密钥对，用于ECDHE密钥交换
            fprintf('客户端: 正在生成X25519 ECDHE密钥对...\n');
            [rawPubKey, rawPrivKey, ~, jcePrivKey, ~, successGKP, errMsgGKP] = ...
                ECDHEUtils.generateFullX25519KeyPairObjects();
            
            if successGKP
                % 密钥生成成功，保存各种格式的密钥
                obj.public_key_bytes = rawPubKey;        % 原始公钥字节（32字节）
                obj.private_key_bytes = rawPrivKey;      % 原始私钥字节（32字节）
                obj.jce_private_key_object = jcePrivKey; % JCE私钥对象
            else
                % 密钥生成失败处理
                % 在实际应用中应该抛出异常而不是继续执行
                fprintf('错误(客户端): ECDHE密钥对生成失败: %s\n', errMsgGKP);
                obj.public_key_bytes = zeros(1, 32, 'uint8');
                obj.private_key_bytes = zeros(1, 32, 'uint8');
                obj.jce_private_key_object = [];
            end
            
            % ===== 步骤4: 生成客户端随机数 =====
            % 生成32字节的加密安全随机数
            % 注意：实际应用中应使用加密安全的随机数生成器
            obj.client_random = reshape(uint8(randi([0, 255], 32, 1)), 1, []);

            % ===== 步骤5: 初始化记录层序列号 =====
            % 序列号从0开始，每发送/接收一个加密记录递增1
            obj.client_record_send_seq_num = uint64(0);
            obj.server_record_recv_seq_num = uint64(0);

            % ===== 步骤6: 加载客户端证书和私钥 =====
            % 构造证书和私钥文件的路径
            current_file_path = fileparts(mfilename('fullpath'));
            src_path = fileparts(current_file_path);
            project_root = fileparts(src_path);
            
            % 客户端证书路径（DER格式）
            clientCertPath = fullfile(project_root, 'config', 'certificates', 'client', 'client_certificate.der');
            % 客户端私钥路径（PKCS#8 DER格式）
            clientKeyPath = fullfile(project_root, 'config', 'certificates', 'client', 'client_private_key_pkcs8.der');
            
            
            % 加载客户端证书
            obj.client_certificate_der_bytes = RSAUtils.loadBytesFromFile(clientCertPath);

            
            % 加载客户端RSA签名私钥
            obj.client_signing_jce_priv_key = RSAUtils.loadPKCS8PrivateKeyFromFile(clientKeyPath, 'RSA');

            
            % ===== 步骤7: 初始化应用层密钥属性 =====
            % 这些属性将在握手成功完成后由deriveApplicationKeys()方法填充
            obj.master_secret_prk = [];
            obj.client_application_traffic_secret_0 = [];
            obj.server_application_traffic_secret_0 = [];
            obj.client_application_write_key = [];
            obj.client_application_write_iv = [];
            obj.server_application_write_key = [];
            obj.server_application_write_iv = [];
            
            fprintf('客户端已初始化\n');
        end

        function message = generateClientHello(obj)
            % 生成TLS 1.3 ClientHello消息
            % 功能：构造并返回完整的ClientHello记录，包含所有必要的扩展
            % 参数：无
            % 返回:
            %   message - 完整的ClientHello记录字节数组 (包含5字节记录层头部)
            %
            % ClientHello消息结构:
            % - Legacy Version: 0x0303 (TLS 1.2，用于向后兼容)
            % - Random: 32字节随机数
            % - Legacy Session ID: 用于中间件兼容性
            % - Cipher Suites: 支持的密码套件列表
            % - Legacy Compression Methods: 仅包含null压缩（0x00）
            % - Extensions: 包括supported_versions, key_share, supported_groups等
            
            fprintf('客户端: 正在生成 ClientHello...\n');
            
            % ===== 辅助函数定义 =====
            % 将uint16转换为大端序2字节数组的辅助函数
            uint16_to_uint8_be = @(val) uint8([bitshift(val, -8), bitand(val, 255)]);

            % ===== 1. Legacy Version (2字节) =====
            % RFC 8446要求设置为0x0303 (TLS 1.2) 以兼容旧版本服务器
            legacy_version = TLSProtocol.TLS_1_2; % [0x03, 0x03]
            
            % ===== 2. Random (32字节) =====
            % 使用构造函数中生成的客户端随机数
            random_bytes = obj.client_random;
            
            % ===== 3. Legacy Session ID =====
            % TLS 1.3不使用会话ID进行会话恢复，但为了兼容性仍需发送
            % 生成32字节的会话ID供服务器回显验证
            obj.sent_session_id_len = uint8(32); % 会话ID长度
            obj.sent_session_id_val = uint8(randi([0 255], 1, 32)); % 随机会话ID值
            fprintf('  生成会话ID: %s\n', sprintf('%02x', obj.sent_session_id_val(1:8)));
            
            % ===== 4. Cipher Suites (密码套件列表) =====
            % 本实现仅支持 TLS_AES_128_GCM_SHA256 (0x1301)
            % 格式: [长度(2字节)][套件1(2字节)][套件2(2字节)]...
            cipher_suites_val = uint16_to_uint8_be(TLSProtocol.TLS_AES_128_GCM_SHA256); % [0x13, 0x01]
            cipher_suites_len_field = uint16_to_uint8_be(length(cipher_suites_val)); % [0x00, 0x02]
            fprintf('  支持的密码套件: TLS_AES_128_GCM_SHA256 (0x1301)\n');

            % ===== 5. Legacy Compression Methods =====
            % TLS 1.3禁用压缩，仅支持null压缩方法
            compression_methods_len_field = uint8(1); % 压缩方法列表长度
            compression_methods_val = TLSProtocol.COMPRESSION_NULL; % null压缩 (0x00)
            
            % ===== 6. Extensions (扩展) =====
            % TLS 1.3的关键功能都通过扩展实现
            
            % --- 6.1 Supported Versions扩展 (必需) ---
            % 声明客户端支持TLS 1.3
            sv_ext_type = uint16_to_uint8_be(TLSProtocol.EXT_SUPPORTED_VERSIONS); % [0x00, 0x2B]
            sv_ext_versions_list = uint16_to_uint8_be(TLSProtocol.TLS_1_3_VERSION_ID); % [0x03, 0x04]
            sv_ext_versions_list_len = uint8(length(sv_ext_versions_list)); % 版本列表长度
            sv_ext_payload = [sv_ext_versions_list_len, sv_ext_versions_list];
            sv_ext_len = uint16_to_uint8_be(length(sv_ext_payload));
            sv_ext = [sv_ext_type, sv_ext_len, sv_ext_payload];
            fprintf('  添加supported_versions扩展: TLS 1.3 (0x0304)\n');

            % --- 6.2 Key Share扩展 (必需) ---
            % 包含客户端的ECDHE公钥
            ks_ext_type = uint16_to_uint8_be(TLSProtocol.EXT_KEY_SHARE); % [0x00, 0x33]
            ks_entry_group = uint16_to_uint8_be(TLSProtocol.X25519); % [0x00, 0x1D] X25519曲线
            ks_entry_key_len = uint16_to_uint8_be(32); % X25519公钥长度固定为32字节
            ks_entry_key_val = obj.public_key_bytes; % 客户端X25519公钥
            
            % 构建KeyShareEntry: [group(2)][key_length(2)][key_exchange(32)]
            ks_entry_payload = [ks_entry_group, ks_entry_key_len, ks_entry_key_val];
            ks_client_shares_list_len_field = uint16_to_uint8_be(length(ks_entry_payload));
            ks_payload_data = [ks_client_shares_list_len_field, ks_entry_payload];
            ks_ext_len_field = uint16_to_uint8_be(length(ks_payload_data));
            key_share_ext = [ks_ext_type, ks_ext_len_field, ks_payload_data];
            fprintf('  添加key_share扩展: X25519 公钥 (%d字节)\n', length(obj.public_key_bytes));
            
            % --- 6.3 Supported Groups扩展 ---
            % 声明支持的ECDHE组/曲线
            sg_ext_type = uint16_to_uint8_be(TLSProtocol.EXT_SUPPORTED_GROUPS); % [0x00, 0x0A]
            sg_groups_list = uint16_to_uint8_be(TLSProtocol.X25519); % 仅支持X25519
            sg_groups_list_len = uint16_to_uint8_be(length(sg_groups_list));
            sg_payload = [sg_groups_list_len, sg_groups_list];
            sg_ext_len = uint16_to_uint8_be(length(sg_payload));
            sg_ext = [sg_ext_type, sg_ext_len, sg_payload];
            fprintf('  添加supported_groups扩展: X25519\n');
            
            % --- 6.4 Signature Algorithms扩展 ---
            % 声明支持的签名算法（用于证书验证）
            sa_ext_type = uint16_to_uint8_be(TLSProtocol.EXT_SIGNATURE_ALGORITHMS); % [0x00, 0x0D]
            % 支持的算法：RSA-PSS-SHA256 和 ECDSA-P256-SHA256
            sa_algs_list = [uint16_to_uint8_be(TLSProtocol.RSA_PSS_RSAE_SHA256), ... % [0x08, 0x04]
                           uint16_to_uint8_be(TLSProtocol.ECDSA_SECP256R1_SHA256)]; % [0x04, 0x03]
            sa_algs_list_len = uint16_to_uint8_be(length(sa_algs_list));
            sa_payload = [sa_algs_list_len, sa_algs_list];
            sa_ext_len = uint16_to_uint8_be(length(sa_payload));
            sa_ext = [sa_ext_type, sa_ext_len, sa_payload];
            fprintf('  添加signature_algorithms扩展: RSA-PSS-SHA256, ECDSA-P256-SHA256\n');
            
            % --- 组合所有扩展 ---
            extensions_payload = [sv_ext, key_share_ext, sg_ext, sa_ext];
            extensions_overall_len_field = uint16_to_uint8_be(length(extensions_payload));
            fprintf('  扩展总长度: %d字节\n', length(extensions_payload));
            
            % ===== 组装ClientHello消息体 =====
            client_hello_body_content = [
                legacy_version,...                   % TLS版本 (2字节)
                random_bytes,...                      % 随机数 (32字节)
                obj.sent_session_id_len,...          % 会话ID长度 (1字节)
                obj.sent_session_id_val,...          % 会话ID值 (N字节)
                cipher_suites_len_field,...          % 密码套件列表长度 (2字节)
                cipher_suites_val,...                % 密码套件列表
                compression_methods_len_field,...    % 压缩方法列表长度 (1字节)
                compression_methods_val,...          % 压缩方法列表
                extensions_overall_len_field,...     % 扩展总长度 (2字节)
                extensions_payload                % 扩展内容
            ];
            
            % ===== 添加握手消息头部 =====
            % 格式: [Type(1)][Length(3)][Content]
            handshake_type = TLSProtocol.HANDSHAKE_CLIENT_HELLO; % 0x01
            handshake_length_val = length(client_hello_body_content);
            
            % 将长度编码为3字节大端序uint24
            handshake_length_field = uint8([
                bitshift(handshake_length_val, -16),...           % 高位字节
                bitshift(bitand(handshake_length_val, 65280), -8),... % 中位字节
                bitand(handshake_length_val, 255)              % 低位字节
            ]);
            
            % 完整的ClientHello握手消息
            client_hello_handshake_msg = [handshake_type, handshake_length_field, client_hello_body_content];
            
            % ===== 将握手消息添加到transcript =====
            % 用于后续计算Transcript Hash
            obj.handshake_messages = [obj.handshake_messages, client_hello_handshake_msg];
            fprintf('  ClientHello握手消息已添加到transcript (长度: %d字节)\n', ...
                  length(client_hello_handshake_msg));
            
            % ===== 添加记录层头部 =====
            % 格式: [ContentType(1)][LegacyRecordVersion(2)][Length(2)][Fragment]
            record_type = TLSProtocol.RECORD_HANDSHAKE; % 0x16 (Handshake)
            record_legacy_version = TLSProtocol.TLS_1_0; % [0x03, 0x01] 兼容性
            record_length_val = length(client_hello_handshake_msg);
            record_length_field = uint16_to_uint8_be(record_length_val);
            
            record_header = [record_type, record_legacy_version, record_length_field];
            
            % ===== 组装最终消息 =====
            message = [record_header, client_hello_handshake_msg];
            
            fprintf('客户端: ✓ ClientHello生成完成\n');
            fprintf('  总长度: %d字节 (记录头: 5字节, 握手消息: %d字节)\n', ...
                  length(message), length(client_hello_handshake_msg));
            fprintf('====================================\n');
        end
        
        function success = parseServerHello(obj, server_hello_record_bytes)
            % 解析服务器发送的ServerHello消息
            % 功能：解析ServerHello记录并提取关键信息，包括服务器随机数、选择的密码套件、服务器公钥等
            % 参数:
            %   server_hello_record_bytes - 接收到的完整ServerHello记录字节数组 (包含记录层头部)
            % 返回:
            %   success - 解析成功并找到所有必需扩展时为true，否则为false
            %
            % ServerHello消息结构:
            % - Legacy Version: 0x0303 (兼容性字段)
            % - Random: 32字节服务器随机数
            % - Session ID Echo: 回显客户端发送的会话ID
            % - Cipher Suite: 服务器选择的密码套件
            % - Compression Method: 必须为null (0x00)
            % - Extensions: 必须包含supported_versions和key_share
            
            success = false; % 初始化返回状态
            fprintf('客户端: 正在解析ServerHello...\n');
            
            % 辅助函数
            uint16_to_uint8_be = @(val) uint8([bitshift(val, -8), bitand(val, 255)]);
            
            try
                % ===== 常量定义 =====
                RECORD_HEADER_LEN = 5;        % 记录层头部长度
                HANDSHAKE_MSG_HEADER_LEN = 4; % 握手消息头部长度
                
                % ===== 验证记录长度 =====
                if length(server_hello_record_bytes) < RECORD_HEADER_LEN + HANDSHAKE_MSG_HEADER_LEN
                    fprintf('错误: ServerHello记录过短 (%d字节)，无法解析。\n', ...
                          length(server_hello_record_bytes));
                    return;
                end
                
                % ===== 解析记录层头部 =====
                % 记录类型应该是0x16 (Handshake)
                record_type = server_hello_record_bytes(1);
                if record_type ~= TLSProtocol.RECORD_HANDSHAKE
                    fprintf('错误: 期望记录类型0x16，实际收到0x%02X\n', record_type);
                    return;
                end
                
                % 提取记录长度
                record_declared_len = double(server_hello_record_bytes(4))*256 + ...
                                    double(server_hello_record_bytes(5));
                actual_payload_len = length(server_hello_record_bytes) - RECORD_HEADER_LEN;
                
                % 验证声明长度与实际长度是否一致
                if record_declared_len ~= actual_payload_len
                    fprintf('错误: 记录长度不一致 (声明: %d, 实际: %d)\n', ...
                          record_declared_len, actual_payload_len);
                    return;
                end
                
                % ===== 提取握手消息 =====
                server_hello_handshake_msg = server_hello_record_bytes(RECORD_HEADER_LEN + 1 : end);
                
                % 将ServerHello消息添加到transcript
                obj.handshake_messages = [obj.handshake_messages, server_hello_handshake_msg];
                fprintf('  ServerHello握手消息已添加到transcript (长度: %d字节)\n', ...
                      length(server_hello_handshake_msg));
                
                % ===== 解析握手消息头部 =====
                idx = 1; % 解析位置指针
                
                % 验证消息类型是否为ServerHello (0x02)
                handshake_type = server_hello_handshake_msg(idx);
                if handshake_type ~= TLSProtocol.HANDSHAKE_SERVER_HELLO
                    fprintf('错误: 期望ServerHello(0x02)，实际收到0x%02X\n', handshake_type);
                    return;
                end
                idx = idx + 1;
                
                % 解析消息长度 (3字节uint24)
                handshake_body_len = double(server_hello_handshake_msg(idx))*65536 + ...
                                   double(server_hello_handshake_msg(idx+1))*256 + ...
                                   double(server_hello_handshake_msg(idx+2));
                idx = idx + 3;
                
                % 验证消息长度
                if handshake_body_len ~= (length(server_hello_handshake_msg) - HANDSHAKE_MSG_HEADER_LEN)
                    fprintf('错误: ServerHello消息长度不一致\n');
                    return;
                end
                
                % ===== 解析ServerHello消息体 =====
                
                % 1. Legacy Version (跳过，实际版本在supported_versions扩展中)
                idx = idx + 2; % 跳过2字节
                
                % 2. Server Random (32字节)
                obj.received_server_random = server_hello_handshake_msg(idx:idx+31);
                idx = idx + 32;
                fprintf('  服务器随机数: %s...\n', sprintf('%02x', obj.received_server_random(1:8)));
                
                % 3. Legacy Session ID Echo
                % 服务器应该回显客户端发送的会话ID
                obj.echoed_session_id_len_byte = server_hello_handshake_msg(idx);
                idx = idx + 1;
                echoed_sid_len = double(obj.echoed_session_id_len_byte);
                
                % 检查是否有足够的字节
                if echoed_sid_len > 0
                    if length(server_hello_handshake_msg) < (idx + echoed_sid_len - 1)
                        fprintf('错误: 消息过短，无法读取会话ID\n');
                        return;
                    end
                    obj.echoed_session_id_val_bytes = server_hello_handshake_msg(idx:idx+echoed_sid_len-1);
                    idx = idx + echoed_sid_len;
                else
                    obj.echoed_session_id_val_bytes = reshape(uint8([]), 1, 0);
                end
                
                % 验证会话ID回显是否正确
                if obj.echoed_session_id_len_byte == obj.sent_session_id_len && ...
                   (obj.sent_session_id_len == 0 || all(obj.echoed_session_id_val_bytes == obj.sent_session_id_val))
                    fprintf('  ✓ 会话ID回显验证通过\n');
                else
                    fprintf('  ✗ 会话ID回显不匹配!\n');
                    fprintf('    发送长度: %d, 回显长度: %d\n', ...
                          obj.sent_session_id_len, obj.echoed_session_id_len_byte);
                end
                
                % 4. Cipher Suite (2字节)
                obj.selected_cipher_suite = server_hello_handshake_msg(idx:idx+1);
                idx = idx + 2;
                
                % 验证选择的密码套件
                expected_suite = uint16_to_uint8_be(TLSProtocol.TLS_AES_128_GCM_SHA256);
                if all(obj.selected_cipher_suite == expected_suite)
                    fprintf('  ✓ 服务器选择的密码套件: TLS_AES_128_GCM_SHA256 (0x%02X%02X)\n', ...
                          obj.selected_cipher_suite(1), obj.selected_cipher_suite(2));
                else
                    fprintf('  ✗ 服务器选择了不支持的密码套件: 0x%02X%02X\n', ...
                          obj.selected_cipher_suite(1), obj.selected_cipher_suite(2));
                    % 根据安全策略，这里可能需要终止握手
                end
                
                % 5. Legacy Compression Method (应为0x00)
                compression_method = server_hello_handshake_msg(idx);
                idx = idx + 1;
                if compression_method ~= 0
                    fprintf('  警告: 压缩方法不为null (值: 0x%02X)\n', compression_method);
                end
                
                % ===== 解析扩展 =====
                % 检查是否有扩展长度字段
                if length(server_hello_handshake_msg) < (idx + 1)
                    fprintf('错误: 消息过短，无法读取扩展长度\n');
                    return;
                end
                
                % 扩展总长度 (2字节)
                extensions_total_len = double(server_hello_handshake_msg(idx))*256 + ...
                                     double(server_hello_handshake_msg(idx+1));
                idx = idx + 2;
                
                % 验证扩展长度
                if (idx + extensions_total_len - 1) > length(server_hello_handshake_msg)
                    fprintf('错误: 扩展长度 (%d) 超出消息边界\n', extensions_total_len);
                    return;
                end
                
                fprintf('  开始解析扩展 (总长度: %d字节)...\n', extensions_total_len);
                
                % 遍历所有扩展
                end_of_all_extensions_idx = idx + extensions_total_len;
                found_sh_key_share = false;      % 是否找到key_share扩展
                found_sh_sv = false;             % 是否找到supported_versions扩展
                
                while idx < end_of_all_extensions_idx
                    % 检查是否有足够的字节读取扩展头
                    if length(server_hello_handshake_msg) < (idx + 3)
                        fprintf('  警告: 扩展数据不完整\n');
                        break;
                    end
                    
                    % 扩展类型 (2字节)
                    ext_type = double(server_hello_handshake_msg(idx))*256 + ...
                             double(server_hello_handshake_msg(idx+1));
                    idx = idx + 2;
                    
                    % 扩展数据长度 (2字节)
                    ext_data_len = double(server_hello_handshake_msg(idx))*256 + ...
                                 double(server_hello_handshake_msg(idx+1));
                    idx = idx + 2;
                    
                    % 检查扩展数据长度
                    if length(server_hello_handshake_msg) < (idx + ext_data_len - 1)
                        fprintf('  警告: 扩展0x%04X数据不完整\n', ext_type);
                        break;
                    end
                    
                    % 提取扩展数据
                    ext_data_block = server_hello_handshake_msg(idx : idx + ext_data_len - 1);
                    
                    % --- 处理Supported Versions扩展 (0x002B) ---
                    if ext_type == TLSProtocol.EXT_SUPPORTED_VERSIONS
                        % ServerHello中此扩展应包含选择的版本 (2字节)
                        if ext_data_len == 2 && all(ext_data_block == uint16_to_uint8_be(TLSProtocol.TLS_1_3_VERSION_ID))
                            found_sh_sv = true;
                            fprintf('    ✓ supported_versions扩展: 选择TLS 1.3 (0x0304)\n');
                        else
                            fprintf('    ✗ supported_versions扩展无效或选择了非TLS 1.3版本\n');
                        end
                    end
                    
                    % --- 处理Key Share扩展 (0x0033) ---
                    if ext_type == TLSProtocol.EXT_KEY_SHARE
                        % ServerHello中的KeyShareEntry格式:
                        % group(2) + key_exchange_length(2) + key_exchange(variable)
                        expected_len = 2 + 2 + 32; % X25519: 组(2) + 长度(2) + 公钥(32)
                        
                        if ext_data_len == expected_len
                            % 提取组类型
                            ks_group_bytes = ext_data_block(1:2);
                            % 提取公钥长度
                            ks_key_len = double(ext_data_block(3))*256 + double(ext_data_block(4));
                            
                            % 验证是否为X25519且公钥长度为32
                            if all(ks_group_bytes == uint16_to_uint8_be(TLSProtocol.X25519)) && ks_key_len == 32
                                % 提取服务器的X25519公钥
                                obj.server_raw_public_key = ext_data_block(5 : 36);
                                found_sh_key_share = true;
                                fprintf('    ✓ key_share扩展: 获取X25519公钥成功\n');
                            else
                                fprintf('    ✗ key_share扩展: 组或公钥长度不匹配\n');
                            end
                        else
                            fprintf('    ✗ key_share扩展: 长度不符合预期 (%d vs %d)\n', ...
                                  ext_data_len, expected_len);
                        end
                    end
                    
                    % 移动到下一个扩展
                    idx = idx + ext_data_len;
                end
                
                % ===== 验证必需扩展 =====
                if found_sh_key_share && found_sh_sv
                    success = true;
                    fprintf('客户端: ✓ ServerHello解析成功\n');
                else
                    if ~found_sh_key_share
                        fprintf('客户端: ✗ 缺少必需的key_share扩展\n');
                    end
                    if ~found_sh_sv
                        fprintf('客户端: ✗ 缺少必需的supported_versions扩展\n');
                    end
                end
                
            catch ME_parse
                % 捕获解析过程中的异常
                fprintf('错误: 解析ServerHello时发生异常: %s\n', ME_parse.message);
                fprintf('  位置: %s (第%d行)\n', ME_parse.stack(1).name, ME_parse.stack(1).line);
                success = false;
            end
            
            fprintf('====================================\n');
        end

        function computed_secret_hex = calculateSharedSecret(obj)
            % 计算ECDHE共享密钥
            % 功能：使用客户端私钥和服务器公钥执行X25519密钥交换，计算共享密钥
            % 参数：无
            % 返回:
            %   computed_secret_hex - 十六进制表示的共享密钥字符串，失败时为空字符串
            %
            % 密钥交换过程:
            % 1. 验证必要的密钥材料是否存在
            % 2. 从服务器原始公钥字节重建JCE公钥对象
            % 3. 执行X25519 ECDHE计算: shared_secret = X25519(client_private, server_public)
            % 4. 成功后立即派生握手密钥
            
            computed_secret_hex = ''; % 初始化返回值
            fprintf('客户端: 开始计算ECDHE共享密钥...\n');
            
            % ===== 步骤1: 验证密钥材料 =====
            if isempty(obj.jce_private_key_object)
                fprintf('错误: 客户端JCE私钥对象为空\n');
                obj.shared_secret = [];
                return;
            end
            
            if isempty(obj.server_raw_public_key)
                fprintf('错误: 服务器公钥为空（可能ServerHello解析失败）\n');
                obj.shared_secret = [];
                return;
            end
            
            % ===== 步骤2: 重建服务器公钥对象 =====
            % 从32字节原始公钥重建JCE公钥对象
            fprintf('  从原始字节重建服务器X25519公钥对象...\n');
            [jceServerPublicKey, reconSuccess, reconErrMsg] = ...
                ECDHEUtils.reconstructJCEPublicKeyFromRawBytes(obj.server_raw_public_key);
            
            if ~reconSuccess
                fprintf('错误: 重建服务器公钥失败: %s\n', reconErrMsg);
                obj.shared_secret = [];
                return;
            end
            fprintf('  ✓ 服务器公钥对象重建成功\n');
            
            % ===== 步骤3: 执行ECDHE密钥交换 =====
            fprintf('  执行X25519密钥交换计算...\n');
            [secretBytes, successCSS, errMsgCSS] = ...
                ECDHEUtils.calculateSharedSecretFromJCEObjects(...
                    obj.jce_private_key_object, ... % 客户端私钥
                    jceServerPublicKey);         % 服务器公钥
            
            if successCSS
                % 密钥交换成功
                obj.shared_secret = secretBytes; % 保存32字节共享密钥
                fprintf('  ✓ ECDHE共享密钥计算成功 (%d字节)\n', length(secretBytes));
                
                % 将共享密钥转换为十六进制字符串（用于调试显示）
                import org.bouncycastle.util.encoders.Hex;
                computed_secret_hex = char(Hex.toHexString(obj.shared_secret));
                fprintf('  共享密钥(前8字节): %s...\n', computed_secret_hex(1:16));
                
                % ===== 步骤4: 立即派生握手密钥 =====
                fprintf('  开始派生握手阶段密钥...\n');
                if obj.deriveHandshakeKeys()
                    fprintf('  ✓ 握手密钥派生成功\n');
                else
                    fprintf('  ✗ 握手密钥派生失败\n');
                end
            else
                % 密钥交换失败
                fprintf('错误: ECDHE密钥交换失败: %s\n', errMsgCSS);
                obj.shared_secret = [];
            end
            
            fprintf('====================================\n');
        end
        
        function transcriptHash = getCurrentTranscriptHash(obj)
            % 计算当前Transcript Hash
            % 功能：对所有累积的握手消息计算SHA-256哈希值
            % 参数：无
            % 返回:
            %   transcriptHash - 32字节的SHA-256哈希值(uint8数组)，失败时为空数组
            %
            % Transcript Hash用途:
            % - 密钥派生的上下文输入
            % - CertificateVerify签名的输入
            % - Finished消息HMAC的输入
            % 确保握手消息的完整性和顺序性
            
            transcriptHash = []; % 初始化返回值
            
            % ===== 检查握手消息是否为空 =====
            if isempty(obj.handshake_messages)
                fprintf('警告: 握手消息累积器为空，无法计算Transcript Hash\n');
                return;
            end
            
            try
                % ===== 计算SHA-256哈希 =====
                import java.security.MessageDigest;
                
                % 创建SHA-256消息摘要实例
                md = MessageDigest.getInstance('SHA-256');
                
                % 更新摘要器内容（输入所有握手消息）
                md.update(obj.handshake_messages);
                
                % 计算最终哈希值
                hash_java_bytes = md.digest(); % 返回Java byte[]
                
                % 将Java字节数组转换为MATLAB uint8数组
                transcriptHash = reshape(typecast(hash_java_bytes, 'uint8'), 1, []);
                
                % ===== 验证哈希长度 =====
                if numel(transcriptHash) ~= 32
                    fprintf('错误: SHA-256哈希长度不正确 (%d字节，期望32字节)\n', ...
                          numel(transcriptHash));
                    transcriptHash = [];
                end
                
            catch ME
                % 捕获计算过程中的异常
                fprintf('错误: 计算Transcript Hash失败: %s\n', ME.message);
                transcriptHash = [];
            end
        end

        function success = deriveHandshakeKeys(obj)
            % 派生TLS 1.3握手阶段所需的所有密钥
            % 功能：根据RFC 8446规范，使用HKDF从共享密钥派生各种握手密钥
            % 参数：无
            % 返回:
            %   success - 所有密钥派生成功时为true
            %
            % 派生的密钥包括:
            % - client/server_handshake_traffic_secret: 流量密钥
            % - client/server_handshake_write_key: AES-128加密密钥
            % - client/server_handshake_write_iv: AES-GCM初始化向量
            % - client/server_finished_key: Finished消息HMAC密钥
            
            success = false;
            
            % ===== 常量定义 =====
            HASH_LEN_BYTES = 32;     % SHA-256输出长度
            AEAD_KEY_LEN_BYTES = 16; % AES-128密钥长度
            AEAD_IV_LEN_BYTES = 12;  % AES-GCM IV长度
            
            fprintf('客户端: 开始派生握手密钥 (HKDF-SHA256)...\n');
            
            % ===== 验证共享密钥 =====
            if isempty(obj.shared_secret) || numel(obj.shared_secret) ~= HASH_LEN_BYTES
                fprintf('错误: ECDHE共享密钥无效或长度不正确\n');
                return;
            end
            
            % ===== TLS 1.3密钥派生流程 (RFC 8446 Section 7.1) =====
            
            % --- 步骤1: 计算EarlySecret ---
            % EarlySecret = HKDF-Extract(salt=0, IKM=0)
            % 在无PSK场景下，salt和IKM都是全零
            fprintf('  步骤1: 计算EarlySecret...\n');
            salt_zeros = zeros(1, HASH_LEN_BYTES, 'uint8');
            ikm_zeros = zeros(1, HASH_LEN_BYTES, 'uint8');
            early_secret_prk = HKDFUtils.extract(salt_zeros, ikm_zeros);
            
            if isempty(early_secret_prk)
                fprintf('  ✗ EarlySecret计算失败\n');
                return;
            end
            fprintf('  ✓ EarlySecret计算成功\n');
            
            % --- 步骤2: 派生Derived Secret ---
            % Derived = HKDF-Expand-Label(EarlySecret, "derived", Hash(""), 32)
            fprintf('  步骤2: 计算Derived Secret...\n');
            
            % Hash("")的预计算值 (SHA-256空字符串哈希)
            empty_string_hash = uint8(org.bouncycastle.util.encoders.Hex.decode(...
                'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'))';
            
            derived_secret_for_handshake = HKDFUtils.expandLabel(...
                early_secret_prk,...      % Secret
                "derived",  ...           % Label
                empty_string_hash,...     % Context
                HASH_LEN_BYTES);       % Length
            
            if isempty(derived_secret_for_handshake)
                fprintf('  ✗ Derived Secret计算失败\n');
                return;
            end
            fprintf('  ✓ Derived Secret计算成功\n');
            
            % --- 步骤3: 计算HandshakeSecret ---
            % HandshakeSecret = HKDF-Extract(salt=Derived, IKM=shared_secret)
            fprintf('  步骤3: 计算HandshakeSecret PRK...\n');
            obj.handshake_secret_prk = HKDFUtils.extract(...
                derived_secret_for_handshake,...  % Salt
                obj.shared_secret);            % IKM (ECDHE共享密钥)
            
            if isempty(obj.handshake_secret_prk)
                fprintf('  ✗ HandshakeSecret PRK计算失败\n');
                return;
            end
            fprintf('  ✓ HandshakeSecret PRK计算成功\n');
            
            % --- 步骤4: 计算Transcript Hash ---
            % 此时应包含ClientHello和ServerHello
            fprintf('  步骤4: 计算Transcript-Hash(CH||SH)...\n');
            transcript_hash_ch_sh = obj.getCurrentTranscriptHash();
            
            if isempty(transcript_hash_ch_sh)
                fprintf('  ✗ Transcript Hash计算失败\n');
                return;
            end
            fprintf('  ✓ Transcript Hash计算成功\n');
            fprintf('    Hash(前8字节): %s...\n', sprintf('%02x', transcript_hash_ch_sh(1:8)));
            
            % --- 步骤5: 派生流量密钥 ---
            fprintf('  步骤5: 派生客户端和服务器流量密钥...\n');
            
            % client_handshake_traffic_secret = 
            %   HKDF-Expand-Label(HandshakeSecret, "c hs traffic", transcript_hash, 32)
            obj.client_handshake_traffic_secret = HKDFUtils.expandLabel(...
                obj.handshake_secret_prk,...    % Secret
                'c hs traffic',       ...       % Label
                transcript_hash_ch_sh, ...      % Context
                HASH_LEN_BYTES);             % Length
            
            % server_handshake_traffic_secret = 
            %   HKDF-Expand-Label(HandshakeSecret, "s hs traffic", transcript_hash, 32)
            obj.server_handshake_traffic_secret = HKDFUtils.expandLabel(...
                obj.handshake_secret_prk,...    % Secret
                's hs traffic',...              % Label
                transcript_hash_ch_sh,...       % Context
                HASH_LEN_BYTES);             % Length
            
            if isempty(obj.client_handshake_traffic_secret) || ...
               isempty(obj.server_handshake_traffic_secret)
                fprintf('  ✗ 流量密钥派生失败\n');
                return;
            end
            fprintf('  ✓ 客户端/服务器流量密钥派生成功\n');
            
            % --- 步骤6: 派生AEAD密钥和IV ---
            fprintf('  步骤6: 派生AEAD加密密钥和IV...\n');
            
            % 客户端写密钥 (用于加密客户端发送的消息)
            obj.client_handshake_write_key = HKDFUtils.expandLabel(...
                obj.client_handshake_traffic_secret, 'key', uint8([]), AEAD_KEY_LEN_BYTES);
            obj.client_handshake_write_iv = HKDFUtils.expandLabel(...
                obj.client_handshake_traffic_secret, 'iv', uint8([]), AEAD_IV_LEN_BYTES);
            
            % 服务器写密钥 (客户端用于解密服务器发送的消息)
            obj.server_handshake_write_key = HKDFUtils.expandLabel(...
                obj.server_handshake_traffic_secret, 'key', uint8([]), AEAD_KEY_LEN_BYTES);
            obj.server_handshake_write_iv = HKDFUtils.expandLabel(...
                obj.server_handshake_traffic_secret, 'iv', uint8([]), AEAD_IV_LEN_BYTES);
            
            % --- 步骤7: 派生Finished密钥 ---
            fprintf('  步骤7: 派生Finished消息密钥...\n');
            
            % 客户端Finished密钥 (用于生成客户端Finished)
            obj.client_finished_key = HKDFUtils.expandLabel(...
                obj.client_handshake_traffic_secret, 'finished', uint8([]), HASH_LEN_BYTES);
            
            % 服务器Finished密钥 (用于验证服务器Finished)
            obj.server_finished_key_for_verify = HKDFUtils.expandLabel(...
                obj.server_handshake_traffic_secret, 'finished', uint8([]), HASH_LEN_BYTES);
            
            % ===== 验证所有密钥是否派生成功 =====
            if any(cellfun('isempty', {
                obj.client_handshake_write_key,...
                obj.client_handshake_write_iv,...
                obj.server_handshake_write_key,...
                obj.server_handshake_write_iv,...
                obj.client_finished_key,...
                obj.server_finished_key_for_verify
            }))
                fprintf('  ✗ 部分密钥派生失败\n');
                return;
            end
            
            success = true;
            fprintf('客户端: ✓ 所有握手密钥派生成功\n');
            fprintf('  - 客户端加密密钥: %d字节\n', length(obj.client_handshake_write_key));
            fprintf('  - 客户端IV: %d字节\n', length(obj.client_handshake_write_iv));
            fprintf('  - 服务器加密密钥: %d字节\n', length(obj.server_handshake_write_key));
            fprintf('  - 服务器IV: %d字节\n', length(obj.server_handshake_write_iv));
            fprintf('====================================\n');
        end
        
        % ========== 解析服务器加密消息的方法 ==========

        function success = parseEncryptedExtensions(obj, encrypted_ee_record)
            % 解析服务器的EncryptedExtensions消息
            % 功能：解密并解析EncryptedExtensions消息，这是服务器发送的第一个加密消息
            % 参数:
            %   encrypted_ee_record - 加密的EncryptedExtensions记录字节数组
            % 返回:
            %   success - 解析成功时为true
            %
            % EncryptedExtensions消息:
            % - 包含不需要在ServerHello中发送的扩展
            % - 在TLS 1.3中总是加密的
            % - 通常包含SNI确认、ALPN选择等扩展
            
            success = false;
            fprintf('客户端: 正在解析EncryptedExtensions...\n');

            % ===== 检查解密密钥 =====
            if isempty(obj.server_handshake_write_key) || isempty(obj.server_handshake_write_iv)
                fprintf('错误: 服务器握手密钥/IV未派生\n');
                return;
            end
            
            % ===== 解密记录 =====
            fprintf('  使用AES-128-GCM解密记录...\n');
            [ee_handshake_plaintext, dec_success, dec_errMsg] = ...
                AES128Utils.decryptAndUnpackRecord(...
                    obj.server_handshake_write_key,...     % 解密密钥
                    obj.server_handshake_write_iv,...      % 解密IV
                    obj.server_record_recv_seq_num,...     % 序列号
                    encrypted_ee_record,...                % 加密数据
                    TLSProtocol.RECORD_HANDSHAKE);      % 期望的内部类型
            
            if ~dec_success
                fprintf('  ✗ 解密失败: %s\n', dec_errMsg);
                return;
            end
            fprintf('  ✓ 解密成功\n');
            
            % ===== 验证消息类型 =====
            if isempty(ee_handshake_plaintext) || ...
               ee_handshake_plaintext(1) ~= TLSProtocol.HANDSHAKE_ENCRYPTED_EXTENSIONS
                actual_type = MExceptionHelper.fif(isempty(ee_handshake_plaintext), -1, ee_handshake_plaintext(1));
                fprintf('错误: 消息类型不正确 (期望0x08, 实际0x%02X)\n', actual_type);
                return;
            end
            
            % ===== 添加到transcript =====
            obj.handshake_messages = [obj.handshake_messages, ee_handshake_plaintext];
            fprintf('  EncryptedExtensions已添加到transcript (%d字节)\n', ...
                  length(ee_handshake_plaintext));
            
            % ===== 解析消息内容 =====
            % 消息格式: Type(1) + Length(3) + Extensions
            if length(ee_handshake_plaintext) >= 4
                msg_length = double(ee_handshake_plaintext(2))*65536 + ...
                           double(ee_handshake_plaintext(3))*256 + ...
                           double(ee_handshake_plaintext(4));
                           
                if msg_length >= 2
                    % 提取扩展总长度
                    ext_total_len = double(ee_handshake_plaintext(5))*256 + ...
                                  double(ee_handshake_plaintext(6));
                    
                    if ext_total_len == 0
                        fprintf('  EncryptedExtensions不包含任何扩展\n');
                    else
                        fprintf('  EncryptedExtensions包含%d字节的扩展数据\n', ext_total_len);
                        % 这里可以添加具体扩展的解析逻辑
                    end
                end
            end
            
            % ===== 更新序列号 =====
            obj.server_record_recv_seq_num = obj.server_record_recv_seq_num + 1;
            success = true;
            
            fprintf('  ✓ EncryptedExtensions解析成功\n');
            fprintf('  下一个服务器序列号: %lu\n', obj.server_record_recv_seq_num);
            fprintf('====================================\n');
        end

        function success = parseCertificateRequest(obj, encrypted_cr_record)
            % 解析服务器的CertificateRequest消息
            % 功能：解密并解析CertificateRequest，提取证书请求上下文和支持的签名算法
            % 参数:
            %   encrypted_cr_record - 加密的CertificateRequest记录
            % 返回:
            %   success - 解析成功时为true
            %
            % CertificateRequest消息:
            % - 请求客户端发送证书进行双向认证
            % - 包含证书请求上下文（需在客户端Certificate消息中回显）
            % - 包含服务器支持的签名算法列表
            
            success = false;
            fprintf('客户端: 正在解析CertificateRequest...\n');

            % ===== 检查解密密钥 =====
            if isempty(obj.server_handshake_write_key) || isempty(obj.server_handshake_write_iv)
                fprintf('错误: 服务器握手密钥/IV未派生\n');
                return;
            end
            
            % ===== 解密记录 =====
            [cr_handshake_plaintext, dec_success, dec_errMsg] = ...
                AES128Utils.decryptAndUnpackRecord(...
                    obj.server_handshake_write_key,...
                    obj.server_handshake_write_iv,...
                    obj.server_record_recv_seq_num,...
                    encrypted_cr_record,...
                    TLSProtocol.RECORD_HANDSHAKE);
            
            if ~dec_success
                fprintf('  ✗ 解密失败: %s\n', dec_errMsg);
                return;
            end
            
            % ===== 验证消息类型 =====
            if isempty(cr_handshake_plaintext) || ...
               cr_handshake_plaintext(1) ~= TLSProtocol.HANDSHAKE_CERTIFICATE_REQUEST
                fprintf('错误: 消息类型不正确 (期望0x0D)\n');
                return;
            end
            
            % ===== 添加到transcript =====
            obj.handshake_messages = [obj.handshake_messages, cr_handshake_plaintext];
            fprintf('  CertificateRequest已添加到transcript (%d字节)\n', ...
                  length(cr_handshake_plaintext));
            
            % ===== 解析消息内容 =====
            idx = 5; % 跳过Type(1) + Length(3)
            
            % 1. Certificate Request Context
            if length(cr_handshake_plaintext) < idx
                fprintf('错误: 消息过短\n');
                return;
            end
            
            context_len = double(cr_handshake_plaintext(idx));
            idx = idx + 1;
            
            if context_len > 0
                if length(cr_handshake_plaintext) < (idx + context_len - 1)
                    fprintf('错误: 上下文长度超出消息边界\n');
                    return;
                end
                obj.received_certificate_request_context = cr_handshake_plaintext(idx : idx + context_len - 1);
            else
                obj.received_certificate_request_context = reshape(uint8([]), 1, 0);
            end
            idx = idx + context_len;
            
            fprintf('  证书请求上下文长度: %d字节\n', context_len);
            
            % 2. Extensions
            if length(cr_handshake_plaintext) < (idx + 1)
                fprintf('错误: 无法读取扩展长度\n');
                return;
            end
            
            extensions_len = double(cr_handshake_plaintext(idx))*256 + ...
                           double(cr_handshake_plaintext(idx+1));
            idx = idx + 2;
            
            fprintf('  开始解析扩展 (总长度: %d字节)...\n', extensions_len);
            
            % 遍历扩展，查找signature_algorithms
            end_of_extensions = idx + extensions_len;
            obj.received_sig_algs_from_cr = {};
            found_sig_algs = false;
            
            while idx < end_of_extensions
                if length(cr_handshake_plaintext) < (idx + 3)
                    break;
                end
                
                % 扩展类型和长度
                ext_type = double(cr_handshake_plaintext(idx))*256 + ...
                         double(cr_handshake_plaintext(idx+1));
                idx = idx + 2;
                
                ext_data_len = double(cr_handshake_plaintext(idx))*256 + ...
                             double(cr_handshake_plaintext(idx+1));
                idx = idx + 2;
                
                if length(cr_handshake_plaintext) < (idx + ext_data_len - 1)
                    break;
                end
                
                ext_data = cr_handshake_plaintext(idx : idx + ext_data_len - 1);
                
                % 处理signature_algorithms扩展 (0x000D)
                if ext_type == TLSProtocol.EXT_SIGNATURE_ALGORITHMS
                    if length(ext_data) >= 2
                        sig_algs_list_len = double(ext_data(1))*256 + double(ext_data(2));
                        
                        if sig_algs_list_len == (length(ext_data) - 2) && mod(sig_algs_list_len, 2) == 0
                            % 提取每个签名算法（2字节）
                            sig_algs_bytes = ext_data(3:end);
                            for i = 1:2:sig_algs_list_len
                                sig_alg = sig_algs_bytes(i:i+1);
                                obj.received_sig_algs_from_cr{end+1} = sig_alg;
                                
                                % 识别算法名称
                                if all(sig_alg == [0x08, 0x04])
                                    alg_name = 'RSA-PSS-SHA256';
                                elseif all(sig_alg == [0x04, 0x03])
                                    alg_name = 'ECDSA-P256-SHA256';
                                else
                                    alg_name = sprintf('未知(0x%02X%02X)', sig_alg(1), sig_alg(2));
                                end
                                fprintf('    支持的签名算法: %s\n', alg_name);
                            end
                            found_sig_algs = true;
                        end
                    end
                end
                
                idx = idx + ext_data_len;
            end
            
            if found_sig_algs
                fprintf('  ✓ 解析到%d个签名算法\n', length(obj.received_sig_algs_from_cr));
            else
                fprintf('  警告: 未找到signature_algorithms扩展\n');
            end
            
            % ===== 更新序列号 =====
            obj.server_record_recv_seq_num = obj.server_record_recv_seq_num + 1;
            success = true;
            
            fprintf('客户端: ✓ CertificateRequest解析成功\n');
            fprintf('====================================\n');
        end

        function success = parseCertificateMessageS(obj, encrypted_cert_s_record)
            % 解析服务器的Certificate消息
            % 功能：解密并解析服务器证书链，提取服务器签名公钥
            % 参数:
            %   encrypted_cert_s_record - 加密的服务器Certificate记录
            % 返回:
            %   success - 成功解析并提取公钥时为true
            %
            % Certificate消息结构:
            % - Certificate Request Context (服务器证书时为空)
            % - Certificate List: 证书链，从叶证书到根证书
            % - 每个证书条目包含: 证书数据长度 + DER编码证书 + 扩展
            
            success = false;
            fprintf('客户端: 正在解析服务器Certificate消息...\n');
            
            % ===== 检查解密密钥 =====
            if isempty(obj.server_handshake_write_key) || isempty(obj.server_handshake_write_iv)
                fprintf('错误: 服务器握手密钥/IV未派生\n');
                return;
            end
            
            % ===== 解密记录 =====
            [cert_s_handshake_plaintext, dec_success, dec_errMsg] = ...
                AES128Utils.decryptAndUnpackRecord(...
                    obj.server_handshake_write_key,...
                    obj.server_handshake_write_iv,...
                    obj.server_record_recv_seq_num,...
                    encrypted_cert_s_record,...
                    TLSProtocol.RECORD_HANDSHAKE);
            
            if ~dec_success
                fprintf('  ✗ 解密失败: %s\n', dec_errMsg);
                return;
            end
            
            % ===== 验证消息类型 =====
            if isempty(cert_s_handshake_plaintext) || ...
               cert_s_handshake_plaintext(1) ~= TLSProtocol.HANDSHAKE_CERTIFICATE
                fprintf('错误: 消息类型不正确 (期望0x0B)\n');
                return;
            end
            
            % ===== 添加到transcript =====
            obj.handshake_messages = [obj.handshake_messages, cert_s_handshake_plaintext];
            fprintf('  服务器Certificate已添加到transcript (%d字节)\n', ...
                  length(cert_s_handshake_plaintext));
            
            % ===== 解析消息内容 =====
            idx = 5; % 跳过Type(1) + Length(3)
            
            % 1. Certificate Request Context (服务器证书应为空)
            if length(cert_s_handshake_plaintext) < idx
                fprintf('错误: 消息过短\n');
                return;
            end
            
            cert_req_ctx_len = double(cert_s_handshake_plaintext(idx));
            idx = idx + 1;
            
            if cert_req_ctx_len ~= 0
                fprintf('  警告: 服务器证书包含非空上下文(%d字节)\n', cert_req_ctx_len);
                idx = idx + cert_req_ctx_len; % 跳过上下文
            end
            
            % 2. Certificate List
            if length(cert_s_handshake_plaintext) < (idx + 2)
                fprintf('错误: 无法读取证书列表长度\n');
                return;
            end
            
            cert_list_total_len = double(cert_s_handshake_plaintext(idx))*65536 + ...
                                double(cert_s_handshake_plaintext(idx+1))*256 + ...
                                double(cert_s_handshake_plaintext(idx+2));
            idx = idx + 3;
            
            fprintf('  证书链总长度: %d字节\n', cert_list_total_len);
            
            % 初始化证书链存储
            obj.received_server_certificate_chain_der = {};
            
            % 解析证书链中的每个证书
            cert_count = 0;
            end_of_list = idx + cert_list_total_len;
            
            while idx < end_of_list
                cert_count = cert_count + 1;
                fprintf('  解析证书 #%d...\n', cert_count);
                
                % 证书数据长度 (3字节)
                if length(cert_s_handshake_plaintext) < (idx + 2)
                    fprintf('    错误: 无法读取证书长度\n');
                    break;
                end
                
                cert_data_len = double(cert_s_handshake_plaintext(idx))*65536 + ...
                              double(cert_s_handshake_plaintext(idx+1))*256 + ...
                              double(cert_s_handshake_plaintext(idx+2));
                idx = idx + 3;
                
                % 证书数据
                if length(cert_s_handshake_plaintext) < (idx + cert_data_len - 1)
                    fprintf('    错误: 证书数据不完整\n');
                    break;
                end
                
                cert_data_bytes = cert_s_handshake_plaintext(idx : idx + cert_data_len - 1);
                obj.received_server_certificate_chain_der{end+1} = cert_data_bytes;
                idx = idx + cert_data_len;
                
                fprintf('    证书%d: %d字节\n', cert_count, cert_data_len);
                
                % 证书扩展长度 (2字节)
                if length(cert_s_handshake_plaintext) < (idx + 1)
                    fprintf('    错误: 无法读取扩展长度\n');
                    break;
                end
                
                cert_ext_len = double(cert_s_handshake_plaintext(idx))*256 + ...
                             double(cert_s_handshake_plaintext(idx+1));
                idx = idx + 2 + cert_ext_len; % 跳过扩展
                
                if cert_ext_len > 0
                    fprintf('    证书扩展: %d字节\n', cert_ext_len);
                end
            end
            
            % ===== 从第一个证书提取公钥 =====
            if ~isempty(obj.received_server_certificate_chain_der)
                fprintf('  从叶证书提取签名公钥...\n');
                first_cert_der = obj.received_server_certificate_chain_der{1};
                
                % 加载X.509证书对象
                temp_cert_obj = RSAUtils.loadX509CertificateFromBytes(first_cert_der);
                
                if ~isempty(temp_cert_obj)
                    % 提取公钥
                    obj.server_signing_jce_pub_key = temp_cert_obj.getPublicKey();
                    key_algorithm = char(obj.server_signing_jce_pub_key.getAlgorithm());
                    fprintf('  ✓ 成功提取服务器签名公钥 (算法: %s)\n', key_algorithm);
                    
                    % 显示证书信息
                    subject_dn = char(temp_cert_obj.getSubjectDN().toString());
                    fprintf('  证书主题: %s\n', subject_dn);
                else
                    fprintf('  ✗ 无法从证书加载公钥\n');
                end
            else
                fprintf('  警告: 未收到任何证书\n');
            end
            
            % ===== 更新序列号 =====
            obj.server_record_recv_seq_num = obj.server_record_recv_seq_num + 1;
            
            % 只有成功提取公钥才算成功
            success = ~isempty(obj.server_signing_jce_pub_key);
            
            if success
                fprintf('客户端: ✓ 服务器Certificate解析成功\n');
            else
                fprintf('客户端: ✗ 服务器Certificate解析失败（未能提取公钥）\n');
            end
            fprintf('====================================\n');
        end

        function success = parseAndVerifyCertificateVerifyS(obj, encrypted_cv_s_record)
            % 解析并验证服务器的CertificateVerify消息
            % 功能：解密CertificateVerify消息并验证服务器的数字签名
            % 参数:
            %   encrypted_cv_s_record - 加密的服务器CertificateVerify记录
            % 返回:
            %   success - 签名验证成功时为true
            %
            % CertificateVerify验证过程:
            % 1. 解密消息
            % 2. 提取签名算法和签名值
            % 3. 构造待验证数据: 64个空格 + "TLS 1.3, server CertificateVerify" + 0x00 + TranscriptHash
            % 4. 使用服务器公钥验证签名
            
            success = false;
            fprintf('客户端: 正在解析并验证服务器CertificateVerify...\n');
            uint16_to_uint8_be = @(val) uint8([bitshift(val, -8), bitand(val, 255)]);

            % ===== 检查前置条件 =====
            if isempty(obj.server_handshake_write_key) || isempty(obj.server_handshake_write_iv)
                fprintf('错误: 服务器握手密钥未派生\n');
                return;
            end
            
            if isempty(obj.server_signing_jce_pub_key)
                fprintf('错误: 服务器签名公钥未知（Certificate解析可能失败）\n');
                return;
            end
            
            % ===== 计算当前Transcript Hash =====
            % 包含: ClientHello || ServerHello || EncryptedExtensions || 
            %       CertificateRequest || Certificate
            transcript_hash_for_cv = obj.getCurrentTranscriptHash();
            if isempty(transcript_hash_for_cv)
                fprintf('错误: 无法计算Transcript Hash\n');
                return;
            end
            fprintf('  Transcript Hash计算成功\n');

            % ===== 解密记录 =====
            [cv_s_handshake_plaintext, dec_success, dec_errMsg] = ...
                AES128Utils.decryptAndUnpackRecord(...
                    obj.server_handshake_write_key,...
                    obj.server_handshake_write_iv,...
                    obj.server_record_recv_seq_num,...
                    encrypted_cv_s_record,...
                    TLSProtocol.RECORD_HANDSHAKE);
            
            if ~dec_success
                fprintf('  ✗ 解密失败: %s\n', dec_errMsg);
                return;
            end
            
            % ===== 验证消息类型 =====
            if isempty(cv_s_handshake_plaintext) || ...
               cv_s_handshake_plaintext(1) ~= TLSProtocol.HANDSHAKE_CERTIFICATE_VERIFY
                fprintf('错误: 消息类型不正确 (期望0x0F)\n');
                return;
            end
            
            % ===== 解析消息内容 =====
            idx = 5; % 跳过Type(1) + Length(3)
            
            % 1. 签名算法 (2字节)
            if length(cv_s_handshake_plaintext) < (idx + 1)
                fprintf('错误: 消息过短，无法读取签名算法\n');
                return;
            end
            
            received_sig_scheme_bytes = cv_s_handshake_plaintext(idx:idx+1);
            idx = idx + 2;
            
            % 识别签名算法
            if all(received_sig_scheme_bytes == uint16_to_uint8_be(TLSProtocol.RSA_PSS_RSAE_SHA256))
                sig_alg_name = 'RSA-PSS-SHA256';
            elseif all(received_sig_scheme_bytes == uint16_to_uint8_be(TLSProtocol.ECDSA_SECP256R1_SHA256))
                sig_alg_name = 'ECDSA-P256-SHA256';
            else
                sig_alg_name = sprintf('未知(0x%02X%02X)', received_sig_scheme_bytes(1), received_sig_scheme_bytes(2));
            end
            fprintf('  签名算法: %s\n', sig_alg_name);
            
            % 2. 签名长度和数据
            if length(cv_s_handshake_plaintext) < (idx + 1)
                fprintf('错误: 无法读取签名长度\n');
                return;
            end
            
            signature_len = double(cv_s_handshake_plaintext(idx))*256 + ...
                          double(cv_s_handshake_plaintext(idx+1));
            idx = idx + 2;
            
            if length(cv_s_handshake_plaintext) < (idx + signature_len - 1)
                fprintf('错误: 签名数据不完整\n');
                return;
            end
            
            received_signature_bytes = cv_s_handshake_plaintext(idx : idx + signature_len - 1);
            fprintf('  签名长度: %d字节\n', signature_len);
            
            % ===== 构造待验证数据 =====
            % RFC 8446: 64个0x20 + 上下文字符串 + 0x00 + Transcript-Hash
            prefix_spaces = repmat(uint8(32), 1, 64);  % 64个空格
            context_string = 'TLS 1.3, server CertificateVerify';
            separator = uint8(0);
            
            data_to_verify = [prefix_spaces, uint8(context_string), separator, transcript_hash_for_cv];
            fprintf('  待验证数据长度: %d字节\n', length(data_to_verify));
            
            % ===== 验证签名 =====
            verification_passed = false;
            
            % RSA-PSS-SHA256
            if all(received_sig_scheme_bytes == uint16_to_uint8_be(TLSProtocol.RSA_PSS_RSAE_SHA256))
                fprintf('  使用RSA-PSS-SHA256验证签名...\n');
                
                % PSS参数
                pssParams.hashAlg = 'SHA-256';
                pssParams.mgfAlg = 'MGF1';
                pssParams.mgfHashAlg = 'SHA-256';
                pssParams.saltLen = int32(32);
                pssParams.trailerField = int32(1);
                
                verification_passed = RSAUtils.verifySignaturePSS(...
                    obj.server_signing_jce_pub_key,...
                    data_to_verify,...
                    received_signature_bytes,...
                    pssParams);
                    
            % ECDSA-P256-SHA256
            elseif all(received_sig_scheme_bytes == uint16_to_uint8_be(TLSProtocol.ECDSA_SECP256R1_SHA256))
                fprintf('  使用ECDSA-P256-SHA256验证签名...\n');
                
                verification_passed = ECDSAUtils.verifySignature(...
                    obj.server_signing_jce_pub_key,...
                    data_to_verify,...
                    received_signature_bytes,...
                    'SHA256withECDSA');
            else
                fprintf('  警告: 不支持的签名算法\n');
            end
            
            % ===== 处理验证结果 =====
            if verification_passed
                fprintf('  ✓ 签名验证成功!\n');
                
                % 只有验证成功才添加到transcript
                obj.handshake_messages = [obj.handshake_messages, cv_s_handshake_plaintext];
                fprintf('  CertificateVerify已添加到transcript\n');
                
                success = true;
            else
                fprintf('  ✗ 签名验证失败!\n');
                fprintf('  可能原因: 证书与私钥不匹配、消息被篡改等\n');
            end
            
            % ===== 更新序列号 =====
            obj.server_record_recv_seq_num = obj.server_record_recv_seq_num + 1;
            
            fprintf('客户端: CertificateVerify处理完成\n');
            fprintf('====================================\n');
        end
        
        function success = parseAndVerifyFinishedS(obj, encrypted_fin_s_record)
            % 解析并验证服务器的Finished消息
            % 功能：解密Finished消息并验证HMAC，确认握手完整性
            % 参数:
            %   encrypted_fin_s_record - 加密的服务器Finished记录
            % 返回:
            %   success - HMAC验证成功时为true
            %
            % Finished消息验证:
            % verify_data = HMAC(finished_key, Transcript-Hash)
            % 其中finished_key从server_handshake_traffic_secret派生
            
            success = false;
            fprintf('客户端: 正在解析并验证服务器Finished消息...\n');
            
            % ===== 检查前置条件 =====
            if isempty(obj.server_handshake_write_key) || ...
               isempty(obj.server_handshake_write_iv) || ...
               isempty(obj.server_finished_key_for_verify)
                fprintf('错误: 解密/验证所需密钥未就绪\n');
                return;
            end
            
            % ===== 计算Transcript Hash =====
            % 包含所有消息直到CertificateVerify
            transcript_hash_for_fin = obj.getCurrentTranscriptHash();
            if isempty(transcript_hash_for_fin)
                fprintf('错误: 无法计算Transcript Hash\n');
                return;
            end

            % ===== 解密记录 =====
            [fin_s_handshake_plaintext, dec_success, dec_errMsg] = ...
                AES128Utils.decryptAndUnpackRecord(...
                    obj.server_handshake_write_key,...
                    obj.server_handshake_write_iv,...
                    obj.server_record_recv_seq_num,...
                    encrypted_fin_s_record,...
                    TLSProtocol.RECORD_HANDSHAKE);
            
            if ~dec_success
                fprintf('  ✗ 解密失败: %s\n', dec_errMsg);
                return;
            end
            
            % ===== 验证消息类型 =====
            if isempty(fin_s_handshake_plaintext) || ...
               fin_s_handshake_plaintext(1) ~= TLSProtocol.HANDSHAKE_FINISHED
                fprintf('错误: 消息类型不正确 (期望0x14)\n');
                return;
            end
            
            % ===== 提取verify_data =====
            % Finished消息格式: Type(1) + Length(3) + verify_data(32)
            verify_data_received = fin_s_handshake_plaintext(5:end);
            
            if length(verify_data_received) ~= 32
                fprintf('错误: verify_data长度不正确 (%d字节，期望32字节)\n', ...
                      length(verify_data_received));
                return;
            end
            
            % ===== 计算预期的verify_data =====
            expected_verify_data = HKDFUtils.hmacSha256(...
                obj.server_finished_key_for_verify,...
                transcript_hash_for_fin);
            
            % ===== 验证HMAC =====
            if all(verify_data_received == expected_verify_data)
                fprintf('  ✓ Finished消息验证成功!\n');
                fprintf('  服务器身份和握手完整性已确认\n');
                
                % 验证成功，添加到transcript
                obj.handshake_messages = [obj.handshake_messages, fin_s_handshake_plaintext];
                fprintf('  服务器Finished已添加到transcript\n');
                
                success = true;
            else
                fprintf('  ✗ Finished消息验证失败!\n');
                fprintf('  预期: %s\n', sprintf('%02x', expected_verify_data(1:8)));
                fprintf('  收到: %s\n', sprintf('%02x', verify_data_received(1:8)));
            end
            
            % ===== 更新序列号 =====
            obj.server_record_recv_seq_num = obj.server_record_recv_seq_num + 1;
            
            fprintf('客户端: 服务器Finished处理完成\n');
            fprintf('====================================\n');
        end

        % ========== 生成客户端认证消息的方法 ==========

        function encrypted_cert_c_record = generateCertificateMessageC(obj)
            % 生成客户端Certificate消息（响应服务器的CertificateRequest）
            % 功能：构造包含客户端证书的Certificate消息并加密
            % 参数：无
            % 返回:
            %   encrypted_cert_c_record - 加密的客户端Certificate记录，失败时为空
            %
            % Certificate消息结构:
            % - Certificate Request Context: 回显服务器发送的上下文
            % - Certificate List: 客户端证书链（通常只有一个证书）
            
            encrypted_cert_c_record = [];
            fprintf('客户端: 正在生成Certificate (Client)消息...\n');
            
            % ===== 检查前置条件 =====
            if isempty(obj.client_handshake_write_key) || isempty(obj.client_handshake_write_iv)
                fprintf('错误: 客户端握手加密密钥未就绪\n');
                return;
            end
            
            if isempty(obj.client_certificate_der_bytes)
                fprintf('错误: 客户端证书为空\n');
                return;
            end
            
            % ===== 构建Certificate消息内容 =====
            
            % 1. Certificate Request Context
            % 必须回显服务器CertificateRequest中的上下文
            ctx_bytes = obj.received_certificate_request_context;
            if isempty(ctx_bytes)
                ctx_bytes = reshape(uint8([]), 1, 0); % 确保是行向量
            end
            cert_req_ctx_len_byte = uint8(length(ctx_bytes));
            cert_req_ctx_payload = [cert_req_ctx_len_byte, ctx_bytes];
            fprintf('  证书请求上下文长度: %d字节\n', length(ctx_bytes));
            
            % 2. Certificate List
            % 构建证书条目
            single_cert_der = obj.client_certificate_der_bytes;
            
            % 证书数据长度 (3字节uint24)
            cert_data_len = length(single_cert_der);
            cert_data_len_field = uint8([
                bitshift(cert_data_len, -16),...
                bitshift(bitand(cert_data_len, 65280), -8),...
                bitand(cert_data_len, 255)
            ]);
            
            % 证书扩展（通常为空）
            cert_entry_extensions = uint8([0, 0]); % 空扩展列表
            
            % 组装证书条目
            certificate_entry = [cert_data_len_field, single_cert_der, cert_entry_extensions];
            
            % 证书列表（这里只有一个证书）
            certificate_list = certificate_entry;
            
            % 证书列表总长度 (3字节uint24)
            cert_list_len = length(certificate_list);
            cert_list_len_field = uint8([
                bitshift(cert_list_len, -16),...
                bitshift(bitand(cert_list_len, 65280), -8),...
                bitand(cert_list_len, 255)
            ]);
            
            % 完整的Certificate消息内容
            cert_c_content = [cert_req_ctx_payload, cert_list_len_field, certificate_list];
            
            % ===== 添加握手消息头部 =====
            handshake_type = TLSProtocol.HANDSHAKE_CERTIFICATE; % 0x0B
            handshake_len = length(cert_c_content);
            handshake_len_field = uint8([
                bitshift(handshake_len, -16),...
                bitshift(bitand(handshake_len, 65280), -8),...
                bitand(handshake_len, 255)
            ]);
            
            cert_c_handshake_msg = [handshake_type, handshake_len_field, cert_c_content];
            
            % 添加到transcript
            obj.handshake_messages = [obj.handshake_messages, cert_c_handshake_msg];
            fprintf('  客户端Certificate已添加到transcript (%d字节)\n', ...
                  length(cert_c_handshake_msg));
            
            % ===== 加密并打包 =====
            [encrypted_cert_c_record, enc_ok, enc_err] = ...
                AES128Utils.encryptAndPackageRecord(...
                    obj.client_handshake_write_key,...
                    obj.client_handshake_write_iv,...
                    obj.client_record_send_seq_num,...
                    cert_c_handshake_msg,...
                    TLSProtocol.RECORD_HANDSHAKE);
            
            if ~enc_ok
                fprintf('  ✗ 加密失败: %s\n', enc_err);
                encrypted_cert_c_record = [];
                return;
            end
            
            % 更新序列号
            obj.client_record_send_seq_num = obj.client_record_send_seq_num + 1;
            
            fprintf('  ✓ 客户端Certificate生成成功\n');
            fprintf('  加密记录长度: %d字节\n', length(encrypted_cert_c_record));
            fprintf('====================================\n');
        end

        function encrypted_cv_c_record = generateCertificateVerifyC(obj)
            % 生成客户端CertificateVerify消息
            % 功能：对握手消息创建数字签名，证明客户端拥有证书对应的私钥
            % 参数：无
            % 返回:
            %   encrypted_cv_c_record - 加密的CertificateVerify记录，失败时为空
            %
            % 签名过程:
            % 1. 选择签名算法（基于服务器CertificateRequest中的列表）
            % 2. 构造待签名数据
            % 3. 使用客户端私钥签名
            % 4. 加密并打包
            
            encrypted_cv_c_record = [];
            fprintf('客户端: 正在生成CertificateVerify (Client)消息...\n');
            uint16_to_uint8_be = @(val) uint8([bitshift(val, -8), bitand(val, 255)]);

            % ===== 检查前置条件 =====
            if isempty(obj.client_handshake_write_key) || isempty(obj.client_handshake_write_iv)
                fprintf('错误: 客户端握手加密密钥未就绪\n');
                return;
            end
            
            if isempty(obj.client_signing_jce_priv_key)
                fprintf('错误: 客户端签名私钥为空\n');
                return;
            end
            
            % ===== 选择签名算法 =====
            fprintf('  选择签名算法...\n');
            selected_sig_scheme_code = 0;
            chosen_sig_scheme_bytes = [];
            
            % 客户端支持的算法（按优先级）
            client_preferred_algs = [
                TLSProtocol.RSA_PSS_RSAE_SHA256,...    % 0x0804
                TLSProtocol.ECDSA_SECP256R1_SHA256  % 0x0403
            ];
            
            % 如果服务器提供了算法列表，选择双方都支持的
            if ~isempty(obj.received_sig_algs_from_cr)
                for i = 1:length(client_preferred_algs)
                    current_alg_code = client_preferred_algs(i);
                    current_alg_bytes = uint16_to_uint8_be(current_alg_code);
                    
                    % 检查服务器是否支持此算法
                    for j = 1:length(obj.received_sig_algs_from_cr)
                        if all(current_alg_bytes == obj.received_sig_algs_from_cr{j})
                            selected_sig_scheme_code = current_alg_code;
                            chosen_sig_scheme_bytes = current_alg_bytes;
                            fprintf('    选择算法: 0x%02X%02X (与服务器列表匹配)\n', ...
                                  chosen_sig_scheme_bytes(1), chosen_sig_scheme_bytes(2));
                            break;
                        end
                    end
                    
                    if ~isempty(chosen_sig_scheme_bytes)
                        break;
                    end
                end
            end
            
            % 如果没有匹配，使用默认算法
            if isempty(chosen_sig_scheme_bytes)
                % 检查私钥类型
                key_algorithm = char(obj.client_signing_jce_priv_key.getAlgorithm());
                
                if strcmp(key_algorithm, 'RSA')
                    selected_sig_scheme_code = TLSProtocol.RSA_PSS_RSAE_SHA256;
                    fprintf('    基于RSA私钥，选择RSA-PSS-SHA256\n');
                elseif strcmp(key_algorithm, 'EC')
                    selected_sig_scheme_code = TLSProtocol.ECDSA_SECP256R1_SHA256;
                    fprintf('    基于EC私钥，选择ECDSA-P256-SHA256\n');
                else
                    fprintf('错误: 不支持的私钥类型: %s\n', key_algorithm);
                    return;
                end
                
                chosen_sig_scheme_bytes = uint16_to_uint8_be(selected_sig_scheme_code);
            end
            
            % ===== 计算Transcript Hash =====
            % 包含所有消息直到客户端Certificate
            transcript_hash_for_cv = obj.getCurrentTranscriptHash();
            if isempty(transcript_hash_for_cv)
                fprintf('错误: 无法计算Transcript Hash\n');
                return;
            end
            
            % ===== 构造待签名数据 =====
            % RFC 8446: 64个0x20 + 上下文字符串 + 0x00 + Transcript-Hash
            prefix_spaces = repmat(uint8(32), 1, 64);
            context_string = 'TLS 1.3, client CertificateVerify';
            separator = uint8(0);
            
            data_to_sign = [prefix_spaces, uint8(context_string), separator, transcript_hash_for_cv];
            fprintf('  待签名数据长度: %d字节\n', length(data_to_sign));

            % ===== 执行签名 =====
            
            if selected_sig_scheme_code == TLSProtocol.RSA_PSS_RSAE_SHA256
                fprintf('  使用RSA-PSS-SHA256签名...\n');
                
                % PSS参数配置
                pssParams.hashAlg = 'SHA-256';
                pssParams.mgfAlg = 'MGF1';
                pssParams.mgfHashAlg = 'SHA-256';
                pssParams.saltLen = int32(32);     % 盐长度等于哈希长度
                pssParams.trailerField = int32(1);  % BouncyCastle标准值
                
                signature_bytes = RSAUtils.signDataPSS(...
                    obj.client_signing_jce_priv_key,...
                    data_to_sign,...
                    pssParams);
                    
            elseif selected_sig_scheme_code == TLSProtocol.ECDSA_SECP256R1_SHA256
                fprintf('  使用ECDSA-P256-SHA256签名...\n');
                
                signature_bytes = ECDSAUtils.signData(...
                    obj.client_signing_jce_priv_key,...
                    data_to_sign,...
                    'SHA256withECDSA');
            else
                fprintf('错误: 未实现的签名算法: 0x%04X\n', selected_sig_scheme_code);
                return;
            end
            
            if isempty(signature_bytes)
                fprintf('  ✗ 签名失败\n');
                return;
            end
            
            fprintf('  ✓ 签名成功 (%d字节)\n', length(signature_bytes));
            
            % ===== 构建CertificateVerify消息 =====
            % 签名长度 (2字节)
            signature_len_field = uint16_to_uint8_be(length(signature_bytes));
            
            % 消息内容: 算法(2) + 签名长度(2) + 签名
            cv_c_content = [chosen_sig_scheme_bytes, signature_len_field, signature_bytes];
            
            % 添加握手消息头部
            handshake_type = TLSProtocol.HANDSHAKE_CERTIFICATE_VERIFY; % 0x0F
            handshake_len = length(cv_c_content);
            handshake_len_field = uint8([
                bitshift(handshake_len, -16),...
                bitshift(bitand(handshake_len, 65280), -8),...
                bitand(handshake_len, 255)
            ]);
            
            cv_c_handshake_msg = [handshake_type, handshake_len_field, cv_c_content];
            
            % 添加到transcript
            obj.handshake_messages = [obj.handshake_messages, cv_c_handshake_msg];
            fprintf('  CertificateVerify已添加到transcript\n');
            
            % ===== 加密并打包 =====
            [encrypted_cv_c_record, enc_ok, enc_err] = ...
                AES128Utils.encryptAndPackageRecord(...
                    obj.client_handshake_write_key,...
                    obj.client_handshake_write_iv,...
                    obj.client_record_send_seq_num,...
                    cv_c_handshake_msg,...
                    TLSProtocol.RECORD_HANDSHAKE);
            
            if ~enc_ok
                fprintf('  ✗ 加密失败: %s\n', enc_err);
                encrypted_cv_c_record = [];
                return;
            end
            
            % 更新序列号
            obj.client_record_send_seq_num = obj.client_record_send_seq_num + 1;
            
            fprintf('客户端: ✓ CertificateVerify生成成功\n');
            fprintf('====================================\n');
        end

        function encrypted_fin_c_record = generateFinishedMessageC(obj)
            % 生成客户端Finished消息
            % 功能：生成包含HMAC的Finished消息，完成客户端握手
            % 参数：无
            % 返回:
            %   encrypted_fin_c_record - 加密的Finished记录，失败时为空
            %
            % Finished消息:
            % - 包含基于所有之前握手消息的HMAC
            % - 证明握手的完整性和客户端身份
            % - 是客户端发送的最后一个握手消息
            
            encrypted_fin_c_record = [];
            fprintf('客户端: 正在生成Finished (Client)消息...\n');
            
            % ===== 检查前置条件 =====
            if isempty(obj.client_handshake_write_key) || ...
               isempty(obj.client_handshake_write_iv) || ...
               isempty(obj.client_finished_key)
                fprintf('错误: 生成Finished所需密钥未就绪\n');
                return;
            end

            % ===== 计算Transcript Hash =====
            % 包含所有消息直到客户端CertificateVerify
            transcript_hash_for_fin = obj.getCurrentTranscriptHash();
            if isempty(transcript_hash_for_fin)
                fprintf('错误: 无法计算Transcript Hash\n');
                return;
            end
            fprintf('  Transcript Hash计算成功\n');
            
            % ===== 计算verify_data =====
            % verify_data = HMAC(finished_key, Transcript-Hash)
            verify_data = HKDFUtils.hmacSha256(...
                obj.client_finished_key,...
                transcript_hash_for_fin);
            
            if isempty(verify_data)
                fprintf('错误: HMAC计算失败\n');
                return;
            end
            
            fprintf('  verify_data计算成功 (%d字节)\n', length(verify_data));
            
            % ===== 构建Finished消息 =====
            % Finished消息内容就是verify_data
            fin_c_content = verify_data;
            
            % 添加握手消息头部
            handshake_type = TLSProtocol.HANDSHAKE_FINISHED; % 0x14
            handshake_len = length(fin_c_content); % 应该是32字节
            
            % 对于32字节长度，编码为 [0x00, 0x00, 0x20]
            handshake_len_field = uint8([0, 0, handshake_len]);
            
            fin_c_handshake_msg = [handshake_type, handshake_len_field, fin_c_content];
            
            % 添加到transcript
            obj.handshake_messages = [obj.handshake_messages, fin_c_handshake_msg];
            fprintf('  客户端Finished已添加到transcript\n');
            
            % ===== 加密并打包 =====
            [encrypted_fin_c_record, enc_ok, enc_err] = ...
                AES128Utils.encryptAndPackageRecord(...
                    obj.client_handshake_write_key,...
                    obj.client_handshake_write_iv,...
                    obj.client_record_send_seq_num,...
                    fin_c_handshake_msg,...
                    TLSProtocol.RECORD_HANDSHAKE);
            
            if ~enc_ok
                fprintf('  ✗ 加密失败: %s\n', enc_err);
                encrypted_fin_c_record = [];
                return;
            end
            
            % 更新序列号
            obj.client_record_send_seq_num = obj.client_record_send_seq_num + 1;
            
            fprintf('客户端: ✓ Finished消息生成成功\n');
            fprintf('  这是客户端最后一个握手消息\n');
            fprintf('====================================\n');
        end
        
        function success = deriveApplicationKeys(obj)
            % 派生应用层密钥
            % 功能：在握手完成后，派生用于加密应用数据的密钥
            % 参数：无
            % 返回:
            %   success - 应用层密钥派生成功时为true
            %
            % 派生过程:
            % 1. 从HandshakeSecret派生MasterSecret
            % 2. 使用最终的Transcript Hash派生应用流量密钥
            % 3. 从流量密钥派生AEAD密钥和IV
            % 4. 重置序列号为应用数据阶段做准备
            
            success = false;
            
            % ===== 常量定义 =====
            HASH_LEN_BYTES = 32;     % SHA-256输出长度
            AEAD_KEY_LEN_BYTES = 16; % AES-128密钥长度
            AEAD_IV_LEN_BYTES = 12;  % AES-GCM IV长度
            
            fprintf('客户端: 开始派生应用层密钥...\n');
            
            % ===== 验证HandshakeSecret =====
            if isempty(obj.handshake_secret_prk)
                fprintf('错误: HandshakeSecret PRK为空\n');
                return;
            end

            % ===== 步骤1: 派生MasterSecret =====
            fprintf('  步骤1: 从HandshakeSecret派生MasterSecret...\n');
            
            % 空字符串的SHA-256哈希（预计算值）
            empty_string_hash = uint8(org.bouncycastle.util.encoders.Hex.decode(...
                'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'))';
            
            % Derived = HKDF-Expand-Label(HandshakeSecret, "derived", Hash(""), 32)
            derived_from_hs = HKDFUtils.expandLabel(...
                obj.handshake_secret_prk,...
                "derived",...
                empty_string_hash,...
                HASH_LEN_BYTES);
            
            if isempty(derived_from_hs)
                fprintf('  ✗ DerivedSecret计算失败\n');
                return;
            end

            % MasterSecret = HKDF-Extract(Derived, 0)
            zeros_ikm = zeros(1, HASH_LEN_BYTES, 'uint8');
            obj.master_secret_prk = HKDFUtils.extract(derived_from_hs, zeros_ikm);
            
            if isempty(obj.master_secret_prk)
                fprintf('  ✗ MasterSecret PRK计算失败\n');
                return;
            end
            
            fprintf('  ✓ MasterSecret PRK计算成功\n');

            % ===== 步骤2: 计算最终Transcript Hash =====
            fprintf('  步骤2: 计算最终握手Transcript Hash...\n');
            
            % 此时应包含所有握手消息（包括双方的Finished）
            final_transcript_hash = obj.getCurrentTranscriptHash();
            
            if isempty(final_transcript_hash)
                fprintf('  ✗ 最终Transcript Hash计算失败\n');
                return;
            end
            
            fprintf('  ✓ Transcript Hash计算成功\n');
            fprintf('    包含消息数: %d字节\n', length(obj.handshake_messages));

            % ===== 步骤3: 派生应用流量密钥 =====
            fprintf('  步骤3: 派生客户端和服务器应用流量密钥...\n');
            
            % client_application_traffic_secret_0 = 
            %   HKDF-Expand-Label(MasterSecret, "c ap traffic", transcript, 32)
            obj.client_application_traffic_secret_0 = HKDFUtils.expandLabel(...
                obj.master_secret_prk,...
                'c ap traffic',...
                final_transcript_hash,...
                HASH_LEN_BYTES);
                
            % server_application_traffic_secret_0 = 
            %   HKDF-Expand-Label(MasterSecret, "s ap traffic", transcript, 32)
            obj.server_application_traffic_secret_0 = HKDFUtils.expandLabel(...
                obj.master_secret_prk,...
                's ap traffic',...
                final_transcript_hash,...
                HASH_LEN_BYTES);

            if isempty(obj.client_application_traffic_secret_0) || ...
               isempty(obj.server_application_traffic_secret_0)
                fprintf('  ✗ 应用流量密钥派生失败\n');
                return;
            end
            
            fprintf('  ✓ 应用流量密钥派生成功\n');
            
            % ===== 步骤4: 派生AEAD密钥和IV =====
            fprintf('  步骤4: 派生AEAD密钥和IV...\n');
            
            % 客户端写密钥（用于加密客户端发送的应用数据）
            obj.client_application_write_key = HKDFUtils.expandLabel(...
                obj.client_application_traffic_secret_0,...
                'key',...
                uint8([]),...
                AEAD_KEY_LEN_BYTES);
                
            obj.client_application_write_iv = HKDFUtils.expandLabel(...
                obj.client_application_traffic_secret_0,...
                'iv',...
                uint8([]),...
                AEAD_IV_LEN_BYTES);
                
            % 服务器写密钥（客户端用于解密服务器发送的应用数据）
            obj.server_application_write_key = HKDFUtils.expandLabel(...
                obj.server_application_traffic_secret_0,...
                'key',...
                uint8([]),...
                AEAD_KEY_LEN_BYTES);
                
            obj.server_application_write_iv = HKDFUtils.expandLabel(...
                obj.server_application_traffic_secret_0,...
                'iv',...
                uint8([]),...
                AEAD_IV_LEN_BYTES);

            % ===== 验证所有密钥 =====
            if any(cellfun('isempty', {
                obj.client_application_write_key,...
                obj.client_application_write_iv,...
                obj.server_application_write_key,...
                obj.server_application_write_iv
            }))
                fprintf('  ✗ 部分AEAD密钥派生失败\n');
                return;
            end
            
            fprintf('  ✓ 所有AEAD密钥和IV派生成功\n');
            fprintf('    客户端密钥: %d字节, IV: %d字节\n', ...
                  length(obj.client_application_write_key), ...
                  length(obj.client_application_write_iv));
            fprintf('    服务器密钥: %d字节, IV: %d字节\n', ...
                  length(obj.server_application_write_key), ...
                  length(obj.server_application_write_iv));
            
            % ===== 重置序列号 =====
            % TLS 1.3中，应用数据阶段的序列号独立计数
            obj.client_record_send_seq_num = uint64(0);
            obj.server_record_recv_seq_num = uint64(0);
            fprintf('  记录层序列号已重置为0\n');
            
            success = true;
            fprintf('客户端: ✓ 应用层密钥派生完成\n');
            fprintf('  准备进行加密的应用数据传输\n');
            fprintf('====================================\n');
        end
        
        % ========== 应用数据传输辅助方法（可选）==========
        
        function encrypted_record = encryptApplicationData(obj, plaintext_data)
            % 加密应用数据
            % 功能：使用应用层密钥加密数据
            % 参数:
            %   plaintext_data - 要加密的明文数据（uint8数组）
            % 返回:
            %   encrypted_record - 加密的TLS记录
            
            encrypted_record = [];
            
            if isempty(obj.client_application_write_key) || ...
               isempty(obj.client_application_write_iv)
                fprintf('错误: 应用层加密密钥未就绪\n');
                return;
            end
            
            % 使用应用数据记录类型加密
            [encrypted_record, success, errMsg] = ...
                AES128Utils.encryptAndPackageRecord(...
                    obj.client_application_write_key,...
                    obj.client_application_write_iv,...
                    obj.client_record_send_seq_num,...
                    plaintext_data,...
                    TLSProtocol.RECORD_APPLICATION_DATA); % 0x17
            
            if success
                obj.client_record_send_seq_num = obj.client_record_send_seq_num + 1;
                fprintf('应用数据加密成功 (%d字节 -> %d字节)\n', ...
                      length(plaintext_data), length(encrypted_record));
            else
                fprintf('应用数据加密失败: %s\n', errMsg);
            end
        end
        
        function [plaintext_data, success] = decryptApplicationData(obj, encrypted_record)
            % 解密应用数据
            % 功能：使用应用层密钥解密服务器发送的数据
            % 参数:
            %   encrypted_record - 加密的TLS记录
            % 返回:
            %   plaintext_data - 解密后的明文数据
            %   success - 解密成功时为true
            
            plaintext_data = [];
            success = false;
            
            if isempty(obj.server_application_write_key) || ...
               isempty(obj.server_application_write_iv)
                fprintf('错误: 应用层解密密钥未就绪\n');
                return;
            end
            
            [plaintext_data, success, errMsg] = ...
                AES128Utils.decryptAndUnpackRecord(...
                    obj.server_application_write_key,...
                    obj.server_application_write_iv,...
                    obj.server_record_recv_seq_num,...
                    encrypted_record,...
                    TLSProtocol.RECORD_APPLICATION_DATA); % 0x17
            
            if success
                obj.server_record_recv_seq_num = obj.server_record_recv_seq_num + 1;
                fprintf('应用数据解密成功 (%d字节)\n', length(plaintext_data));
            else
                fprintf('应用数据解密失败: %s\n', errMsg);
            end
        end
        
        function printHandshakeState(obj)
            % 打印当前握手状态（用于调试）
            % 功能：显示客户端的当前状态和密钥信息
            
            fprintf('\n========== 客户端握手状态 ==========\n');
            
            % 基本信息
            fprintf('握手消息累积长度: %d字节\n', length(obj.handshake_messages));
            fprintf('客户端发送序列号: %lu\n', obj.client_record_send_seq_num);
            fprintf('服务器接收序列号: %lu\n', obj.server_record_recv_seq_num);
            
            % 密钥状态
            fprintf('\n密钥派生状态:\n');
            fprintf('  ECDHE密钥对: %s\n', MExceptionHelper.fif(~isempty(obj.jce_private_key_object), '已生成', '未生成'));
            fprintf('  共享密钥: %s\n', MExceptionHelper.fif(~isempty(obj.shared_secret), '已计算', '未计算'));
            fprintf('  握手密钥: %s\n', MExceptionHelper.fif(~isempty(obj.handshake_secret_prk), '已派生', '未派生'));
            fprintf('  应用密钥: %s\n', MExceptionHelper.fif(~isempty(obj.master_secret_prk), '已派生', '未派生'));
            
            % 证书状态
            fprintf('\n证书状态:\n');
            fprintf('  客户端证书: %s\n', MExceptionHelper.fif(~isempty(obj.client_certificate_der_bytes), '已加载', '未加载'));
            fprintf('  客户端私钥: %s\n', MExceptionHelper.fif(~isempty(obj.client_signing_jce_priv_key), '已加载', '未加载'));
            fprintf('  服务器证书: %s\n', MExceptionHelper.fif(~isempty(obj.received_server_certificate_chain_der), '已接收', '未接收'));
            fprintf('  服务器公钥: %s\n', MExceptionHelper.fif(~isempty(obj.server_signing_jce_pub_key), '已提取', '未提取'));
            
            fprintf('=====================================\n\n');
        end
        
    end % methods
end % classdef

