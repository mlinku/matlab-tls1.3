% Server.m
% TLS 1.3 服务器实现类，遵循RFC 8446规范
% 提供TLS 1.3握手过程中服务器端的全部功能，包括密钥交换、证书验证和双向认证
% 
% 主要功能：
% 1. 解析客户端的ClientHello消息，提取客户端支持的参数
% 2. 生成ServerHello响应，选择密码套件和发送服务器公钥
% 3. 使用ECDHE算法计算共享密钥
% 4. 派生握手期间使用的对称密钥
% 5. 生成和验证证书相关消息（Certificate, CertificateVerify）
% 6. 完成握手并派生应用层密钥
%
classdef Server < handle
    properties
        % ========== 通信通道相关属性 ==========
        % 发送通道对象（预留接口，实际使用时需要替换为真实通信通道）
        % 例如：TCP Socket、UDP Socket或其他传输层协议
        send_channel
        
        % 接收通道对象（预留接口，实际使用时需要替换为真实通信通道）
        % 用于接收客户端发送的TLS消息
        recv_channel
        
        % ========== TLS状态管理 ==========
        % 当前TLS握手状态机的状态
        % 可能的值：'initial'（初始）、'sent_server_hello'（已发送ServerHello）、
        % 'sent_encrypted_extensions'（已发送加密扩展）、'handshake_complete'（握手完成）等
        state
        
        % 累积的握手消息字节序列，用于计算TranscriptHash
        % 格式：每个消息为 HandshakeType(1字节) + Length(3字节) + Content(N字节)
        % 这个累积消息用于生成握手过程中的各种哈希值，确保握手的完整性
        handshake_messages
        
        % ========== 服务器ECDHE密钥材料 ==========
        % 服务器生成的32字节随机数，用于握手过程
        % 在ServerHello消息中发送给客户端，用于派生会话密钥
        server_random
        
        % X25519椭圆曲线的原始私钥，32字节uint8数组
        % 这是服务器的ECDHE私钥，用于与客户端进行密钥协商
        private_key_bytes
        
        % X25519原生JCE（Java Cryptography Extension）私钥对象
        % 用于调用Java加密库进行密钥协商计算
        jce_private_key_object
        
        % X25519原始公钥，32字节uint8数组
        % 这是从私钥派生的公钥，将在ServerHello的key_share扩展中发送给客户端
        public_key_bytes

        % ========== 服务器签名认证材料 ==========
        % 服务器的RSA签名私钥（JCE对象）
        % 用于在CertificateVerify消息中对握手记录进行签名
        rsa_signing_jce_priv_key
        
        % 服务器的X.509证书对象
        % 包含服务器的身份信息和公钥，用于客户端验证服务器身份
        x509_server_certificate
        
        % 服务器证书的DER（Distinguished Encoding Rules）编码字节
        % 这是证书的二进制表示，将在Certificate消息中发送
        server_certificate_der_bytes

        % ========== 从ClientHello中解析的信息 ==========
        % 客户端会话ID长度字段，1字节
        % TLS 1.3中主要用于兼容性，实际不使用会话恢复
        received_client_session_id_len_byte
        
        % 客户端会话ID值，长度由上面的字段指定
        % 服务器需要在ServerHello中回显这个值以保持兼容性
        received_client_session_id_val_bytes
        
        % 客户端的X25519原始公钥，32字节
        % 从ClientHello的key_share扩展中提取，用于ECDHE密钥协商
        received_client_raw_public_key

        % ========== 从客户端Certificate消息中解析的信息 ==========
        % 客户端证书的DER编码字节
        % 在双向认证场景中，服务器需要验证客户端的证书
        received_client_certificate_der
        
        % 从客户端证书中提取的签名公钥（JCE对象）
        % 用于验证客户端的CertificateVerify消息
        received_client_signing_jce_pub_key
        
        % ========== ECDHE共享密钥和派生密钥 ==========
        % 与客户端协商得到的ECDHE共享密钥，32字节
        % 这是使用服务器私钥和客户端公钥计算得到的共享密钥
        shared_secret_with_client
        
        % 握手密钥的伪随机密钥（PRK），通过HKDF-Extract计算得到
        % 这是所有握手期间密钥的根密钥
        handshake_secret_prk
        
        % 客户端握手流量密钥，32字节
        % 用于派生客户端发送的加密握手消息的密钥和IV
        client_handshake_traffic_secret
        
        % 服务器握手流量密钥，32字节
        % 用于派生服务器发送的加密握手消息的密钥和IV
        server_handshake_traffic_secret
        
        % 用于解密客户端握手消息的AES-128密钥，16字节
        client_handshake_write_key
        
        % 用于解密客户端握手消息的初始化向量，12字节
        client_handshake_write_iv
        
        % 用于加密服务器握手消息的AES-128密钥，16字节
        server_handshake_write_key
        
        % 用于加密服务器握手消息的初始化向量，12字节
        server_handshake_write_iv
        
        % 用于生成服务器Finished消息的密钥，32字节
        % 通过HMAC-SHA256计算verify_data
        server_finished_key
        
        % 用于验证客户端Finished消息的密钥，32字节
        client_finished_key_for_verify
        
        % ========== 记录层序列号管理 ==========
        % 服务器已发送的加密记录序列号（uint64）
        % 每发送一个加密记录递增1，用于防止重放攻击
        server_record_send_seq_num
        
        % 服务器已接收的来自客户端的加密记录序列号（uint64）
        % 每接收一个加密记录递增1，确保消息的顺序性
        client_record_recv_seq_num

        % ========== CertificateRequest相关 ==========
        % 服务器生成并发送给客户端的证书请求上下文
        % 随机生成的字节序列，客户端必须在Certificate消息中回显
        certificate_request_context_sent
        
        % 选择的密码套件字节表示
        % TLS_AES_128_GCM_SHA256 (0x1301) 的字节形式 [0x13, 0x01]
        chosen_cipher_suite_bytes

        % ========== 应用层密钥相关属性 ==========
        % 主密钥PRK（伪随机密钥），32字节
        % 从握手密钥派生，是所有应用层密钥的根密钥
        master_secret_prk
        
        % 客户端应用流量密钥0，32字节
        % 用于派生客户端发送的应用数据加密密钥
        client_application_traffic_secret_0
        
        % 服务器应用流量密钥0，32字节
        % 用于派生服务器发送的应用数据加密密钥
        server_application_traffic_secret_0
        
        % 用于解密客户端应用数据的AES-128密钥，16字节
        client_application_write_key
        
        % 用于解密客户端应用数据的IV，12字节
        client_application_write_iv
        
        % 用于加密服务器应用数据的AES-128密钥，16字节
        server_application_write_key
        
        % 用于加密服务器应用数据的IV，12字节
        server_application_write_iv
    end
    
    methods
        function obj = Server(send_channel, recv_channel)
            % Server类构造函数
            % 初始化服务器对象，包括通信通道、密钥材料和状态
            % 
            % 参数:
            %   send_channel - 发送通道对象（可选）
            %   recv_channel - 接收通道对象（可选）
            %
            % 功能说明：
            % 1. 初始化通信通道
            % 2. 生成ECDHE密钥对（X25519）
            % 3. 生成服务器随机数
            % 4. 加载服务器证书和私钥
            % 5. 设置初始状态和默认参数

            % 辅助函数：将uint16转换为大端字节序的uint8数组
            % 大端序：高位字节在前，低位字节在后
            uint16_to_uint8_be = @(val) uint8([bitshift(val, -8), bitand(val, 255)]);

            % ===== 1. 初始化通信通道 =====
            obj.send_channel = send_channel;
            obj.recv_channel = recv_channel;

            % ===== 2. 初始化TLS状态机 =====
            obj.state = 'initial';  % 设置初始状态
            obj.handshake_messages = reshape(uint8([]), 1, 0);  % 初始化为空的行向量

            % ===== 3. 生成ECDHE密钥对 =====
            % 使用X25519椭圆曲线算法生成密钥对
            [rawPubKey, rawPrivKey, ~, jcePrivKey, ~, successGKP, errMsgGKP] = ECDHEUtils.generateFullX25519KeyPairObjects();

            % 检查密钥对生成是否成功
            if successGKP
                % 保存生成的密钥材料
                obj.public_key_bytes = rawPubKey;      % 32字节公钥
                obj.private_key_bytes = rawPrivKey;    % 32字节私钥
                obj.jce_private_key_object = jcePrivKey; % JCE私钥对象
            else
                % 密钥生成失败，记录错误并使用空密钥
                fprintf('错误(服务器): ECDHE密钥对生成失败: %s\n', errMsgGKP);
                obj.public_key_bytes = zeros(1, 32, 'uint8');
                obj.jce_private_key_object = [];
            end

            % ===== 4. 生成服务器随机数 =====
            % 生成32字节的随机数，用于ServerHello消息
            obj.server_random = reshape(uint8(randi([0, 255], 32, 1)), 1, []);

            % ===== 5. 设置密码套件 =====
            % TLS_AES_128_GCM_SHA256 (0x1301) - TLS 1.3推荐的密码套件
            % 使用AES-128-GCM进行加密，SHA256进行哈希
            obj.chosen_cipher_suite_bytes = uint16_to_uint8_be(TLSProtocol.TLS_AES_128_GCM_SHA256);

            % ===== 6. 初始化记录层序列号 =====
            % 序列号从0开始，每发送/接收一个加密记录递增
            obj.server_record_send_seq_num = uint64(0);  % 服务器发送序列号
            obj.client_record_recv_seq_num = uint64(0);  % 客户端接收序列号

            % ===== 7. 初始化其他属性 =====
            % 将所有其他属性初始化为空，确保对象状态的一致性
            obj.certificate_request_context_sent = [];
            obj.received_client_certificate_der = [];
            obj.received_client_signing_jce_pub_key = [];
            obj.server_finished_key = [];
            obj.client_finished_key_for_verify = [];
            obj.master_secret_prk = [];
            obj.client_application_traffic_secret_0 = [];
            obj.server_application_traffic_secret_0 = [];
            obj.client_application_write_key = [];
            obj.client_application_write_iv = [];
            obj.server_application_write_key = [];
            obj.server_application_write_iv = [];
            
            % ===== 8. 加载服务器证书和私钥 =====
            % 构建证书和私钥文件的路径
            % 假设项目结构为：project_root/src/Server.m
            current_file_path = fileparts(mfilename('fullpath'));  % 获取当前文件路径
            src_path = fileparts(current_file_path);               % 获取src目录路径
            project_root = fileparts(src_path);                     % 获取项目根目录
            
            % 构建证书和私钥的完整路径
            serverCertPath = fullfile(project_root, 'config', 'certificates', 'server', 'server_certificate.der');
            serverKeyPath = fullfile(project_root, 'config', 'certificates', 'server', 'server_private_key_pkcs8.der');

            % 加载服务器证书的DER编码字节
            obj.server_certificate_der_bytes = RSAUtils.loadBytesFromFile(serverCertPath);

            % 如果证书加载成功，创建X509证书对象
            if ~isempty(obj.server_certificate_der_bytes)
                % 从DER字节创建X509证书对象，用于后续操作
                obj.x509_server_certificate = RSAUtils.loadX509CertificateFromFile(serverCertPath);

                if isempty(obj.x509_server_certificate)
                    fprintf('警告(服务器): 服务器证书对象加载失败。\n');
                end
            else
                fprintf('警告(服务器): 服务器证书文件 "%s" 加载失败。\n', serverCertPath);
            end

            % 加载服务器的RSA私钥（PKCS#8格式）
            obj.rsa_signing_jce_priv_key = RSAUtils.loadPKCS8PrivateKeyFromFile(serverKeyPath, 'RSA');

            if isempty(obj.rsa_signing_jce_priv_key)
                fprintf('警告(服务器): 服务器RSA私钥文件 "%s" 加载失败。\n', serverKeyPath);
            end

            % 构造函数完成
            fprintf('服务器已初始化。\n');
        end
        
        function success = parseClientHello(obj, client_hello_record_bytes)
            % 解析ClientHello记录并提取关键信息
            % 
            % 功能说明：
            % 1. 验证记录格式和长度
            % 2. 提取握手消息并添加到累积消息中
            % 3. 解析ClientHello的各个字段
            % 4. 重点提取key_share扩展中的X25519公钥
            %
            % 参数:
            %   client_hello_record_bytes - 完整的ClientHello记录（包含记录层头部）
            %                               格式：[记录类型|版本|长度|握手消息]
            % 
            % 返回:
            %   success - 解析成功并找到X25519密钥时为true，否则为false
            %
            % ClientHello消息结构：
            % - legacy_version: 2字节（兼容性版本）
            % - random: 32字节（客户端随机数）
            % - session_id: 变长（会话ID）
            % - cipher_suites: 变长（支持的密码套件列表）
            % - compression_methods: 变长（压缩方法，TLS 1.3中为null）
            % - extensions: 变长（扩展列表）

            
            % 辅助函数：将uint16转换为大端字节序
            uint16_to_uint8_be = @(val) uint8([bitshift(val, -8), bitand(val, 255)]);

            try
                % ===== 1. 定义协议常量 =====
                RECORD_HEADER_LEN = 5;              % 记录头长度：类型(1) + 版本(2) + 长度(2)
                HANDSHAKE_HEADER_LEN_FIELD_BYTES = 3;  % 握手消息长度字段
                HANDSHAKE_TYPE_FIELD_BYTES = 1;    % 握手类型字段

                % ===== 2. 验证记录最小长度 =====
                if length(client_hello_record_bytes) < RECORD_HEADER_LEN + HANDSHAKE_TYPE_FIELD_BYTES + HANDSHAKE_HEADER_LEN_FIELD_BYTES
                    error('CH记录过短');
                end

                % ===== 3. 验证记录长度字段 =====
                % 从记录头提取声明的载荷长度（字节4-5）
                recordDeclaredLength = double(client_hello_record_bytes(4))*256 + double(client_hello_record_bytes(5));
                actualPayloadLength = length(client_hello_record_bytes) - RECORD_HEADER_LEN;

                if recordDeclaredLength ~= actualPayloadLength
                    error('CH记录长度与载荷不符');
                end

                % ===== 4. 提取握手消息部分 =====
                client_hello_handshake_message = client_hello_record_bytes(RECORD_HEADER_LEN + 1 : RECORD_HEADER_LEN + recordDeclaredLength);
                
                % 将握手消息添加到累积消息中（用于计算TranscriptHash）
                obj.handshake_messages = [obj.handshake_messages, client_hello_handshake_message];
                fprintf('  服务器: ClientHello握手消息 (长度 %d) 已添加到transcript。\n', length(client_hello_handshake_message));

                % ===== 5. 解析握手消息头部 =====
                idx = 1;  % 当前解析位置索引
                handshakeType = client_hello_handshake_message(idx);

                % 验证握手类型是否为ClientHello (0x01)
                if handshakeType ~= TLSProtocol.HANDSHAKE_CLIENT_HELLO
                    error('非ClientHello类型');
                end

                idx = idx + 1;
                
                % 解析3字节的握手消息长度
                handshakeLength = double(client_hello_handshake_message(idx))*65536 + ...
                                double(client_hello_handshake_message(idx+1))*256 + ...
                                double(client_hello_handshake_message(idx+2));
                idx = idx + 3;

                % 验证握手消息长度
                if handshakeLength ~= (length(client_hello_handshake_message)-4)
                    error('CH握手长度与内容不符');
                end

                % ===== 6. 解析ClientHello消息体 =====
                % 定义字段长度常量
                CH_LEGACY_VERSION_LEN = 2;    % 兼容版本字段长度
                CH_RANDOM_LEN = 32;           % 随机数字段长度  
                CH_SESSION_ID_LEN_FIELD_LEN = 1;  % 会话ID长度字段

                % 跳过legacy_version和random字段（暂不使用）
                idx_body = idx;
                idx_body = idx_body + CH_LEGACY_VERSION_LEN + CH_RANDOM_LEN;

                % 检查剩余长度
                if idx_body > length(client_hello_handshake_message)
                    error('CH body过短(sessID len)');
                end

                % ===== 7. 解析session_id =====
                % 读取会话ID长度
                obj.received_client_session_id_len_byte = client_hello_handshake_message(idx_body);
                idx_body = idx_body + CH_SESSION_ID_LEN_FIELD_LEN;
                sid_len_val = double(obj.received_client_session_id_len_byte);

                % 验证会话ID长度
                if length(client_hello_handshake_message) < (idx_body + sid_len_val -1) && sid_len_val > 0
                    error('CH body过短(sessID val)');
                end

                % 提取会话ID值（如果有）
                if sid_len_val > 0
                    obj.received_client_session_id_val_bytes = client_hello_handshake_message(idx_body : idx_body + sid_len_val - 1);
                else
                    obj.received_client_session_id_val_bytes = reshape(uint8([]), 1, 0);
                end

                idx_body = idx_body + sid_len_val;

                % ===== 8. 跳过密码套件列表 =====
                if length(client_hello_handshake_message) < (idx_body+1)
                    error('CH body过短(cs len)');
                end

                % 读取密码套件列表长度（2字节）
                cs_len = double(client_hello_handshake_message(idx_body))*256 + double(client_hello_handshake_message(idx_body+1));
                idx_body = idx_body + 2 + cs_len;  % 跳过整个密码套件列表

                % ===== 9. 跳过压缩方法列表 =====
                if length(client_hello_handshake_message) < idx_body
                    error('CH body过短(comp len)');
                end

                % 读取压缩方法列表长度（1字节）
                comp_len = double(client_hello_handshake_message(idx_body));
                idx_body = idx_body + 1 + comp_len;  % 跳过整个压缩方法列表

                % ===== 10. 解析扩展部分 =====
                if length(client_hello_handshake_message) < (idx_body+1)
                    error('CH body过短(ext total len)');
                end

                % 读取扩展总长度（2字节）
                extensions_total_len = double(client_hello_handshake_message(idx_body))*256 + ...
                                     double(client_hello_handshake_message(idx_body+1));
                idx_body = idx_body + 2;

                % 验证扩展长度
                if (idx_body + extensions_total_len - 1) > length(client_hello_handshake_message)
                    error('CH扩展总长度超出body');
                end

                % ===== 11. 遍历所有扩展寻找key_share =====
                end_of_all_extensions_idx_body = idx_body + extensions_total_len;
                found_client_x25519_key = false;  % 标记是否找到X25519密钥

                while idx_body < end_of_all_extensions_idx_body
                    % 检查是否有足够字节读取扩展类型和长度
                    if length(client_hello_handshake_message) < (idx_body+3)
                        break;
                    end

                    % 读取扩展类型（2字节）
                    ext_type_val = double(client_hello_handshake_message(idx_body))*256 + ...
                                  double(client_hello_handshake_message(idx_body+1));
                    idx_body = idx_body + 2;
                    
                    % 读取扩展数据长度（2字节）
                    ext_data_len = double(client_hello_handshake_message(idx_body))*256 + ...
                                  double(client_hello_handshake_message(idx_body+1));
                    idx_body = idx_body + 2;

                    % 验证扩展数据长度
                    if length(client_hello_handshake_message) < (idx_body+ext_data_len-1) && ext_data_len > 0
                        break;
                    end

                    % 提取当前扩展的数据块
                    current_extension_data_block = client_hello_handshake_message(idx_body:idx_body+ext_data_len-1);

                    % ===== 12. 处理key_share扩展 =====
                    if ext_type_val == TLSProtocol.EXT_KEY_SHARE  % 0x0033
                        % key_share扩展格式：
                        % - client_shares长度: 2字节
                        % - KeyShareEntry列表，每个包含：
                        %   - group: 2字节（曲线类型）
                        %   - key_exchange长度: 2字节
                        %   - key_exchange: 变长（公钥数据）
                        
                        if length(current_extension_data_block) >= 2  % 至少有列表长度
                            % 读取client_shares列表长度
                            client_shares_list_len = double(current_extension_data_block(1))*256 + ...
                                                   double(current_extension_data_block(2));
                            entry_idx_in_ext_data = 3;  % 第一个KeyShareEntry的起始位置

                            % 遍历KeyShareEntry列表
                            current_pos_in_list = 0;
                            while current_pos_in_list < client_shares_list_len
                                % 检查是否有足够字节读取一个entry
                                if (entry_idx_in_ext_data + 3) <= length(current_extension_data_block)
                                    % 读取group（2字节）
                                    group_bytes = current_extension_data_block(entry_idx_in_ext_data : entry_idx_in_ext_data+1);
                                    
                                    % 读取key_exchange长度（2字节）
                                    key_len = double(current_extension_data_block(entry_idx_in_ext_data+2))*256 + ...
                                            double(current_extension_data_block(entry_idx_in_ext_data+3));

                                    % 检查是否为X25519曲线（0x001D）且密钥长度正确（32字节）
                                    if all(group_bytes == uint16_to_uint8_be(TLSProtocol.X25519)) && key_len == 32
                                        % 验证密钥数据是否完整
                                        if (entry_idx_in_ext_data+4+key_len-1) <= length(current_extension_data_block)
                                            % 提取X25519公钥
                                            obj.received_client_raw_public_key = current_extension_data_block(entry_idx_in_ext_data+4 : entry_idx_in_ext_data+4+key_len-1);
                                            found_client_x25519_key = true;
                                            break;  % 找到后退出内层循环
                                        end
                                    end
                                    
                                    % 移动到下一个KeyShareEntry
                                    entry_idx_in_ext_data = entry_idx_in_ext_data + 4 + key_len;
                                    current_pos_in_list = current_pos_in_list + (4 + key_len);
                                else
                                    break;  % KeyShareEntry列表格式错误
                                end
                            end
                            
                            if found_client_x25519_key
                                break;  % 找到后退出外层扩展循环
                            end
                        end
                    end
                    
                    % TODO: 可以在这里解析其他扩展，如：
                    % - supported_versions（支持的TLS版本）
                    % - signature_algorithms（签名算法）
                    % - supported_groups（支持的椭圆曲线）
                    
                    % 移动到下一个扩展
                    idx_body = idx_body + ext_data_len;
                end

                % ===== 13. 设置解析结果 =====
                success = found_client_x25519_key;

                if success
                    fprintf('服务器: ClientHello关键信息解析完毕。\n');
                else
                    fprintf('服务器: ClientHello关键信息解析不完整或失败 (未找到X25519 key_share)。\n');
                end

            catch ME_parse
                % 捕获并报告解析过程中的任何异常
                fprintf('错误: 服务器解析ClientHello时发生异常: %s\n', ME_parse.message);
                success = false;
            end
        end
        
        function message = generateServerHello(obj)
            % 生成ServerHello消息，包括服务器随机数和ECDHE公钥
            % 
            % 功能说明：
            % 1. 构建ServerHello消息的各个字段
            % 2. 添加必要的TLS 1.3扩展（supported_versions, key_share）
            % 3. 将消息打包成完整的TLS记录
            % 4. 更新服务器状态
            %
            % 返回:
            %   message - 完整的ServerHello记录（包含记录层头部）
            %            格式：[记录头|握手消息]
            %
            % ServerHello消息结构：
            % - legacy_version: 2字节（0x0303，TLS 1.2）
            % - random: 32字节（服务器随机数）
            % - session_id_echo: 变长（回显客户端的session_id）
            % - cipher_suite: 2字节（选择的密码套件）
            % - compression_method: 1字节（TLS 1.3中为0）
            % - extensions: 变长（扩展列表）

            % 辅助函数：将uint16转换为大端字节序
            uint16_to_uint8_be = @(val) uint8([bitshift(val, -8), bitand(val, 255)]);

            % ===== 1. 构建ServerHello消息的基本字段 =====
            % legacy_version字段：TLS 1.2版本号（0x0303），用于向后兼容
            sh_legacy_version = TLSProtocol.TLS_1_2;
            
            % 服务器随机数：32字节，在构造函数中已生成
            sh_random = obj.server_random;
            
            % 会话ID回显：TLS 1.3要求服务器回显客户端发送的session_id
            sh_session_id_echo_len = obj.received_client_session_id_len_byte;
            sh_session_id_echo_val = obj.received_client_session_id_val_bytes;
            
            % 选择的密码套件：TLS_AES_128_GCM_SHA256 (0x1301)
            sh_cipher_suite_bytes = obj.chosen_cipher_suite_bytes;
            
            % 压缩方法：TLS 1.3中必须为null（0x00）
            sh_compression_method = TLSProtocol.COMPRESSION_NULL;

            % ===== 2. 构建扩展部分 =====
            extensions_payload_bytes = [];

            % --- 2.1 添加supported_versions扩展 ---
            % 这个扩展表明服务器选择使用TLS 1.3
            sv_ext_type = uint16_to_uint8_be(TLSProtocol.EXT_SUPPORTED_VERSIONS);  % 扩展类型
            sv_ext_selected_version = TLSProtocol.TLS_1_3;  % 选择的版本：TLS 1.3 (0x0304)
            sv_ext_payload = sv_ext_selected_version;       % 扩展数据就是版本号
            sv_ext_len = uint16_to_uint8_be(length(sv_ext_payload));  % 扩展长度
            
            % 组装supported_versions扩展
            sv_ext = [sv_ext_type, sv_ext_len, sv_ext_payload];
            extensions_payload_bytes = [extensions_payload_bytes, sv_ext];

            % --- 2.2 添加key_share扩展 ---
            % 这个扩展包含服务器的ECDHE公钥
            ks_ext_type = uint16_to_uint8_be(TLSProtocol.EXT_KEY_SHARE);  % 扩展类型
            
            % KeyShareEntry结构
            ks_entry_group = uint16_to_uint8_be(TLSProtocol.X25519);  % 曲线类型：X25519
            ks_entry_key_val = obj.public_key_bytes;                   % 32字节公钥
            ks_entry_key_len = uint16_to_uint8_be(length(ks_entry_key_val));  % 公钥长度
            
            % 组装KeyShareEntry
            ks_entry_payload = [ks_entry_group, ks_entry_key_len, ks_entry_key_val];
            
            % ServerHello中的key_share扩展直接包含一个KeyShareEntry（不是列表）
            ks_ext_len = uint16_to_uint8_be(length(ks_entry_payload));
            key_share_ext = [ks_ext_type, ks_ext_len, ks_entry_payload];
            extensions_payload_bytes = [extensions_payload_bytes, key_share_ext];

            % ===== 3. 计算扩展总长度 =====
            ext_overall_len_val = length(extensions_payload_bytes);
            ext_overall_len_f = uint16_to_uint8_be(ext_overall_len_val);

            % ===== 4. 组装完整的ServerHello消息体 =====
            server_hello_body_content = [sh_legacy_version, sh_random, sh_session_id_echo_len];

            % 如果有会话ID，添加会话ID值
            if sh_session_id_echo_len > 0 && ~isempty(sh_session_id_echo_val)
                server_hello_body_content = [server_hello_body_content, sh_session_id_echo_val];
            end

            % 添加密码套件、压缩方法和扩展
            server_hello_body_content = [server_hello_body_content, ...
                                       sh_cipher_suite_bytes, ...
                                       sh_compression_method, ...
                                       ext_overall_len_f, ...
                                       extensions_payload_bytes];

            % ===== 5. 添加握手消息头部 =====
            % 握手类型：ServerHello (0x02)
            hs_type = TLSProtocol.HANDSHAKE_SERVER_HELLO;
            
            % 计算握手消息长度（3字节表示）
            hs_len_val = length(server_hello_body_content);
            hs_len_f = uint8([bitshift(hs_len_val, -16), ...
                            bitshift(bitand(hs_len_val, 65280), -8), ...
                            bitand(hs_len_val, 255)]);

            % 组装完整的握手消息
            server_hello_handshake_payload = [hs_type, hs_len_f, server_hello_body_content];

            % ===== 6. 添加到累积握手消息 =====
            % 用于后续计算TranscriptHash
            obj.handshake_messages = [obj.handshake_messages, server_hello_handshake_payload];
            fprintf('  服务器: ServerHello握手消息 (长度 %d) 已添加到transcript。\n', length(server_hello_handshake_payload));

            % ===== 7. 添加记录层头部 =====
            % 记录类型：握手消息 (22)
            rec_type = TLSProtocol.RECORD_HANDSHAKE;
            
            % 记录版本：TLS 1.2 (0x0303)，用于兼容性
            rec_ver = TLSProtocol.TLS_1_2;
            
            % 记录长度：握手消息的长度
            rec_len_val = length(server_hello_handshake_payload);
            rec_len_f = uint16_to_uint8_be(rec_len_val);

            % 组装记录头
            rec_hdr = [rec_type rec_ver rec_len_f];
            
            % 组装完整的TLS记录
            message = [rec_hdr, server_hello_handshake_payload];

            % ===== 8. 更新服务器状态 =====
            obj.state = 'sent_server_hello';
            
            fprintf('服务器: ServerHello生成完成，总长度: %d字节\n', length(message));
        end

        function computed_secret_hex = calculateSharedSecret(obj)
            % 计算ECDHE共享密钥并派生握手密钥
            % 
            % 功能说明：
            % 1. 使用服务器私钥和客户端公钥计算ECDHE共享密钥
            % 2. 立即调用deriveHandshakeKeys()派生握手期间使用的对称密钥
            % 3. 将共享密钥转换为十六进制字符串返回（用于调试）
            %
            % 返回:
            %   computed_secret_hex - 十六进制表示的共享密钥字符串
            %                        失败时返回空字符串
            %
            % ECDHE密钥协商原理：
            % - 服务器私钥 + 客户端公钥 = 共享密钥
            % - 客户端私钥 + 服务器公钥 = 相同的共享密钥
            % - 这个共享密钥将用作后续密钥派生的输入

            computed_secret_hex = '';  % 初始化返回值

            % ===== 1. 检查必要的密钥材料 =====
            if isempty(obj.jce_private_key_object) || isempty(obj.received_client_raw_public_key)
                fprintf('错误(服务器): 服务器JCE原生私钥或客户端原始公钥字节为空。\n');
                obj.shared_secret_with_client = [];
                return;
            end

            % ===== 2. 重建客户端的JCE公钥对象 =====
            % 从原始字节重建Java加密扩展（JCE）兼容的公钥对象
            [jceClientPublicKey, reconSuccess, ~] = ECDHEUtils.reconstructJCEPublicKeyFromRawBytes(obj.received_client_raw_public_key);

            if ~reconSuccess
                fprintf('错误(服务器): 重建客户端JCE公钥失败.\n');
                obj.shared_secret_with_client = [];
                return;
            end

            % ===== 3. 执行ECDHE密钥协商 =====
            % 使用X25519算法计算共享密钥
            [secretBytes, successCSS, errMsgCSS] = ECDHEUtils.calculateSharedSecretFromJCEObjects(obj.jce_private_key_object,jceClientPublicKey);

            if successCSS
                % ===== 4. 保存共享密钥 =====
                obj.shared_secret_with_client = secretBytes;  % 32字节共享密钥
                
                % ===== 5. 立即派生握手密钥 =====
                % 这是关键步骤：计算出共享密钥后立即派生所有握手期间需要的密钥
                obj.deriveHandshakeKeys();

                % ===== 6. 转换为十六进制字符串（用于调试和日志） =====
                import org.bouncycastle.util.encoders.Hex;
                computed_secret_hex = char(Hex.toHexString(obj.shared_secret_with_client));
            else
                % 密钥协商失败
                fprintf('错误(服务器): 计算共享密钥失败: %s\n', errMsgCSS);
                obj.shared_secret_with_client = [];
            end
        end
        
        function transcriptHash = getCurrentTranscriptHash(obj)
            % 计算当前累积握手消息的SHA-256哈希值
            % 
            % 功能说明：
            % 这个函数计算到目前为止所有握手消息的哈希值，
            % 用于密钥派生和Finished消息的生成。
            % TLS 1.3使用这个哈希值确保握手的完整性。
            %
            % 返回:
            %   transcriptHash - 32字节的SHA-256哈希值
            %                   失败时返回空数组
            %
            % 使用场景：
            % 1. 派生握手流量密钥时（CH...SH的哈希）
            % 2. 生成CertificateVerify时（CH...Cert的哈希）
            % 3. 生成Finished消息时（CH...CV的哈希）
            % 4. 派生应用层密钥时（完整握手的哈希）

            transcriptHash = [];  % 初始化返回值

            % ===== 1. 检查握手消息是否为空 =====
            if isempty(obj.handshake_messages)
                fprintf('警告(服务器): 握手消息为空无法哈希。\n');
                return;
            end

            try
                % ===== 2. 使用Java的MessageDigest计算SHA-256 =====
                import java.security.MessageDigest;
                
                % 创建SHA-256消息摘要实例
                md = MessageDigest.getInstance('SHA-256');
                
                % 输入所有累积的握手消息
                md.update(obj.handshake_messages);
                
                % 计算最终的哈希值
                hash_java_bytes = md.digest();

                % ===== 3. 转换Java字节数组为MATLAB格式 =====
                % Java的byte[]需要转换为MATLAB的uint8数组
                transcriptHash = reshape(typecast(hash_java_bytes, 'uint8'), 1, []);

                % ===== 4. 验证哈希长度 =====
                % SHA-256的输出应该是32字节
                if numel(transcriptHash) ~= 32
                    fprintf('错误(服务器): SHA-256哈希长度不正确：%d字节\n', numel(transcriptHash));
                    transcriptHash = [];
                end

            catch ME
                % 捕获并报告计算过程中的错误
                fprintf('错误(服务器): 计算TranscriptHash: %s\n', ME.message);
                transcriptHash = [];
            end
        end
        
        function success = deriveHandshakeKeys(obj)
            % 使用HKDF派生TLS 1.3握手密钥
            % 
            % 功能说明：
            % 根据TLS 1.3规范，使用HKDF（HMAC-based Key Derivation Function）
            % 从ECDHE共享密钥派生出握手期间使用的所有对称密钥。
            % 
            % 派生的密钥包括：
            % 1. 客户端和服务器的握手流量密钥（traffic secret）
            % 2. 客户端和服务器的AEAD加密密钥和IV
            % 3. 客户端和服务器的Finished密钥
            %
            % 返回:
            %   success - 密钥派生成功时为true，失败为false
            %
            % TLS 1.3密钥派生流程：
            % 1. EarlySecret = HKDF-Extract(0, 0)
            % 2. DerivedSecret = HKDF-Expand-Label(EarlySecret, "derived", Hash(""))
            % 3. HandshakeSecret = HKDF-Extract(DerivedSecret, shared_secret)
            % 4. 从HandshakeSecret派生各种握手密钥

            success = false;  % 初始化返回值

            % ===== 定义常量 =====
            HASH_LEN_BYTES = 32;     % SHA-256输出长度（字节）
            AEAD_KEY_LEN_BYTES = 16; % AES-128-GCM密钥长度（字节）
            AEAD_IV_LEN_BYTES = 12;  % AES-GCM初始化向量长度（字节）

            ikm_ss = obj.shared_secret_with_client;  % 输入密钥材料（共享密钥）
            prefix = "服务器";  % 日志前缀

            fprintf('%s: 开始派生握手密钥...\n', prefix);

            % ===== 1. 验证共享密钥 =====
            if isempty(ikm_ss) || numel(ikm_ss) ~= HASH_LEN_BYTES
                fprintf('错误(%s): ECDHE共享密钥无效（空或长度不正确）。\n', prefix);
                return;
            end

            % ===== 2. 计算EarlySecret =====
            % TLS 1.3中，如果没有PSK，EarlySecret = HKDF-Extract(0, 0)
            Salt0 = zeros(1, HASH_LEN_BYTES, 'uint8');  % 全零盐值
            IKM0 = zeros(1, HASH_LEN_BYTES, 'uint8');   % 全零输入密钥材料
            EarlySec = HKDFUtils.extract(Salt0, IKM0);

            if isempty(EarlySec)
                fprintf('错误(%s): 计算EarlySecret失败。\n', prefix);
                return;
            end

            % ===== 3. 派生用于HandshakeSecret的DerivedSecret =====
            % 使用空字符串的SHA-256哈希作为上下文
            % SHA-256("")的值是固定的
            ContextHashEmpty = uint8(org.bouncycastle.util.encoders.Hex.decode(...
                'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'))';
            
            % HKDF-Expand-Label(EarlySecret, "derived", Hash(""), 32)
            DerivedSec = HKDFUtils.expandLabel(EarlySec, "derived", ContextHashEmpty, HASH_LEN_BYTES);

            if isempty(DerivedSec)
                fprintf('错误(%s): 计算DerivedSecret失败。\n', prefix);
                return;
            end

            % ===== 4. 计算HandshakeSecret =====
            % HandshakeSecret = HKDF-Extract(DerivedSecret, shared_secret)
            obj.handshake_secret_prk = HKDFUtils.extract(DerivedSec, ikm_ss);

            if isempty(obj.handshake_secret_prk)
                fprintf('错误(%s): 计算HandshakeSecret_PRK失败。\n', prefix);
                return;
            end

            % ===== 5. 计算ClientHello...ServerHello的记录哈希 =====
            % 此时handshake_messages应该包含ClientHello和ServerHello
            transcript_CHSH = obj.getCurrentTranscriptHash();

            if isempty(transcript_CHSH)
                fprintf('错误(%s): 计算TranscriptHash(CH||SH)失败。\n', prefix);
                return;
            end

            % ===== 6. 派生客户端握手流量密钥 =====
            % client_handshake_traffic_secret = 
            %   HKDF-Expand-Label(HandshakeSecret, "c hs traffic", Hash(CH...SH), 32)
            obj.client_handshake_traffic_secret = HKDFUtils.expandLabel(...
                obj.handshake_secret_prk, ...
                'c hs traffic', ...
                transcript_CHSH, ...
                HASH_LEN_BYTES);

            % ===== 7. 派生服务器握手流量密钥 =====
            % server_handshake_traffic_secret = 
            %   HKDF-Expand-Label(HandshakeSecret, "s hs traffic", Hash(CH...SH), 32)
            obj.server_handshake_traffic_secret = HKDFUtils.expandLabel(...
                obj.handshake_secret_prk, ...
                's hs traffic', ...
                transcript_CHSH, ...
                HASH_LEN_BYTES);

            if isempty(obj.client_handshake_traffic_secret) || isempty(obj.server_handshake_traffic_secret)
                fprintf('错误(%s): 派生traffic_secrets失败。\n', prefix);
                return;
            end

            % ===== 8. 从服务器流量密钥派生AEAD密钥和IV =====
            % 服务器使用这些密钥加密发送给客户端的握手消息
            obj.server_handshake_write_key = HKDFUtils.expandLabel(...
                obj.server_handshake_traffic_secret, ...
                'key', ...
                uint8([]), ...  % 空上下文
                AEAD_KEY_LEN_BYTES);
                
            obj.server_handshake_write_iv = HKDFUtils.expandLabel(...
                obj.server_handshake_traffic_secret, ...
                'iv', ...
                uint8([]), ...  % 空上下文
                AEAD_IV_LEN_BYTES);

            % ===== 9. 从客户端流量密钥派生AEAD密钥和IV =====
            % 服务器使用这些密钥解密客户端发送的握手消息
            obj.client_handshake_write_key = HKDFUtils.expandLabel(...
                obj.client_handshake_traffic_secret, ...
                'key', ...
                uint8([]), ...  % 空上下文
                AEAD_KEY_LEN_BYTES);
                
            obj.client_handshake_write_iv = HKDFUtils.expandLabel(...
                obj.client_handshake_traffic_secret, ...
                'iv', ...
                uint8([]), ...  % 空上下文
                AEAD_IV_LEN_BYTES);

            % ===== 10. 派生Finished密钥 =====
            % 服务器Finished密钥：用于生成服务器的Finished消息
            obj.server_finished_key = HKDFUtils.expandLabel(...
                obj.server_handshake_traffic_secret, ...
                'finished', ...
                uint8([]), ...  % 空上下文
                HASH_LEN_BYTES);
                
            % 客户端Finished密钥：用于验证客户端的Finished消息
            obj.client_finished_key_for_verify = HKDFUtils.expandLabel(...
                obj.client_handshake_traffic_secret, ...
                'finished', ...
                uint8([]), ...  % 空上下文
                HASH_LEN_BYTES);

            % ===== 11. 验证所有密钥材料是否成功派生 =====
            if any(cellfun('isempty', {
                obj.server_handshake_write_key, ...
                obj.server_handshake_write_iv, ...
                obj.client_handshake_write_key, ...
                obj.client_handshake_write_iv, ...
                obj.server_finished_key, ...
                obj.client_finished_key_for_verify}))
                fprintf('错误(%s): 派生AEAD或Finished密钥失败。\n', prefix);
                return;
            end

            % 所有密钥派生成功
            success = true;
            fprintf('%s: 所有握手密钥派生完成。\n', prefix);
            
        end
        
        function encrypted_ee_record = generateEncryptedExtensions(obj)
            % 生成EncryptedExtensions消息，加密并打包为记录
            % 
            % 功能说明：
            % EncryptedExtensions是ServerHello之后的第一个加密消息，
            % 包含不适合放在ServerHello中的扩展。
            % 在基本的TLS 1.3握手中，这个消息通常为空。
            %
            % 返回:
            %   encrypted_ee_record - 加密后的EncryptedExtensions记录
            %                        失败时返回空数组
            %
            % 消息格式：
            % - HandshakeType: 1字节 (0x08)
            % - Length: 3字节
            % - Extensions: 变长（这里为空列表，即0x0000）

            encrypted_ee_record = [];  % 初始化返回值

            % ===== 1. 检查加密所需密钥 =====
            if isempty(obj.server_handshake_write_key) || isempty(obj.server_handshake_write_iv)
                fprintf('错误(S): 加密EE所需密钥/IV未派生。\n');
                return;
            end

            % ===== 2. 确保序列号已初始化 =====
            % 序列号用于构造每个记录的唯一nonce
            if ~isa(obj.server_record_send_seq_num, 'uint64')
                obj.server_record_send_seq_num = uint64(0);
            end

            % ===== 3. 构造EncryptedExtensions内容 =====
            % 空扩展列表编码为两个字节：0x0000（长度为0）
            ee_content_plaintext_extensions = uint8([0 0]);
            
            % 握手消息类型：EncryptedExtensions (0x08)
            handshake_type_ee = TLSProtocol.HANDSHAKE_ENCRYPTED_EXTENSIONS;

            % ===== 4. 计算并编码消息长度 =====
            handshake_length_ee_val = length(ee_content_plaintext_extensions);
            
            % 长度字段为3字节，大端序
            handshake_length_ee_field = uint8([0, ...
                                              bitshift(handshake_length_ee_val, -8), ...
                                              bitand(handshake_length_ee_val, 255)]);
            
            % 对于较大的消息（虽然EE通常很小）
            if handshake_length_ee_val > (2^16-1)
                handshake_length_ee_field = uint8([
                    bitshift(bitand(handshake_length_ee_val, 16711680), -16), ...
                    bitshift(bitand(handshake_length_ee_val, 65280), -8), ...
                    bitand(handshake_length_ee_val, 255)
                ]);
            end

            % ===== 5. 组装完整的握手消息 =====
            ee_handshake_message_plaintext = [handshake_type_ee, ...
                                             handshake_length_ee_field, ...
                                             ee_content_plaintext_extensions];

            % ===== 6. 添加到累积握手消息 =====
            % 重要：必须在加密之前添加到transcript
            obj.handshake_messages = [obj.handshake_messages, ee_handshake_message_plaintext];
            fprintf('  服务器: EncryptedExtensions 明文 (长度 %d) 已添加到transcript。\n', ...
                    length(ee_handshake_message_plaintext));

            % ===== 7. 加密并打包为TLS记录 =====
            % 使用AES-128-GCM加密，添加认证标签
            [encrypted_ee_record, enc_success, ~] = AES128Utils.encryptAndPackageRecord(...
                obj.server_handshake_write_key, ...      % AES密钥
                obj.server_handshake_write_iv, ...       % 初始IV
                obj.server_record_send_seq_num, ...      % 序列号
                ee_handshake_message_plaintext, ...      % 明文
                TLSProtocol.RECORD_HANDSHAKE);          % 内部内容类型

            if ~enc_success
                fprintf('错误(S): 加密 EncryptedExtensions 失败.\n');
                encrypted_ee_record = [];
                return;
            end

            % ===== 8. 递增序列号 =====
            % 每个加密记录使用唯一的序列号
            obj.server_record_send_seq_num = obj.server_record_send_seq_num + 1;
            
            fprintf('服务器: EncryptedExtensions 已生成并加密 (记录长 %d)。\n', ...
                    length(encrypted_ee_record));
        end
        
        function encrypted_cr_record = generateCertificateRequest(obj)
            % 生成CertificateRequest消息，请求客户端证书
            % 
            % 功能说明：
            % 在双向认证场景中，服务器通过此消息请求客户端提供证书。
            % 消息包含一个随机上下文和服务器接受的签名算法列表。
            %
            % 返回:
            %   encrypted_cr_record - 加密后的CertificateRequest记录
            %                        失败时返回空数组
            %
            % CertificateRequest消息结构：
            % - certificate_request_context: 变长（随机字节）
            % - extensions: 变长
            %   - signature_algorithms: 服务器接受的签名算法列表

            encrypted_cr_record = [];  % 初始化返回值
            
            % 辅助函数：uint16转大端字节序
            uint16_to_uint8_be = @(val) uint8([bitshift(val, -8), bitand(val, 255)]);

            % ===== 1. 检查加密所需密钥 =====
            if isempty(obj.server_handshake_write_key) || isempty(obj.server_handshake_write_iv)
                fprintf('错误(S): 加密CR所需密钥/IV未派生。\n');
                return;
            end

            % ===== 2. 生成证书请求上下文 =====
            % 上下文是一个随机字节序列，客户端必须在其Certificate消息中回显
            context_len = uint8(8);  % 使用8字节的上下文
            obj.certificate_request_context_sent = uint8(randi([0, 255], 1, double(context_len)));
            
            % 构造上下文字段：长度(1字节) + 值
            certificate_request_context_field_payload = [context_len, obj.certificate_request_context_sent];

            % ===== 3. 构造扩展部分 =====
            all_cr_extensions_payload = [];
            
            % --- 3.1 signature_algorithms扩展 ---
            % 告诉客户端服务器支持哪些签名算法
            sig_algs_ext_type = uint16_to_uint8_be(TLSProtocol.EXT_SIGNATURE_ALGORITHMS);

            % 服务器支持的签名算法列表
            % ECDSA_SECP256R1_SHA256 (0x0403) - ECDSA with P-256 and SHA-256
            % RSA_PSS_RSAE_SHA256 (0x0804) - RSA-PSS with SHA-256
            server_preferred_sig_algs = [
                uint16_to_uint8_be(TLSProtocol.ECDSA_SECP256R1_SHA256), ...
                uint16_to_uint8_be(TLSProtocol.RSA_PSS_RSAE_SHA256)
            ];
            
            % 构造signature_algorithms扩展数据
            sig_algs_list_len_bytes = uint16_to_uint8_be(length(server_preferred_sig_algs));
            sig_algs_ext_data = [sig_algs_list_len_bytes, server_preferred_sig_algs];

            % 扩展长度
            sig_algs_ext_len_bytes = uint16_to_uint8_be(length(sig_algs_ext_data));
            
            % 组装完整的扩展
            signature_algorithms_extension = [sig_algs_ext_type, ...
                                            sig_algs_ext_len_bytes, ...
                                            sig_algs_ext_data];

            all_cr_extensions_payload = [all_cr_extensions_payload, signature_algorithms_extension];
            
            % TODO: 可以添加其他扩展，如：
            % - certificate_authorities: 可接受的CA列表
            % - oid_filters: OID过滤器
            % - signature_algorithms_cert: 证书签名算法

            % ===== 4. 计算扩展总长度 =====
            extensions_overall_len_val = length(all_cr_extensions_payload);
            extensions_overall_len_field = uint16_to_uint8_be(extensions_overall_len_val);

            % ===== 5. 组装CertificateRequest消息内容 =====
            cr_content_plaintext = [certificate_request_context_field_payload, ...
                                   extensions_overall_len_field, ...
                                   all_cr_extensions_payload];

            % ===== 6. 添加握手消息头部 =====
            handshake_type_cr = TLSProtocol.HANDSHAKE_CERTIFICATE_REQUEST;
            handshake_length_cr_val = length(cr_content_plaintext);
            
            % 3字节长度字段
            handshake_length_cr_field = uint8([
                bitshift(handshake_length_cr_val, -16), ...
                bitshift(bitand(handshake_length_cr_val, 65280), -8), ...
                bitand(handshake_length_cr_val, 255)
            ]);

            cr_handshake_message_plaintext = [handshake_type_cr, ...
                                             handshake_length_cr_field, ...
                                             cr_content_plaintext];

            % ===== 7. 添加到累积握手消息 =====
            obj.handshake_messages = [obj.handshake_messages, cr_handshake_message_plaintext];
            fprintf('  服务器: CertificateRequest 明文 (长度 %d) 已添加到transcript。\n', ...
                    length(cr_handshake_message_plaintext));

            % ===== 8. 加密并打包记录 =====
            [encrypted_cr_record, enc_success, ~] = AES128Utils.encryptAndPackageRecord(...
                obj.server_handshake_write_key, ...
                obj.server_handshake_write_iv, ...
                obj.server_record_send_seq_num, ...
                cr_handshake_message_plaintext, ...
                TLSProtocol.RECORD_HANDSHAKE);

            if ~enc_success
                fprintf('错误(S): 加密 CertificateRequest 失败.\n');
                encrypted_cr_record = [];
                return;
            end

            % ===== 9. 递增序列号 =====
            obj.server_record_send_seq_num = obj.server_record_send_seq_num + 1;
            
            fprintf('服务器: CertificateRequest 已生成并加密 (记录长 %d)。\n', ...
                    length(encrypted_cr_record));
        end

        function encrypted_cert_s_record = generateCertificateMessageS(obj)
            % 生成服务器Certificate消息，包含服务器证书链
            % 
            % 功能说明：
            % Certificate消息包含服务器的X.509证书，
            % 客户端将使用此证书验证服务器的身份。
            % 证书链从服务器证书开始，可选地包含中间CA证书。
            %
            % 返回:
            %   encrypted_cert_s_record - 加密后的Certificate记录
            %                            失败时返回空数组
            %
            % Certificate消息结构：
            % - certificate_request_context: 1字节（服务器发送时为0）
            % - certificate_list: 变长
            %   - 每个证书条目包含：
            %     - cert_data长度: 3字节
            %     - cert_data: DER编码的证书
            %     - extensions: 变长（通常为空）

            encrypted_cert_s_record = [];  % 初始化返回值

            % ===== 1. 检查必要条件 =====
            if isempty(obj.server_handshake_write_key) || isempty(obj.server_certificate_der_bytes)
                fprintf('错误(S): 加密Cert_S密钥或证书字节未就绪。\n');
                return;
            end

            % ===== 2. 构造certificate_request_context =====
            % 服务器主动发送Certificate时，上下文长度为0
            certificate_request_context_payload = uint8(0);
            
            % ===== 3. 准备证书数据 =====
            single_certificate_bytes = obj.server_certificate_der_bytes;

            % 每个证书条目的扩展（这里为空）
            cert_entry_extensions_bytes = uint8([0 0]);  % 空扩展列表
            
            % 计算证书数据长度（3字节表示）
            cert_data_len = length(single_certificate_bytes);
            cert_data_len_field = uint8([
                bitshift(cert_data_len, -16), ...
                bitshift(bitand(cert_data_len, 65280), -8), ...
                bitand(cert_data_len, 255)
            ]);

            % ===== 4. 组装证书条目 =====
            % 格式：证书长度 + 证书数据 + 扩展
            certificate_entry_payload = [cert_data_len_field, ...
                                       single_certificate_bytes, ...
                                       cert_entry_extensions_bytes];

            % ===== 5. 构造证书列表 =====
            % 这里只有一个证书（服务器证书）
            % TODO: 如果需要发送证书链，在这里循环添加更多certificate_entry_payload
            certificate_list_payload = certificate_entry_payload;

            % 计算证书列表总长度（3字节表示）
            certificate_list_len_val = length(certificate_list_payload);
            certificate_list_len_field = uint8([
                bitshift(certificate_list_len_val, -16), ...
                bitshift(bitand(certificate_list_len_val, 65280), -8), ...
                bitand(certificate_list_len_val, 255)
            ]);

            % ===== 6. 组装Certificate消息内容 =====
            cert_s_content_plaintext = [certificate_request_context_payload, ...
                                       certificate_list_len_field, ...
                                       certificate_list_payload];

            % ===== 7. 添加握手消息头部 =====
            handshake_type_cert = TLSProtocol.HANDSHAKE_CERTIFICATE;
            handshake_length_cert_val = length(cert_s_content_plaintext);
            
            % 3字节长度字段
            handshake_length_cert_field = uint8([
                bitshift(handshake_length_cert_val, -16), ...
                bitshift(bitand(handshake_length_cert_val, 65280), -8), ...
                bitand(handshake_length_cert_val, 255)
            ]);

            cert_s_handshake_message_plaintext = [handshake_type_cert, ...
                                                 handshake_length_cert_field, ...
                                                 cert_s_content_plaintext];

            % ===== 8. 添加到累积握手消息 =====
            obj.handshake_messages = [obj.handshake_messages, cert_s_handshake_message_plaintext];
            fprintf('  服务器: Certificate (Server) 明文 (长度 %d) 已添加到transcript。\n', ...
                    length(cert_s_handshake_message_plaintext));

            % ===== 9. 加密并打包记录 =====
            [encrypted_cert_s_record, enc_success, ~] = AES128Utils.encryptAndPackageRecord(...
                obj.server_handshake_write_key, ...
                obj.server_handshake_write_iv, ...
                obj.server_record_send_seq_num, ...
                cert_s_handshake_message_plaintext, ...
                TLSProtocol.RECORD_HANDSHAKE);

            if ~enc_success
                fprintf('错误(S): 加密 Certificate (Server) 失败.\n');
                encrypted_cert_s_record = [];
                return;
            end

            % ===== 10. 递增序列号 =====
            obj.server_record_send_seq_num = obj.server_record_send_seq_num + 1;
            
            fprintf('服务器: Certificate (Server) 已生成并加密 (记录长 %d)。\n', ...
                    length(encrypted_cert_s_record));
        end
        
        function encrypted_cv_s_record = generateCertificateVerifyS(obj)
            % 生成服务器CertificateVerify消息，包含服务器证书签名
            % 
            % 功能说明：
            % CertificateVerify消息证明服务器拥有证书对应的私钥。
            % 服务器使用其私钥对握手记录的哈希进行签名。
            % 这是TLS 1.3中身份认证的关键步骤。
            %
            % 返回:
            %   encrypted_cv_s_record - 加密后的CertificateVerify记录
            %                          失败时返回空数组
            %
            % CertificateVerify消息结构：
            % - signature_scheme: 2字节（使用的签名算法）
            % - signature: 变长
            %   - 长度: 2字节
            %   - 签名数据: 变长
            %
            % 签名的数据格式（TLS 1.3特定）：
            % - 64个0x20字节（空格）
            % - 上下文字符串 "TLS 1.3, server CertificateVerify"
            % - 0x00字节（分隔符）
            % - 握手记录的SHA-256哈希

            encrypted_cv_s_record = [];  % 初始化返回值
            
            % 辅助函数
            uint16_to_uint8_be = @(val) uint8([bitshift(val, -8), bitand(val, 255)]);

            % ===== 1. 检查必要条件 =====
            if isempty(obj.server_handshake_write_key) || isempty(obj.rsa_signing_jce_priv_key)
                fprintf('错误(S): 加密CV_S或签名密钥未就绪。\n');
                return;
            end

            % ===== 2. 选择签名算法 =====
            % 使用RSA-PSS-RSAE-SHA256 (0x0804)
            % TODO: 应该基于客户端的supported_signature_algorithms和服务器证书类型选择
            selected_signature_scheme_bytes = uint16_to_uint8_be(TLSProtocol.RSA_PSS_RSAE_SHA256);

            % ===== 3. 设置RSA-PSS参数 =====
            % PSS (Probabilistic Signature Scheme) 参数
            pssParams.hashAlg = 'SHA-256';       % 哈希算法
            pssParams.mgfAlg = 'MGF1';           % 掩码生成函数
            pssParams.mgfHashAlg = 'SHA-256';    % MGF使用的哈希算法
            pssParams.saltLen = int32(32);       % 盐长度（等于哈希长度）
            pssParams.trailerField = int32(1);   % Bouncy Castle特定参数

            % ===== 4. 准备签名数据 =====
            % TLS 1.3规定的签名格式
            prefix_spaces = repmat(uint8(32), 1, 64);  % 64个空格（0x20）
            context_string_cv = 'TLS 1.3, server CertificateVerify';  % 上下文字符串
            separator_byte = uint8(0);  % 分隔符

            % ===== 5. 获取当前握手记录的哈希 =====
            % 包含从ClientHello到服务器Certificate的所有消息
            transcript_hash_for_cv = obj.getCurrentTranscriptHash();

            if isempty(transcript_hash_for_cv)
                fprintf('错误(S): 计算CV的TranscriptHash失败。\n');
                return;
            end

            % ===== 6. 组装要签名的数据 =====
            data_to_be_signed = [prefix_spaces, ...
                               uint8(context_string_cv), ...
                               separator_byte, ...
                               transcript_hash_for_cv];

            % ===== 7. 使用RSA-PSS进行签名 =====
            signature_bytes = RSAUtils.signDataPSS(...
                obj.rsa_signing_jce_priv_key, ...  % RSA私钥
                data_to_be_signed, ...             % 要签名的数据
                pssParams);                        % PSS参数

            if isempty(signature_bytes)
                fprintf('错误(S): CV签名失败。\n');
                return;
            end

            % ===== 8. 构造CertificateVerify消息 =====
            % 签名长度字段（2字节）
            signature_len_val = length(signature_bytes);
            signature_len_field = uint16_to_uint8_be(signature_len_val);

            % 组装消息内容
            cv_s_content_plaintext = [selected_signature_scheme_bytes, ...
                                     signature_len_field, ...
                                     signature_bytes];

            % ===== 9. 添加握手消息头部 =====
            handshake_type_cv = TLSProtocol.HANDSHAKE_CERTIFICATE_VERIFY;
            handshake_length_cv_val = length(cv_s_content_plaintext);
            
            % 3字节长度字段
            handshake_length_cv_field = uint8([
                bitshift(handshake_length_cv_val, -16), ...
                bitshift(bitand(handshake_length_cv_val, 65280), -8), ...
                bitand(handshake_length_cv_val, 255)
            ]);

            cv_s_handshake_message_plaintext = [handshake_type_cv, ...
                                               handshake_length_cv_field, ...
                                               cv_s_content_plaintext];

            % ===== 10. 添加到累积握手消息 =====
            obj.handshake_messages = [obj.handshake_messages, cv_s_handshake_message_plaintext];
            fprintf('  服务器: CertificateVerify (Server) 明文 (长度 %d) 已添加到transcript。\n', ...
                    length(cv_s_handshake_message_plaintext));

            % ===== 11. 加密并打包记录 =====
            [encrypted_cv_s_record, enc_success, ~] = AES128Utils.encryptAndPackageRecord(...
                obj.server_handshake_write_key, ...
                obj.server_handshake_write_iv, ...
                obj.server_record_send_seq_num, ...
                cv_s_handshake_message_plaintext, ...
                TLSProtocol.RECORD_HANDSHAKE);

            if ~enc_success
                fprintf('错误(S): 加密 CertificateVerify (Server) 失败.\n');
                encrypted_cv_s_record = [];
                return;
            end

            % ===== 12. 递增序列号 =====
            obj.server_record_send_seq_num = obj.server_record_send_seq_num + 1;
            
            fprintf('服务器: CertificateVerify (Server) 已生成并加密 (记录长 %d)。\n', ...
                    length(encrypted_cv_s_record));
        end

        function encrypted_fin_s_record = generateFinishedMessageS(obj)
            % 生成服务器Finished消息，完成服务器握手部分
            % 
            % 功能说明：
            % Finished消息是服务器握手的最后一个消息，
            % 包含对整个握手过程的认证。
            % 通过HMAC计算验证数据，确保握手的完整性和认证性。
            %
            % 返回:
            %   encrypted_fin_s_record - 加密后的Finished记录
            %                           失败时返回空数组
            %
            % Finished消息结构：
            % - verify_data: 固定长度（SHA-256时为32字节）
            %   通过HMAC-SHA256(server_finished_key, transcript_hash)计算

            encrypted_fin_s_record = [];  % 初始化返回值

            % ===== 1. 检查必要条件 =====
            if isempty(obj.server_handshake_write_key) || isempty(obj.server_finished_key)
                fprintf('错误(S): 生成Finished_S所需密钥未就绪。\n');
                return;
            end

            % ===== 2. 获取当前握手记录的哈希 =====
            % 包含从ClientHello到服务器CertificateVerify的所有消息
            transcript_hash_for_finished = obj.getCurrentTranscriptHash();

            if isempty(transcript_hash_for_finished)
                fprintf('错误(S): 计算Finished的TranscriptHash失败。\n');
                return;
            end

            % ===== 3. 计算验证数据 =====
            % verify_data = HMAC-SHA256(server_finished_key, transcript_hash)
            verify_data = HKDFUtils.hmacSha256(...
                obj.server_finished_key, ...         % Finished密钥
                transcript_hash_for_finished);       % 握手记录哈希

            if isempty(verify_data)
                fprintf('错误(S): 计算verify_data失败。\n');
                return;
            end

            % ===== 4. 构造Finished消息内容 =====
            % Finished消息的内容就是verify_data本身
            fin_s_content_plaintext = verify_data;  % 32字节

            % ===== 5. 添加握手消息头部 =====
            handshake_type_fin = TLSProtocol.HANDSHAKE_FINISHED;
            handshake_length_fin_val = length(fin_s_content_plaintext);  % 应该是32
            
            % 3字节长度字段
            handshake_length_fin_field = uint8([
                0, ...
                bitshift(handshake_length_fin_val, -8), ...
                bitand(handshake_length_fin_val, 255)
            ]);
            
            % 对于较大的Finished消息（虽然通常是32字节）
            if handshake_length_fin_val > (2^16-1)
                handshake_length_fin_field = uint8([
                    bitshift(bitand(handshake_length_fin_val, 16711680), -16), ...
                    bitshift(bitand(handshake_length_fin_val, 65280), -8), ...
                    bitand(handshake_length_fin_val, 255)
                ]);
            end

            fin_s_handshake_message_plaintext = [handshake_type_fin, ...
                                                handshake_length_fin_field, ...
                                                fin_s_content_plaintext];

            % ===== 6. 添加到累积握手消息 =====
            % 重要：服务器的Finished消息也要添加到transcript
            obj.handshake_messages = [obj.handshake_messages, fin_s_handshake_message_plaintext];
            fprintf('  服务器: Finished (Server) 明文 (长度 %d) 已添加到transcript。\n', ...
                    length(fin_s_handshake_message_plaintext));

            % ===== 7. 加密并打包记录 =====
            [encrypted_fin_s_record, enc_success, ~] = AES128Utils.encryptAndPackageRecord(...
                obj.server_handshake_write_key, ...
                obj.server_handshake_write_iv, ...
                obj.server_record_send_seq_num, ...
                fin_s_handshake_message_plaintext, ...
                TLSProtocol.RECORD_HANDSHAKE);

            if ~enc_success
                fprintf('错误(S): 加密 Finished (Server) 失败.\n');
                encrypted_fin_s_record = [];
                return;
            end

            % ===== 8. 递增序列号 =====
            obj.server_record_send_seq_num = obj.server_record_send_seq_num + 1;
            
            fprintf('服务器: Finished (Server) 已生成并加密 (记录长 %d)。\n', ...
                    length(encrypted_fin_s_record));
        end
        % === 服务器解析客户端响应的方法 ===
        function success = parseCertificateMessageC(obj, encrypted_cert_c_record)
            % 解析客户端Certificate消息，提取客户端证书
            % 参数:
            %   encrypted_cert_c_record - 加密的客户端Certificate记录
            % 返回:
            %   success - 解析成功时为true

            success = false;
            fprintf('服务器: 正在解析客户端 Certificate 消息...\n');

            % 检查解密密钥是否就绪
            if isempty(obj.client_handshake_write_key)
                fprintf('错误(S): 解密客户端Cert密钥未派生。\n');
                return;
            end

            % 确保序列号已初始化
            if isempty(obj.client_record_recv_seq_num)
                obj.client_record_recv_seq_num = uint64(0);
            end

            % 解密记录并验证类型
            [cert_c_handshake_plaintext, dec_success, dec_errMsg] = AES128Utils.decryptAndUnpackRecord(obj.client_handshake_write_key, obj.client_handshake_write_iv, obj.client_record_recv_seq_num, encrypted_cert_c_record, TLSProtocol.RECORD_HANDSHAKE); %

            if ~dec_success
                fprintf('错误(S): 解密客户端Certificate失败: %s\n', dec_errMsg);
                return;
            end

            if isempty(cert_c_handshake_plaintext) || cert_c_handshake_plaintext(1) ~= TLSProtocol.HANDSHAKE_CERTIFICATE %
                fprintf('错误(S): 客户端Cert解密后类型不正确。\n');
                return;
            end

            % 添加到累积握手消息
            obj.handshake_messages = [obj.handshake_messages, cert_c_handshake_plaintext];
            fprintf('  服务器: 客户端Certificate明文 (长度 %d) 已添加到transcript。\n', length(cert_c_handshake_plaintext));

            % 解析证书请求上下文
            idx = 5;  % 跳过类型(1)和长度字段(3)

            if length(cert_c_handshake_plaintext) < idx % Need at least context_len (1 byte)
                fprintf('错误(S): ClientCert过短(ctx len)\n');
                return;
            end

            crc_len = double(cert_c_handshake_plaintext(idx));
            idx = idx + 1;

            if length(cert_c_handshake_plaintext) < (idx + crc_len - 1) && crc_len > 0
                fprintf('错误(S): ClientCert过短(ctx val)\n');
                return;
            end

            if crc_len > 0
                received_crc_val = cert_c_handshake_plaintext(idx : idx + crc_len - 1);
            else
                received_crc_val = reshape(uint8([]),1,0);
            end


            % 验证证书请求上下文是否匹配
            if crc_len ~= length(obj.certificate_request_context_sent) || ~all(received_crc_val == obj.certificate_request_context_sent)
                fprintf('错误(S): 客户端Certificate消息中的certificate_request_context (%s) 与服务器发送的 (%s) 不匹配!\n', ...
                    lower(char(org.bouncycastle.util.encoders.Hex.toHexString(received_crc_val))), ...
                    lower(char(org.bouncycastle.util.encoders.Hex.toHexString(obj.certificate_request_context_sent))));
                return;
            end

            fprintf('  服务器: ✓ 客户端Certificate消息中的certificate_request_context验证通过。\n');
            idx = idx + crc_len;

            % 解析证书列表长度
            if length(cert_c_handshake_plaintext) < (idx + 2) % Need 3 bytes for cert_list_total_len
                fprintf('错误(S): ClientCert过短(cert list len)\n');
                return;
            end

            cert_list_total_len = double(cert_c_handshake_plaintext(idx))*65536 + double(cert_c_handshake_plaintext(idx+1))*256 + double(cert_c_handshake_plaintext(idx+2));
            idx = idx + 3;

            if (idx + cert_list_total_len - 1) > length(cert_c_handshake_plaintext) && cert_list_total_len > 0
                fprintf('错误(S): ClientCert声明证书列表长度超出。\n');
                return;
            end

            % 如果有证书数据，解析证书
            if cert_list_total_len > 0
                current_pos_in_list = idx;
                % For simplicity, assuming one certificate in the list as per typical client auth with single cert
                % A full implementation would loop through the certificate_list.

                if length(cert_c_handshake_plaintext) < (current_pos_in_list + 2) % Need 3 bytes for cert_data_len
                    fprintf('错误(S): ClientCert entry过短(cert_data len field)\n');
                    return;
                end

                cert_data_len = double(cert_c_handshake_plaintext(current_pos_in_list))*65536 + double(cert_c_handshake_plaintext(current_pos_in_list+1))*256 + double(cert_c_handshake_plaintext(current_pos_in_list+2));
                current_pos_in_list = current_pos_in_list + 3;

                if length(cert_c_handshake_plaintext) < (current_pos_in_list + cert_data_len - 1)
                    fprintf('错误(S): ClientCert entry过短(cert_data)\n');
                    return;
                end

                % 保存客户端证书DER编码
                obj.received_client_certificate_der = cert_c_handshake_plaintext(current_pos_in_list : current_pos_in_list + cert_data_len - 1);

                % 从证书中提取公钥
                temp_cert_obj = RSAUtils.loadX509CertificateFromBytes(obj.received_client_certificate_der);

                if ~isempty(temp_cert_obj)
                    obj.received_client_signing_jce_pub_key = temp_cert_obj.getPublicKey();
                    fprintf('  服务器: 已从客户端证书提取签名公钥 (算法: %s)。\n', char(obj.received_client_signing_jce_pub_key.getAlgorithm()));
                else
                    fprintf('错误(S): 无法从客户端证书字节加载X509对象。\n');
                    obj.received_client_certificate_der = []; % Clear if invalid
                end

                current_pos_in_list = current_pos_in_list + cert_data_len;
                % Skip extensions for this certificate entry
                 if length(cert_c_handshake_plaintext) < (current_pos_in_list + 1) % Need 2 bytes for ext_len
                    fprintf('错误(S): ClientCert entry过短(ext len field)\n');
                    return;
                end
                
                % current_pos_in_list = current_pos_in_list + 2 + cert_entry_ext_len;
                % TODO: Validate current_pos_in_list against end of cert_list_total_len if parsing multiple certs
            end

            % 增加序列号
            obj.client_record_recv_seq_num = obj.client_record_recv_seq_num + 1;
            success = ~isempty(obj.received_client_signing_jce_pub_key); % Success if public key was extracted

            if success
                fprintf('服务器: 客户端Certificate消息解析成功。\n');
            else
                fprintf('服务器: 客户端Certificate消息解析完成，但未能提取公钥。\n');
            end
        end
        function success = parseAndVerifyCertificateVerifyC(obj, encrypted_cv_c_record)
            % 解析并验证客户端CertificateVerify消息
            % 参数:
            %   encrypted_cv_c_record - 加密的客户端CertificateVerify记录
            % 返回:
            %   success - 验证成功时为true

            success = false;
            fprintf('服务器: 正在解析并验证客户端的 CertificateVerify 消息...\n');
            % Helper function to convert uint16 to big-endian uint8 array
            uint16_to_uint8_be = @(val) uint8([bitshift(val, -8), bitand(val, 255)]);

            % 检查解密和验证所需密钥是否就绪
            if isempty(obj.client_handshake_write_key) || isempty(obj.received_client_signing_jce_pub_key)
                fprintf('错误(S): 解密/验证客户端CV所需密钥或客户端公钥未就绪。\n');
                return;
            end

            % 获取当前记录哈希，应包含CH...Client Certificate
            % The transcript includes messages up to *before* this CertificateVerify message.
            transcript_hash_for_cv_verify = obj.getCurrentTranscriptHash();

            if isempty(transcript_hash_for_cv_verify)
                fprintf('错误(S): 计算客户端CV的TranscriptHash失败。\n');
                return;
            end
            % 解密记录并验证类型
            [cv_c_handshake_plaintext, dec_success, dec_errMsg] = AES128Utils.decryptAndUnpackRecord(obj.client_handshake_write_key, obj.client_handshake_write_iv, obj.client_record_recv_seq_num, encrypted_cv_c_record, TLSProtocol.RECORD_HANDSHAKE); %

            if ~dec_success
                fprintf('错误(S): 解密客户端CV失败: %s\n', dec_errMsg);
                return;
            end

            if isempty(cv_c_handshake_plaintext) || cv_c_handshake_plaintext(1) ~= TLSProtocol.HANDSHAKE_CERTIFICATE_VERIFY %
                fprintf('错误(S): 客户端CV解密后类型不正确。\n');
                return;
            end

            % 解析签名算法和签名数据
            idx = 5; % Skip Type (1) + Length (3)

            if length(cv_c_handshake_plaintext) < (idx + 2 + 1) % sig_alg(2) + sig_len(2) min
                fprintf('错误(S): CV_C消息体过短。\n');
                return;
            end

            received_sig_scheme_bytes = cv_c_handshake_plaintext(idx:idx+1);
            idx = idx + 2;

            signature_len_declared = double(cv_c_handshake_plaintext(idx))*256 + double(cv_c_handshake_plaintext(idx+1));
            idx = idx + 2;

            if length(cv_c_handshake_plaintext) < (idx + signature_len_declared - 1) && signature_len_declared > 0
                fprintf('错误(S): CV_C声明的签名长度超出。\n');
                return;
            end

            received_signature_bytes = cv_c_handshake_plaintext(idx : idx + signature_len_declared - 1);

            % 准备要验证的数据
            prefix_spaces = repmat(uint8(32), 1, 64);  % 64个空格
            context_str = 'TLS 1.3, client CertificateVerify';
            separator = uint8(0);

            data_to_be_verified = [prefix_spaces, uint8(context_str), separator, transcript_hash_for_cv_verify];

            % 根据签名算法进行验证
            % Ensure received_client_signing_jce_pub_key is appropriate for the scheme
            % For example, if scheme is RSA, key must be RSA.
            if all(received_sig_scheme_bytes == uint16_to_uint8_be(TLSProtocol.RSA_PSS_RSAE_SHA256)) && ... %
               strcmp(obj.received_client_signing_jce_pub_key.getAlgorithm(), 'RSA')
                pssParams.hashAlg = 'SHA-256';
                pssParams.mgfAlg = 'MGF1';
                pssParams.mgfHashAlg = 'SHA-256';
                pssParams.saltLen = int32(32); % SHA-256 hash length
                pssParams.trailerField = int32(1); % BC

                isValid = RSAUtils.verifySignaturePSS(obj.received_client_signing_jce_pub_key, data_to_be_verified, received_signature_bytes, pssParams);

                if isValid
                    fprintf('  服务器: ✓ 客户端CertificateVerify签名验证成功 (RSA-PSS)!\n');
                    success = true;
                else
                    fprintf('  服务器: ✗ 客户端CertificateVerify签名验证失败 (RSA-PSS)!\n');
                end
            elseif all(received_sig_scheme_bytes == uint16_to_uint8_be(TLSProtocol.ECDSA_SECP256R1_SHA256)) && ... %
                   (strcmp(obj.received_client_signing_jce_pub_key.getAlgorithm(), 'EC') || strcmp(obj.received_client_signing_jce_pub_key.getAlgorithm(), 'ECDSA'))
                 % Assuming SHA-256 is used with P-256
                isValid = ECDSAUtils.verifySignature(obj.received_client_signing_jce_pub_key, ...
                                                     data_to_be_verified, ...
                                                     received_signature_bytes, 'SHA256withECDSA'); % Java alg string
                if isValid
                    fprintf('  服务器: ✓ 客户端CertificateVerify签名验证成功 (ECDSA-secp256r1-SHA256)!\n');
                    success = true;
                else
                    fprintf('  服务器: ✗ 客户端CertificateVerify签名验证失败 (ECDSA-secp256r1-SHA256)!\n');
                end

            else
                fprintf('  服务器: 警告 - 客户端CV使用了未支持的签名算法 0x%02X%02X 或与公钥类型不匹配。\n', received_sig_scheme_bytes(1), received_sig_scheme_bytes(2));
            end

            % 如果验证成功，将消息添加到累积握手消息
            if success
                obj.handshake_messages = [obj.handshake_messages, cv_c_handshake_plaintext];
                fprintf('  服务器: 客户端CV明文 (长度 %d) 已添加到transcript。\n', length(cv_c_handshake_plaintext));
            end

            % 增加序列号
            obj.client_record_recv_seq_num = obj.client_record_recv_seq_num + 1;
        end
        function success = parseAndVerifyFinishedC(obj, encrypted_fin_c_record)
            % 解析并验证客户端Finished消息
            % 参数:
            %   encrypted_fin_c_record - 加密的客户端Finished记录
            % 返回:
            %   success - 验证成功时为true

            success = false;
            fprintf('服务器: 正在解析并验证客户端的 Finished 消息...\n');

            % 检查解密和验证所需密钥是否就绪
            if isempty(obj.client_handshake_write_key) || isempty(obj.client_finished_key_for_verify)
                fprintf('错误(S): 解密/验证客户端Finished所需密钥未派生。\n');
                return;
            end

            % 获取当前记录哈希，应包含CH...Client CertificateVerify
            % The transcript includes messages up to *before* this Finished message.
            transcript_hash_for_cf = obj.getCurrentTranscriptHash();

            if isempty(transcript_hash_for_cf)
                fprintf('错误(S): 计算客户端Finished的TranscriptHash失败。\n');
                return;
            end
            % 解密记录并验证类型
            [fin_c_handshake_plaintext, dec_success, dec_errMsg] = AES128Utils.decryptAndUnpackRecord(obj.client_handshake_write_key, obj.client_handshake_write_iv, obj.client_record_recv_seq_num, encrypted_fin_c_record, TLSProtocol.RECORD_HANDSHAKE); %

            if ~dec_success
                fprintf('错误(S): 解密客户端Finished失败: %s\n', dec_errMsg);
                return;
            end

            if isempty(fin_c_handshake_plaintext) || fin_c_handshake_plaintext(1) ~= TLSProtocol.HANDSHAKE_FINISHED %
                fprintf('错误(S): 客户端Finished解密后类型不正确。\n');
                return;
            end

            % 提取验证数据 (Handshake header: Type(1) + Length(3) = 4 bytes)
            verify_data_received = fin_c_handshake_plaintext(5:end);

            % 计算预期的验证数据
            expected_verify_data = HKDFUtils.hmacSha256(obj.client_finished_key_for_verify, transcript_hash_for_cf);

            % 验证
            if all(verify_data_received == expected_verify_data)
                fprintf('  服务器: ✓ 客户端Finished消息验证成功!\n');
                success = true;

                % 将消息添加到累积握手消息
                obj.handshake_messages = [obj.handshake_messages, fin_c_handshake_plaintext];
                fprintf('  服务器: 客户端Finished明文 (长度 %d) 已添加到transcript。\n', length(fin_c_handshake_plaintext));
            else
                fprintf('  服务器: ✗ 客户端Finished消息验证失败!\n');
                fprintf('    Expected (hex): %s\n', sprintf('%02x', expected_verify_data));
                fprintf('    Received (hex): %s\n', sprintf('%02x', verify_data_received));
            end

            % 增加序列号
            obj.client_record_recv_seq_num = obj.client_record_recv_seq_num + 1;
        end

        function success = deriveApplicationKeys(obj)
            % 派生TLS 1.3应用层通信密钥
            % 在握手成功完成后调用此方法，派生用于加密应用数据的密钥
            % 返回:
            %   success - 密钥派生成功时为true

            % 初始化返回值
            success = false;

            % 密钥材料长度常量
            HASH_LEN_BYTES = 32;     % SHA-256哈希输出长度(字节)
            AEAD_KEY_LEN_BYTES = 16; % AES-128-GCM密钥长度(字节)
            AEAD_IV_LEN_BYTES = 12;  % AES-GCM IV长度(字节)

            % 日志前缀
            log_prefix = "服务器";

            fprintf('%s: 开始派生应用层密钥...\n', log_prefix);

            % 验证握手密钥材料是否存在
            if isempty(obj.handshake_secret_prk)
                fprintf('错误(%s): HandshakeSecret_PRK 为空，无法派生应用层密钥。\n', log_prefix);
                return;
            end

            % 步骤1: 从HandshakeSecret派生MasterSecret的PRK
            % 使用空字符串的哈希作为上下文
            empty_string_hash_bytes = uint8(org.bouncycastle.util.encoders.Hex.decode('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'))';
            derived_from_hs_secret = HKDFUtils.expandLabel(obj.handshake_secret_prk, "derived", empty_string_hash_bytes, HASH_LEN_BYTES);

            if isempty(derived_from_hs_secret)
                fprintf('错误(%s): 从HandshakeSecret派生DerivedSecret_for_Master失败。\n', log_prefix);
                return;
            end

            % 使用全零输入密钥材料提取主密钥
            obj.master_secret_prk = HKDFUtils.extract(derived_from_hs_secret, zeros(1, HASH_LEN_BYTES, 'uint8'));

            if isempty(obj.master_secret_prk)
                fprintf('错误(%s): 计算MasterSecret_PRK失败。\n', log_prefix);
                return;
            end

            fprintf('  %s: MasterSecret_PRK (Hex): %s\n', log_prefix, lower(char(org.bouncycastle.util.encoders.Hex.toHexString(obj.master_secret_prk))));

            % 步骤2: 计算到ClientFinished的记录哈希 (如果进行了客户端认证)
            % 否则，是到ServerFinished的哈希。
            % obj.handshake_messages 包含了所有到此为止的消息。
            transcript_hash_final_handshake = obj.getCurrentTranscriptHash();

            if isempty(transcript_hash_final_handshake)
                fprintf('错误(%s): 计算最终握手TranscriptHash失败。\n', log_prefix);
                return;
            end

            fprintf('  %s: 用于应用层密钥的最终TranscriptHash (Hex): %s\n', log_prefix, lower(char(org.bouncycastle.util.encoders.Hex.toHexString(transcript_hash_final_handshake))));

            % 步骤3: 派生客户端和服务器的应用层流量密钥
            obj.client_application_traffic_secret_0 = HKDFUtils.expandLabel(...
                obj.master_secret_prk, ...
                'c ap traffic', ...
                transcript_hash_final_handshake, ...
                HASH_LEN_BYTES...
                );

            obj.server_application_traffic_secret_0 = HKDFUtils.expandLabel(...
                obj.master_secret_prk, ...
                's ap traffic', ...
                transcript_hash_final_handshake, ...
                HASH_LEN_BYTES...
                );

            if isempty(obj.client_application_traffic_secret_0) || isempty(obj.server_application_traffic_secret_0)
                fprintf('错误(%s): 派生 application_traffic_secrets_0 失败。\n', log_prefix);
                return;
            end

            fprintf('  %s: client_application_traffic_secret_0 (Hex): %s\n', log_prefix, lower(char(org.bouncycastle.util.encoders.Hex.toHexString(obj.client_application_traffic_secret_0))));
            fprintf('  %s: server_application_traffic_secret_0 (Hex): %s\n', log_prefix, lower(char(org.bouncycastle.util.encoders.Hex.toHexString(obj.server_application_traffic_secret_0))));

            % 步骤4: 派生客户端写密钥和IV (服务器用于解密)
            obj.client_application_write_key = HKDFUtils.expandLabel(...
                obj.client_application_traffic_secret_0, ...
                'key', ...
                uint8([]), ...
                AEAD_KEY_LEN_BYTES...
                );

            obj.client_application_write_iv = HKDFUtils.expandLabel(...
                obj.client_application_traffic_secret_0, ...
                'iv', ...
                uint8([]), ...
                AEAD_IV_LEN_BYTES...
                );

            % 步骤5: 派生服务器写密钥和IV (服务器用于加密)
            obj.server_application_write_key = HKDFUtils.expandLabel(...
                obj.server_application_traffic_secret_0, ...
                'key', ...
                uint8([]), ...
                AEAD_KEY_LEN_BYTES...
                );

            obj.server_application_write_iv = HKDFUtils.expandLabel(...
                obj.server_application_traffic_secret_0, ...
                'iv', ...
                uint8([]), ...
                AEAD_IV_LEN_BYTES...
                );

            % 验证所有密钥材料是否成功派生
            if any(cellfun('isempty', {obj.client_application_write_key, ...
                obj.client_application_write_iv, ...
                obj.server_application_write_key, ...
                obj.server_application_write_iv}))
                fprintf('错误(%s): 派生应用层AEAD密钥或IV失败。\n', log_prefix);
                return;
            end

            fprintf('  %s: client_application_write_key (Hex): %s\n', log_prefix, lower(char(org.bouncycastle.util.encoders.Hex.toHexString(obj.client_application_write_key))));
            fprintf('  %s: server_application_write_key (Hex): %s\n', log_prefix, lower(char(org.bouncycastle.util.encoders.Hex.toHexString(obj.server_application_write_key))));

            % 标记成功
            success = true;
            % Reset handshake record sequence numbers for application data phase
            obj.client_record_recv_seq_num = uint64(0);
            obj.server_record_send_seq_num = uint64(0);


            fprintf('%s: 应用层密钥派生完成。序列号已重置。\n', log_prefix);
        end
    end
end