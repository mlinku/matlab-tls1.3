% TLSProtocol.m
% 定义TLS 1.3协议相关的常量、消息内容结构体模板
classdef TLSProtocol
    properties (Constant)
        % === TLS版本 ===
        TLS_1_0 = uint8([3, 1]); % 用于记录层版本兼容性 (例如ClientHello的记录层)
        TLS_1_2 = uint8([3, 3]); % 用于ClientHello和ServerHello内部的legacy_version字段
        TLS_1_3 = uint8([3, 4]); % TLS 1.3的实际协议版本字节表示
        TLS_1_3_VERSION_ID = uint16(hex2dec('0304')); % 用于SupportedVersions扩展中的版本ID

        % === 记录层内容类型 ===
        RECORD_HANDSHAKE = uint8(22);        % 握手协议消息
        RECORD_APPLICATION_DATA = uint8(23); % 应用数据 (加密后的握手消息也使用此类型)
        RECORD_ALERT = uint8(21);            % 警报协议
        RECORD_CHANGE_CIPHER_SPEC = uint8(20); % 更改密码规范 (TLS 1.3中用途有限)
        
        % === 握手消息类型 ===
        HANDSHAKE_CLIENT_HELLO = uint8(1);
        HANDSHAKE_SERVER_HELLO = uint8(2);
        HANDSHAKE_NEW_SESSION_TICKET = uint8(4);
        HANDSHAKE_END_OF_EARLY_DATA = uint8(5);
        HANDSHAKE_ENCRYPTED_EXTENSIONS = uint8(8);
        HANDSHAKE_CERTIFICATE = uint8(11);
        HANDSHAKE_CERTIFICATE_REQUEST = uint8(13);
        HANDSHAKE_CERTIFICATE_VERIFY = uint8(15);
        HANDSHAKE_FINISHED = uint8(20);
        HANDSHAKE_KEY_UPDATE = uint8(24);
        
        % === TLS 1.3 加密套件 (仅实现一个) ===
        TLS_AES_128_GCM_SHA256 = uint16(hex2dec('1301'));
        
        % === 扩展类型 ID (常用的) ===
        EXT_SERVER_NAME = uint16(0);                         % server_name (SNI)
        EXT_SUPPORTED_GROUPS = uint16(10);                   % supported_groups (Elliptic Curves)
        EXT_SIGNATURE_ALGORITHMS = uint16(13);               % signature_algorithms
        EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION = uint16(16); % application_layer_protocol_negotiation (ALPN)
        EXT_SUPPORTED_VERSIONS = uint16(43);                 % supported_versions
        EXT_COOKIE = uint16(44);                             % cookie
        EXT_PSK_KEY_EXCHANGE_MODES = uint16(45);             % psk_key_exchange_modes
        EXT_CERTIFICATE_AUTHORITIES = uint16(47);            % certificate_authorities
        EXT_OID_FILTERS = uint16(48);                        % oid_filters
        EXT_POST_HANDSHAKE_AUTH = uint16(49);                % post_handshake_auth
        EXT_SIGNATURE_ALGORITHMS_CERT = uint16(50);          % signature_algorithms_cert
        EXT_KEY_SHARE = uint16(51);                          % key_share
        
        % === 命名组 (椭圆曲线) ===
        X25519 = uint16(hex2dec('001D')); % dec 29
        SECP256R1 = uint16(hex2dec('0017')); % dec 23 (P-256)
        % 其他常用组可以按需添加
        
        % === 签名算法 (SignatureScheme) ===
        % ECDSA
        ECDSA_SECP256R1_SHA256 = uint16(hex2dec('0403'));
        ECDSA_SECP384R1_SHA384 = uint16(hex2dec('0503'));
        ECDSA_SECP521R1_SHA512 = uint16(hex2dec('0603'));
        % RSA PSS RSAE
        RSA_PSS_RSAE_SHA256 = uint16(hex2dec('0804'));
        RSA_PSS_RSAE_SHA384 = uint16(hex2dec('0805'));
        RSA_PSS_RSAE_SHA512 = uint16(hex2dec('0806'));
        % RSA PKCS#1 v1.5 (TLS 1.3中不推荐用于握手签名，但可能出现在证书链中)
        RSA_PKCS1_SHA256 = uint16(hex2dec('0401'));
        % EdDSA
        ED25519 = uint16(hex2dec('0807'));

        % === 压缩方法 ===
        COMPRESSION_NULL = uint8(0); % TLS 1.3 只支持null压缩
    end
    
    methods (Static)
        % =================================================================
        % TLS消息内容结构体创建方法
        % 这些方法返回一个包含该消息所有可能字段的结构体，初始值为空。
        % Client.m 和 Server.m 在填充具体消息时可以使用这些模板。
        % =================================================================
        
        function ch_content = createClientHelloContent()
            ch_content = struct();
            ch_content.legacy_version = TLSProtocol.TLS_1_2; % 默认填充，符合规范
            ch_content.random = uint8([]);                   % 32字节
            ch_content.session_id = uint8([]);               % 0-32字节 (前面有1字节长度)
            ch_content.supported_cipher_suites = [];         % uint16数组
            ch_content.compression_methods = [TLSProtocol.COMPRESSION_NULL]; % uint8数组
            ch_content.extensions = struct();                % 用于存放解析或待编码的扩展的子结构体
        end
        
        function sh_content = createServerHelloContent()
            sh_content = struct();
            sh_content.legacy_version = TLSProtocol.TLS_1_2;
            sh_content.random = uint8([]);                      % 32字节
            sh_content.session_id = uint8([]);                  % 回显自ClientHello
            sh_content.cipher_suite = uint16(0);                % uint16, 选择的密码套件
            sh_content.compression_method = TLSProtocol.COMPRESSION_NULL; % uint8
            sh_content.extensions = struct();                   % 扩展子结构体
        end
        
        function ee_content = createEncryptedExtensionsContent()
            ee_content = struct();
            ee_content.extensions = struct(); % 通常为空，或包含如 server_name, alpn 等
        end
        
        function cr_content = createCertificateRequestContent()
            cr_content = struct();
            cr_content.certificate_request_context = uint8([]); % 0-255字节 (前面有1字节长度)
            cr_content.extensions = struct();                   % 扩展子结构体
        end
        
        function cert_content = createCertificateContent()
            cert_content = struct();
            cert_content.certificate_request_context = uint8([]); % 回显自CertificateRequest，或服务器发送自己证书时为空
            cert_content.certificate_list = {};             % CertificateEntry结构体的cell数组
        end
        
        function cert_entry = createCertificateEntry()
            cert_entry = struct();
            cert_entry.cert_data = uint8([]);               % 证书的DER编码字节
            cert_entry.extensions_entry = struct();         % 该证书条目的扩展 (通常为空)
        end
        
        function cv_content = createCertificateVerifyContent()
            cv_content = struct();
            cv_content.signature_algorithm = uint16(0);     % uint16, 使用的签名算法
            cv_content.signature = uint8([]);               % 签名数据 (前面有2字节长度)
        end
        
        function fin_content = createFinishedContent()
            fin_content = struct();
            fin_content.verify_data = uint8([]);            % 验证数据 (长度等于哈希输出长度，例如32字节)
        end
        
        function ks_entry = createKeyShareEntry() % **确保这个方法存在**
            ks_entry = struct();
            ks_entry.group = uint16(0);                     % uint16, 椭圆曲线组ID
            ks_entry.key_exchange = uint8([]);              % 公钥数据 (前面有2字节长度)
        end
        function sv_ext_content = createSupportedVersionsExtensionContent()
            % 创建 SupportedVersions 扩展的内容结构体
            sv_ext_content = struct();
        end
        
        function ks_ext_content = createKeyShareExtensionContent()
            % 创建 KeyShare 扩展的内容结构体
            ks_ext_content = struct();
            % 对于ClientHello，它可能包含一个key_share_list (cell array of KeyShareEntry structs)
            % 对于ServerHello，它可能包含一个key_share_entry (单个KeyShareEntry struct)
        end

        function sg_ext_content = createSupportedGroupsExtensionContent()
            % 创建 SupportedGroups 扩展的内容结构体
            sg_ext_content = struct();
            % sg_content.groups_list = []; % uint16数组
        end

        function sa_ext_content = createSignatureAlgorithmsExtensionContent()
            % 创建 SignatureAlgorithms 扩展的内容结构体
            sa_ext_content = struct();
            % sa_content.algorithms_list = []; % uint16数组
        end

        % === 获取当前实现的配置 ===
        function suites = getCurrentCipherSuites()
            suites = [TLSProtocol.TLS_AES_128_GCM_SHA256];
        end
        function groups = getCurrentGroups()
            groups = [TLSProtocol.X25519, TLSProtocol.SECP256R1]; % 示例：可以支持多个
        end
        function algorithms = getCurrentSignatureAlgorithms()
            % 客户端在ClientHello中声明支持的，服务器在CertificateRequest中可以要求子集
            algorithms = [ TLSProtocol.RSA_PSS_RSAE_SHA256; ... % 主推
                           TLSProtocol.ECDSA_SECP256R1_SHA256]; % 备选
        end
        function versions = getCurrentVersions() % ClientHello中支持的版本列表
            versions = [TLSProtocol.TLS_1_3_VERSION_ID];
        end
        
    end
end