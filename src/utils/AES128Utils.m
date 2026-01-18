% AES128Utils.m
% AES-128-GCM加密工具类，用于TLS 1.3协议中的记录层加密
% 实现TLS 1.3中使用的AES-GCM AEAD加密及记录格式化功能
classdef AES128Utils
    methods (Static)
        function nonce = constructNonce(iv_initial_bytes, sequence_number_uint64)
            % 根据初始IV和序列号构造AES-GCM的nonce
            % 参数:
            %   iv_initial_bytes - 初始IV(12字节uint8数组)
            %   sequence_number_uint64 - 记录序列号(uint64)
            % 返回:
            %   nonce - 生成的用于AES-GCM加密的nonce(12字节uint8数组)
            
            % 验证IV长度
            if numel(iv_initial_bytes) ~= 12
                error('IV长度需12字节');
            end
            
            % 验证序列号类型
            if ~isa(sequence_number_uint64, 'uint64')
                error('序列号需uint64');
            end
            
            % 创建Java字节缓冲区并存入序列号
            bb = java.nio.ByteBuffer.allocate(8);
            bb.putLong(sequence_number_uint64);
            
            % 获取序列号字节数组
            seqNumBytesJava = bb.array();
            
            % 转换为MATLAB字节数组
            seqNumBytesMatlab = reshape(typecast(seqNumBytesJava, 'uint8'), 1, []);
            
            % 计算填充长度
            padding_len = length(iv_initial_bytes) - length(seqNumBytesMatlab);
            
            % 确保IV长度足够
            if padding_len < 0
                error('IV短于序列号');
            end
            
            % 对序列号进行填充
            padded_seq_num = [zeros(1, padding_len, 'uint8'), seqNumBytesMatlab];
            
            % 计算nonce (IV异或填充序列号)
            nonce = bitxor(iv_initial_bytes, padded_seq_num);
            
            % 验证生成的nonce长度
            if numel(nonce) ~= 12
                error('Nonce长度非12');
            end
        end
        
        function [raw_ciphertext_with_tag, success, errMsg] = encrypt(key_bytes, iv_initial_bytes, sequence_number_uint64, associated_data_bytes, plaintext_to_encrypt_inner)
            % 执行AES-128-GCM加密
            % 参数:
            %   key_bytes - AES密钥(16字节uint8数组)
            %   iv_initial_bytes - 初始IV(12字节uint8数组)
            %   sequence_number_uint64 - 记录序列号(uint64)
            %   associated_data_bytes - 附加认证数据(uint8数组)
            %   plaintext_to_encrypt_inner - 待加密明文(uint8数组)
            % 返回:
            %   raw_ciphertext_with_tag - 加密结果，包含认证标签(uint8数组)
            %   success - 操作是否成功(逻辑值)
            %   errMsg - 错误信息(字符串)
            
            % 初始化返回值
            raw_ciphertext_with_tag = [];
            success = false;
            errMsg = '';
            
            % 设置AEAD标签长度(GCM模式)
            AEAD_TAG_LENGTH_BITS = 128;
            
            % 验证密钥长度
            if numel(key_bytes) ~= 16
                errMsg = '密钥需16字节';
                return;
            end
            
            % 验证IV长度
            if numel(iv_initial_bytes) ~= 12
                errMsg = 'IV需12字节';
                return;
            end
            
            try
                % 导入所需的Java类
                import javax.crypto.Cipher;
                import javax.crypto.spec.GCMParameterSpec;
                import javax.crypto.spec.SecretKeySpec;
                import java.security.Security;
                import org.bouncycastle.jce.provider.BouncyCastleProvider;
                
                % 确保BouncyCastle提供者已添加
                if isempty(Security.getProvider('BC'))
                    Security.addProvider(BouncyCastleProvider());
                end
                
                % 构造加密用的nonce
                per_record_nonce = AES128Utils.constructNonce(iv_initial_bytes, sequence_number_uint64);
                
                % 获取AES-GCM加密器实例
                cipher = Cipher.getInstance('AES/GCM/NoPadding', 'BC');
                
                % 创建密钥规范
                keySpec = SecretKeySpec(key_bytes, 'AES');
                
                % 创建GCM参数规范
                gcmSpec = GCMParameterSpec(AEAD_TAG_LENGTH_BITS, per_record_nonce);
                
                % 初始化加密器
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
                
                % 设置附加认证数据(如有)
                if ~isempty(associated_data_bytes)
                    cipher.updateAAD(associated_data_bytes);
                end
                
                % 执行加密
                ciphertextWithTagJavaBytes = cipher.doFinal(plaintext_to_encrypt_inner);
                
                % 转换为MATLAB字节数组
                raw_ciphertext_with_tag = reshape(typecast(ciphertextWithTagJavaBytes, 'uint8'), 1, []);
                
                % 验证输出长度(明文长度 + 标签长度)
                if numel(raw_ciphertext_with_tag) == (length(plaintext_to_encrypt_inner) + AEAD_TAG_LENGTH_BITS/8)
                    success = true;
                else
                    errMsg = '加密输出长度错';
                end
            catch ME
                % 捕获并处理异常
                errMsg = sprintf('AES加密失败: %s', ME.message);
                
                % 如果是Java异常，添加更多信息
                if isa(ME, 'matlab.exception.JavaException')
                    errMsg = [errMsg, sprintf(' (Java: %s)', char(ME.ExceptionObject.toString()))];
                end
            end
        end
        
        function [plaintext_inner, success, errMsg] = decrypt(key_bytes, iv_initial_bytes, sequence_number_uint64, associated_data_bytes, ciphertext_with_tag_bytes)
            % 执行AES-128-GCM解密
            % 参数:
            %   key_bytes - AES密钥(16字节uint8数组)
            %   iv_initial_bytes - 初始IV(12字节uint8数组)
            %   sequence_number_uint64 - 记录序列号(uint64)
            %   associated_data_bytes - 附加认证数据(uint8数组)
            %   ciphertext_with_tag_bytes - 待解密密文，包含认证标签(uint8数组)
            % 返回:
            %   plaintext_inner - 解密后的明文(uint8数组)
            %   success - 操作是否成功(逻辑值)
            %   errMsg - 错误信息(字符串)
            
            % 初始化返回值
            plaintext_inner = [];
            success = false;
            errMsg = '';
            
            % 设置AEAD标签长度
            AEAD_TAG_LENGTH_BITS = 128;
            AEAD_TAG_LENGTH_BYTES = AEAD_TAG_LENGTH_BITS/8;
            
            % 验证密钥长度
            if numel(key_bytes) ~= 16
                errMsg = '密钥需16字节';
                return;
            end
            
            % 验证IV长度
            if numel(iv_initial_bytes) ~= 12
                errMsg = 'IV需12字节';
                return;
            end
            
            % 验证密文长度
            if isempty(ciphertext_with_tag_bytes) || numel(ciphertext_with_tag_bytes) < AEAD_TAG_LENGTH_BYTES
                errMsg = '密文过短';
                return;
            end
            
            try
                % 导入所需的Java类
                import javax.crypto.Cipher;
                import javax.crypto.spec.GCMParameterSpec;
                import javax.crypto.spec.SecretKeySpec;
                import java.security.Security;
                import org.bouncycastle.jce.provider.BouncyCastleProvider;
                
                % 确保BouncyCastle提供者已添加
                if isempty(Security.getProvider('BC'))
                    Security.addProvider(BouncyCastleProvider());
                end
                
                % 构造解密用的nonce
                per_record_nonce = AES128Utils.constructNonce(iv_initial_bytes, sequence_number_uint64);
                
                % 获取AES-GCM解密器实例
                cipher = Cipher.getInstance('AES/GCM/NoPadding', 'BC');
                
                % 创建密钥规范
                keySpec = SecretKeySpec(key_bytes, 'AES');
                
                % 创建GCM参数规范
                gcmSpec = GCMParameterSpec(AEAD_TAG_LENGTH_BITS, per_record_nonce);
                
                % 初始化解密器
                cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
                
                % 设置附加认证数据(如有)
                if ~isempty(associated_data_bytes)
                    cipher.updateAAD(associated_data_bytes);
                end
                
                % 执行解密
                plaintextJavaBytes = cipher.doFinal(ciphertext_with_tag_bytes);
                
                % 转换为MATLAB字节数组
                plaintext_inner = reshape(typecast(plaintextJavaBytes, 'uint8'), 1, []);
                
                % 解密成功
                success = true;
            catch ME
                % 捕获并处理异常
                errMsg = sprintf('AES解密失败: %s', ME.message);
                
                % 如果是Java异常，添加更多信息
                if isa(ME, 'matlab.exception.JavaException')
                    errMsg = [errMsg, sprintf(' (Java: %s)', char(ME.ExceptionObject.toString()))];
                    
                    % 检测认证标签无效的特定错误
                    if contains(char(ME.ExceptionObject.getClass().getName()), 'AEADBadTagException')
                        errMsg = [errMsg, ' ->认证标签无效!'];
                    end
                end
            end
        end
        
        function [full_tls_record, success, errMsg] = encryptAndPackageRecord(key_bytes, iv_initial_bytes, sequence_number_uint64, handshake_message_plaintext_payload, inner_content_type_byte)
            % 加密TLS记录并封装为完整TLS记录格式
            % 参数:
            %   key_bytes - AES密钥(16字节uint8数组)
            %   iv_initial_bytes - 初始IV(12字节uint8数组)
            %   sequence_number_uint64 - 记录序列号(uint64)
            %   handshake_message_plaintext_payload - 握手消息明文(uint8数组)
            %   inner_content_type_byte - 内部内容类型字节(uint8)
            % 返回:
            %   full_tls_record - 完整的TLS记录(uint8数组)
            %   success - 操作是否成功(逻辑值)
            %   errMsg - 错误信息(字符串)
            
            % 初始化返回值
            full_tls_record = [];
            success = false;
            errMsg = '';
            
            % 设置AEAD标签长度
            AEAD_TAG_LENGTH_BYTES = 16;
            
            try
                % 构造TLS内部明文(握手消息 + 内容类型)
                tls_inner_plaintext_to_encrypt = [handshake_message_plaintext_payload, inner_content_type_byte];
                
                % 设置外部记录类型(23表示应用数据)
                record_content_type_outer_encrypted = uint8(23);
                
                % 设置记录版本(TLS 1.2兼容)
                record_legacy_version_for_aad = uint8([3,3]);
                
                % 计算加密内容长度(内部明文 + AEAD标签)
                outer_encrypted_content_length = length(tls_inner_plaintext_to_encrypt) + AEAD_TAG_LENGTH_BYTES;
                
                % 验证内容长度不超过TLS最大限制
                if outer_encrypted_content_length > 2^14
                    errMsg = '内容过长';
                    return;
                end
                
                % 构造记录长度字段(2字节)
                record_length_for_aad_field = reshape(uint8([bitshift(outer_encrypted_content_length,-8) bitand(outer_encrypted_content_length,255)]), 1, []);
                
                % 构造附加认证数据(AAD) - 记录头
                aad_bytes = [record_content_type_outer_encrypted, record_legacy_version_for_aad, record_length_for_aad_field];
                
                % 加密内部明文
                [encrypted_payload_with_tag, enc_success_inner, enc_errMsg_inner] = AES128Utils.encrypt(key_bytes, iv_initial_bytes, sequence_number_uint64, aad_bytes, tls_inner_plaintext_to_encrypt);
                
                % 检查加密结果
                if ~enc_success_inner
                    errMsg = ['内部加密错: ', enc_errMsg_inner];
                    return;
                end
                
                % 构造完整的TLS记录(记录头 + 加密负载)
                full_tls_record = [aad_bytes, encrypted_payload_with_tag];
                
                % 操作成功
                success = true;
            catch ME
                % 捕获并处理异常
                errMsg = sprintf('encryptAndPackage错误: %s', ME.message);
                
                % 如果是Java异常，添加更多信息
                if isa(ME, 'matlab.exception.JavaException')
                    errMsg = [errMsg, sprintf(' (Java: %s)', char(ME.ExceptionObject.toString()))];
                end
            end
        end
        
        function [handshake_message_plaintext_payload, success, errMsg] = decryptAndUnpackRecord(key_bytes, iv_initial_bytes, sequence_number_uint64, full_tls_record_bytes, expected_inner_content_type_byte)
            % 解析并解密TLS记录
            % 参数:
            %   key_bytes - AES密钥(16字节uint8数组)
            %   iv_initial_bytes - 初始IV(12字节uint8数组)
            %   sequence_number_uint64 - 记录序列号(uint64)
            %   full_tls_record_bytes - 完整的TLS记录(uint8数组)
            %   expected_inner_content_type_byte - 期望的内部内容类型字节(uint8)
            % 返回:
            %   handshake_message_plaintext_payload - 解密后的握手消息明文(uint8数组)
            %   success - 操作是否成功(逻辑值)
            %   errMsg - 错误信息(字符串)
            
            % 初始化返回值
            handshake_message_plaintext_payload = [];
            success = false;
            errMsg = '';
            
            % 设置常量
            AEAD_TAG_LENGTH_BYTES = 16;
            RECORD_HEADER_LEN = 5;
            
            % 验证记录长度
            if length(full_tls_record_bytes) < RECORD_HEADER_LEN + AEAD_TAG_LENGTH_BYTES
                errMsg = '记录过短';
                return;
            end
            
            try
                % 提取记录类型
                record_content_type_outer = full_tls_record_bytes(1);
                
                % 计算记录长度字段值
                record_length_outer_field_val = double(full_tls_record_bytes(4))*256 + double(full_tls_record_bytes(5));
                
                % 验证记录类型(应为23，即应用数据)
                if record_content_type_outer ~= 23
                    errMsg = sprintf('期望记录类型23,实际%02X', record_content_type_outer);
                    return;
                end
                
                % 验证记录长度与实际一致
                if record_length_outer_field_val ~= (length(full_tls_record_bytes) - RECORD_HEADER_LEN)
                    errMsg = sprintf('记录长度字段与实际不符');
                    return;
                end
                
                % 提取AAD(记录头)
                aad_bytes = full_tls_record_bytes(1:RECORD_HEADER_LEN);
                
                % 提取加密负载
                encrypted_payload_with_tag = full_tls_record_bytes(RECORD_HEADER_LEN+1:end);
                
                % 解密内部明文
                [decrypted_tls_inner_plaintext, dec_success_inner, dec_errMsg_inner] = AES128Utils.decrypt(key_bytes, iv_initial_bytes, sequence_number_uint64, aad_bytes, encrypted_payload_with_tag);
                
                % 检查解密结果
                if ~dec_success_inner
                    errMsg = ['内部解密错: ', dec_errMsg_inner];
                    return;
                end
                
                % 验证内部内容类型
                if isempty(decrypted_tls_inner_plaintext) || decrypted_tls_inner_plaintext(end) ~= expected_inner_content_type_byte
                    errMsg = sprintf('内部类型错(期望%02X,实际%02X或空)', expected_inner_content_type_byte, decrypted_tls_inner_plaintext(end));
                    return;
                end
                
                % 提取握手消息明文(去除内容类型字节)
                handshake_message_plaintext_payload = decrypted_tls_inner_plaintext(1:end-1);
                
                % 操作成功
                success = true;
            catch ME
                % 捕获并处理异常
                errMsg = sprintf('decryptAndUnpack错误: %s', ME.message);
                
                % 如果是Java异常，添加更多信息
                if isa(ME, 'matlab.exception.JavaException')
                    errMsg = [errMsg, sprintf(' (Java: %s)', char(ME.ExceptionObject.toString()))];
                end
            end
        end
    end
end