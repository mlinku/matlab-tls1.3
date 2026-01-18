% HKDFUtils.m
% 基于HMAC的密钥派生函数(HKDF)工具类
% 实现TLS 1.3协议中使用的密钥派生功能
classdef HKDFUtils
    methods (Static)
        function hmacOutput = hmacSha256(key_bytes, data_bytes)
            % 使用SHA-256哈希函数计算HMAC值
            % 参数:
            %   key_bytes - HMAC密钥(uint8数组)
            %   data_bytes - 要计算HMAC的数据(uint8数组)
            % 返回:
            %   hmacOutput - 32字节的HMAC输出(uint8数组)
            
            % 初始化输出变量
            hmacOutput = [];
            
            try
                % 导入Java加密类
                import javax.crypto.Mac;
                import javax.crypto.spec.SecretKeySpec;
                import java.security.Security;
                import org.bouncycastle.jce.provider.BouncyCastleProvider;
                
                % 确保BouncyCastle提供者已添加
                if isempty(Security.getProvider('BC'))
                    Security.addProvider(BouncyCastleProvider());
                end
                
                % 创建HMAC-SHA256实例
                mac = Mac.getInstance('HmacSHA256', 'BC');
                
                % 创建密钥规范并初始化HMAC
                secretKey = SecretKeySpec(key_bytes, 'HmacSHA256');
                mac.init(secretKey);
                
                % 计算HMAC
                hmacOutputJavaBytes = mac.doFinal(data_bytes);
                
                % 将Java字节转换为MATLAB uint8数组
                hmacOutput = reshape(typecast(hmacOutputJavaBytes, 'uint8'), 1, []);
                
                % 验证输出长度(SHA-256输出应为32字节)
                if numel(hmacOutput) ~= 32
                    % 注：此处原代码有一个空的if块，保留原结构
                end
            catch ME
                % 捕获并显示错误
                fprintf('错误: hmacSha256: %s\n', ME.message);
            end
        end
        
        function prk = extract(salt_bytes, ikm_bytes)
            % 实现HKDF-Extract函数(RFC 5869)
            % 参数:
            %   salt_bytes - 盐值(uint8数组)
            %   ikm_bytes - 初始密钥材料(uint8数组)
            % 返回:
            %   prk - 伪随机密钥(uint8数组)
            
            % 设置哈希长度常量(SHA-256为32字节)
            HASH_LEN = 32;
            
            % 初始化输出变量
            prk = [];
            
            % 检查输入参数数量
            if nargin < 2
                error('HKDFUtils.extract: 需要salt和ikm。');
            end
            
            % 如果盐值为空，则使用全零数组
            if isempty(salt_bytes)
                salt_bytes = zeros(1, HASH_LEN, 'uint8');
            end
            
            % 验证输入类型
            if ~isa(ikm_bytes, 'uint8') || ~isa(salt_bytes, 'uint8')
                error('HKDFUtils.extract: 输入需为uint8。');
            end
            
            % 调用HMAC-SHA256计算PRK
            prk = HKDFUtils.hmacSha256(salt_bytes, ikm_bytes);
            
            % 验证输出有效性
            if isempty(prk) || numel(prk) ~= HASH_LEN
                fprintf('错误: HKDF-Extract计算失败或长度不符。\n');
                prk = [];
            end
        end
        
        function outputKeyMaterial = expandLabel(secret_prk_bytes, label_str, context_hash_bytes, output_length_bytes)
            % 实现TLS 1.3的HKDF-Expand-Label函数
            % 参数:
            %   secret_prk_bytes - 密钥材料(uint8数组)
            %   label_str - 标签字符串(如'key', 'iv'等)
            %   context_hash_bytes - 上下文哈希值(uint8数组)
            %   output_length_bytes - 需要的输出字节数
            % 返回:
            %   outputKeyMaterial - 派生的密钥材料(uint8数组)
            
            % 初始化输出变量
            outputKeyMaterial = [];
            
            % 设置哈希长度常量(SHA-256为32字节)
            HASH_LEN = 32;
            
            % 检查输入参数数量
            if nargin < 4
                error('HKDFUtils.expandLabel: 需要4个参数。');
            end
            
            % 验证输入类型和值
            if ~isa(secret_prk_bytes, 'uint8') || ~(ischar(label_str) || isstring(label_str)) || ~isa(context_hash_bytes, 'uint8') || ~isnumeric(output_length_bytes) || ~isscalar(output_length_bytes) || output_length_bytes < 0
                error('HKDFUtils.expandLabel: 输入类型或值不正确。');
            end
            
            % 检查输出长度是否超出限制
            if output_length_bytes > 255 * HASH_LEN
                error('HKDFUtils.expandLabel: 输出过长。');
            end
            
            % 构建长度字段(2字节)
            len_field = uint8([bitshift(output_length_bytes, -8), bitand(output_length_bytes, 255)]);
            
            % 构建标签前缀('tls13 ' + label_str)
            full_label_prefix = 'tls13 ';
            full_label_as_char_array = [full_label_prefix, char(label_str)];
            full_label_str_uint8 = uint8(full_label_as_char_array);
            
            % 构建标签长度字段
            label_len_field_val = length(full_label_str_uint8);
            
            % 检查标签长度是否超出限制
            if label_len_field_val > 255
                error('Label过长');
            end
            
            label_len_field = uint8(label_len_field_val);
            
            % 构建上下文长度字段
            context_len_field_val = length(context_hash_bytes);
            
            % 检查上下文长度是否超出限制
            if context_len_field_val > 255
                error('Context过长');
            end
            
            context_len_field = uint8(context_len_field_val);
            
            % 组装HKDF标签
            hkdfLabel_bytes = [len_field, label_len_field, full_label_str_uint8, context_len_field, context_hash_bytes];
            
            % 计算需要多少轮HMAC操作
            N = ceil(output_length_bytes / HASH_LEN);
            
            % 检查轮数是否超出限制
            if N > 255
                error('输出长度相对于哈希过长');
            end
            
            % 初始化输出缓冲区
            T = reshape(uint8([]), 1, 0);
            T_prev = reshape(uint8([]), 1, 0);
            
            % 执行各轮HMAC操作
            for i = 1:N
                % 构建当前轮的信息字段
                info_i = [T_prev, hkdfLabel_bytes, uint8(i)];
                
                % 计算当前轮的HMAC
                T_i = HKDFUtils.hmacSha256(secret_prk_bytes, info_i);
                
                % 检查HMAC计算是否成功
                if isempty(T_i)
                    outputKeyMaterial = [];
                    return;
                end
                
                % 累积输出
                T = [T, T_i];
                
                % 保存当前轮结果用于下一轮
                T_prev = T_i;
            end
            
            % 截取所需长度的输出
            if length(T) >= output_length_bytes
                outputKeyMaterial = T(1:output_length_bytes);
            else
                fprintf('错误: HKDF-Expand-Label字节数不足。\n');
            end
        end
    end
end