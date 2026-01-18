% KeyLogFileUtils.m
% 此类用于管理TLS密钥日志文件，采用NSS格式
% 这些文件能够使Wireshark等协议分析器解密TLS流量
classdef KeyLogFileUtils
    methods (Static)
        function fid = initKeyLogFile(filename)
            % 以追加模式打开一个TLS密钥日志文件
            % 参数:
            %   filename - 密钥日志文件的字符串路径
            % 返回:
            %   fid - 用于后续写入操作的文件句柄
            
            % 以追加模式打开文件，如果文件不存在则创建
            fid = fopen(filename, 'at');
            
            % 验证文件是否成功打开
            if fid == -1
                error('无法创建或打开密钥日志文件: %s', filename);
            end
            
            % 记录操作成功信息
            fprintf('信息: 密钥日志文件 "%s" 已打开 (追加模式)。\n', filename);
        end
        
        function closeKeyLogFile(fid)
            % 关闭先前打开的密钥日志文件
            % 参数:
            %   fid - 由initKeyLogFile返回的文件句柄
            
            % 仅在文件句柄有效时关闭
            if fid ~= -1
                fclose(fid);
                
                % 记录操作成功信息
                fprintf('信息: 密钥日志文件已关闭。\n');
            end
        end
        
        function addKeyToLog(fid, label_str, client_random_hex_str, secret_hex_str)
            % 以NSS密钥日志格式将密钥条目写入日志文件
            % 参数:
            %   fid - 密钥日志文件的文件句柄
            %   label_str - 密钥类型标签（如'CLIENT_HANDSHAKE_TRAFFIC_SECRET'）
            %   client_random_hex_str - 客户端随机值的十六进制表示
            %   secret_hex_str - 密钥材料的十六进制表示
            
            % 验证文件句柄有效性
            if fid == -1
                error('无效的密钥日志文件句柄');
            end
            
            % 确保所有输入都是字符数组
            label_str = char(label_str);
            
            client_random_hex_str = char(client_random_hex_str);
            
            secret_hex_str = char(secret_hex_str);
            
            % 以NSS密钥日志格式写入格式化行：标签 客户端随机值 密钥
            fprintf(fid, '%s %s %s\n', label_str, client_random_hex_str, secret_hex_str);
        end
    end
end