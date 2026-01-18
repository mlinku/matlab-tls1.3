% PcapManager.m
% PCAP和密钥日志文件管理器
% 用于生成TLS 1.3会话的网络捕获文件和密钥日志，支持Wireshark等工具进行解密分析
classdef PcapManager < handle
    properties
        % 文件句柄
        pcap_fid = -1;                     % PCAP文件句柄
        keylog_fid = -1;                   % 密钥日志文件句柄
        
        % 文件路径
        pcap_full_path_prop                % PCAP文件完整路径
        keylog_full_path_prop              % 密钥日志文件完整路径
        
        % 网络配置
        client_ip_str_prop                 % 客户端IP地址
        server_ip_str_prop                 % 服务器IP地址
        client_port_uint16_prop            % 客户端端口号
        server_port_uint16_prop            % 服务器端口号
        
        % TCP序列号和确认号管理
        c2s_next_seq_num                   % 客户端到服务器的下一个序列号
        s2c_ack_for_c_data                 % 服务器期望收到的客户端下一个序列号(即服务器在其包中设置的ACK)
        s2c_next_seq_num                   % 服务器到客户端的下一个序列号
        c2s_ack_for_s_data                 % 客户端期望收到的服务器下一个序列号(即客户端在其包中设置的ACK)

        % 时间戳管理
        current_ts_sec                     % 当前时间戳秒部分
        current_ts_usec_counter            % 当前时间戳微秒部分
        
        % 路径管理
        project_root_path                  % 项目根目录路径，用于定位output文件夹
    end
    
    methods
        function obj = PcapManager(varargin)
            % 构造函数，初始化PCAP和密钥日志文件管理器
            % 可选参数:
            %   'PcapBasename' - PCAP文件名
            %   'KeylogBasename' - 密钥日志文件名
            %   'ClientIP' - 客户端IP地址
            %   'ClientPort' - 客户端端口号
            %   'ServerIP' - 服务器IP地址
            %   'ServerPort' - 服务器端口号
            %   'ProjectRoot' - 项目根目录路径
            
            % 获取项目根目录(假设PcapManager.m在项目目录下)
            obj.project_root_path = pwd;
            
            % 设置输出目录
            output_dir_name = 'output';
            output_path = fullfile(obj.project_root_path, output_dir_name);
            
            % 检查并创建输出目录
            if ~exist(output_path, 'dir')
                fprintf('PcapManager: 输出目录 "%s" 不存在，尝试创建...\n', output_path);
                mkdir(output_path);
            end

            % 设置默认配置值
            default_pcap_basename = 'tls13_handshake.pcap';
            default_keylog_basename = 'tls13_sslkeylog.txt';
            default_client_ip = '10.0.0.2';
            default_client_port = uint16(54321);
            default_server_ip = '10.0.0.1';
            default_server_port = uint16(443);

            % 创建输入解析器
            p = inputParser;
            
            % 添加参数
            addParameter(p, 'PcapBasename', default_pcap_basename, @ischar);
            addParameter(p, 'KeylogBasename', default_keylog_basename, @ischar);
            addParameter(p, 'ClientIP', default_client_ip, @ischar);
            addParameter(p, 'ClientPort', default_client_port, @(x) isnumeric(x) && isscalar(x));
            addParameter(p, 'ServerIP', default_server_ip, @ischar);
            addParameter(p, 'ServerPort', default_server_port, @(x) isnumeric(x) && isscalar(x));
            addParameter(p, 'ProjectRoot', obj.project_root_path, @ischar);
            
            % 解析输入参数
            parse(p, varargin{:});

            % 更新项目根目录(如果传入)
            obj.project_root_path = p.Results.ProjectRoot;
            
            % 重新计算输出路径
            output_path = fullfile(obj.project_root_path, output_dir_name);
            
            % 再次确保输出目录存在
            if ~exist(output_path, 'dir')
                mkdir(output_path);
            end

            % 设置文件路径
            obj.pcap_full_path_prop = fullfile(output_path, p.Results.PcapBasename);
            obj.keylog_full_path_prop = fullfile(output_path, p.Results.KeylogBasename);
            
            % 设置网络参数
            obj.client_ip_str_prop = p.Results.ClientIP;
            obj.client_port_uint16_prop = uint16(p.Results.ClientPort);
            obj.server_ip_str_prop = p.Results.ServerIP;
            obj.server_port_uint16_prop = uint16(p.Results.ServerPort);

            % 初始化PCAP文件
            obj.pcap_fid = PcapWriterUtils.initPcapFile(obj.pcap_full_path_prop);
            
            % 检查PCAP文件初始化是否成功
            if obj.pcap_fid == -1
                error('PcapManager: 无法初始化PCAP文件 "%s"', obj.pcap_full_path_prop);
            end
            
            % 确保每次都是新的KeyLog文件
            if exist(obj.keylog_full_path_prop, 'file')
                delete(obj.keylog_full_path_prop);
            end
            
            % 初始化KeyLog文件
            obj.keylog_fid = KeyLogFileUtils.initKeyLogFile(obj.keylog_full_path_prop);
            
            % 检查KeyLog文件初始化是否成功
            if obj.keylog_fid == -1
                error('PcapManager: 无法初始化KeyLog文件 "%s"', obj.keylog_full_path_prop);
            end
            
            % 初始化TCP序列号和确认号(随机值)
            obj.c2s_next_seq_num = uint32(randi(2^30));
            obj.s2c_next_seq_num = uint32(randi(2^30));
            obj.s2c_ack_for_c_data = obj.c2s_next_seq_num;
            obj.c2s_ack_for_s_data = obj.s2c_next_seq_num;
            
            % 初始化时间戳
            obj.current_ts_sec = uint32(floor(posixtime(datetime('now'))));
            obj.current_ts_usec_counter = uint32(0);
            
            % 输出初始化信息
            fprintf('信息 (PcapManager): PcapManager已为会话 %s:%d <-> %s:%d 初始化。\n  PCAP: %s\n  KeyLog: %s\n', ...
                obj.client_ip_str_prop, obj.client_port_uint16_prop, obj.server_ip_str_prop, obj.server_port_uint16_prop, ...
                obj.pcap_full_path_prop, obj.keylog_full_path_prop);
        end
        
        function addTLSRecord(obj, tls_record_bytes, is_from_client_to_server)
            % 将TLS记录添加到PCAP文件中
            % 参数:
            %   tls_record_bytes - TLS记录数据(uint8数组)
            %   is_from_client_to_server - 是否从客户端发送到服务器(逻辑值)
            
            % 检查PCAP文件是否已初始化
            if obj.pcap_fid == -1
                fprintf('错误 (PcapManager): PCAP文件未初始化。\n');
                return;
            end
            
            % 检查TLS记录是否为空
            if isempty(tls_record_bytes)
                fprintf('警告 (PcapManager): 尝试添加空的TLS记录到PCAP。\n');
                return;
            end
            
            % 初始化IP和端口变量
            srcIP = '';
            dstIP = '';
            srcPort = uint16(0);
            dstPort = uint16(0);
            currentSeqToSend = uint32(0);
            ackNumToSend = uint32(0);
            
            % 根据方向设置源/目的IP、端口和序列号
            if is_from_client_to_server
                srcIP = obj.client_ip_str_prop;
                dstIP = obj.server_ip_str_prop;
                srcPort = obj.client_port_uint16_prop;
                dstPort = obj.server_port_uint16_prop;
                currentSeqToSend = obj.c2s_next_seq_num;
                ackNumToSend = obj.c2s_ack_for_s_data;
            else 
                srcIP = obj.server_ip_str_prop;
                dstIP = obj.client_ip_str_prop;
                srcPort = obj.server_port_uint16_prop;
                dstPort = obj.client_port_uint16_prop;
                currentSeqToSend = obj.s2c_next_seq_num;
                ackNumToSend = obj.s2c_ack_for_c_data;
            end
            
            % 设置TCP标志(PSH和ACK)
            tcpFlags = {'PSH', 'ACK'};
            
            % 构造TCP/IP数据包
            packet_bytes = PcapWriterUtils.constructTCPIPPacket(tls_record_bytes, srcIP, dstIP, srcPort, dstPort, currentSeqToSend, ackNumToSend, tcpFlags, is_from_client_to_server);
            
            % 更新时间戳
            obj.current_ts_usec_counter = obj.current_ts_usec_counter + uint32(randi([1000, 50000]));
            
            % 处理微秒计数器溢出
            if obj.current_ts_usec_counter >= 1000000
                obj.current_ts_sec = obj.current_ts_sec + uint32(floor(obj.current_ts_usec_counter / 1000000));
                obj.current_ts_usec_counter = mod(obj.current_ts_usec_counter, 1000000);
            end
            
            % 将数据包添加到PCAP文件
            PcapWriterUtils.addPacketToPcap(obj.pcap_fid, packet_bytes, obj.current_ts_sec, obj.current_ts_usec_counter);
            
            % 计算载荷长度
            payload_len = uint32(length(tls_record_bytes));
            
            % 更新序列号和确认号
            if is_from_client_to_server
                obj.c2s_next_seq_num = obj.c2s_next_seq_num + payload_len;
                obj.s2c_ack_for_c_data = obj.c2s_next_seq_num;
            else
                obj.s2c_next_seq_num = obj.s2c_next_seq_num + payload_len;
                obj.c2s_ack_for_s_data = obj.s2c_next_seq_num;
            end
        end
        
        function addKeyToLog(obj, label_str, client_random_hex_str, secret_hex_str)
            % 将密钥信息添加到密钥日志文件
            % 参数:
            %   label_str - 密钥标签(如'CLIENT_HANDSHAKE_TRAFFIC_SECRET')
            %   client_random_hex_str - 客户端随机数的十六进制表示
            %   secret_hex_str - 密钥的十六进制表示
            
            % 检查密钥日志文件是否已初始化
            if obj.keylog_fid == -1
                fprintf('错误 (PcapManager): KeyLog文件未初始化。\n');
                return;
            end
            
            % 调用KeyLogFileUtils添加密钥
            KeyLogFileUtils.addKeyToLog(obj.keylog_fid, label_str, client_random_hex_str, secret_hex_str);
        end
        
        function close(obj)
            % 关闭PCAP和密钥日志文件
            
            % 关闭PCAP文件
            PcapWriterUtils.closePcapFile(obj.pcap_fid);
            
            % 关闭密钥日志文件
            KeyLogFileUtils.closeKeyLogFile(obj.keylog_fid);
            
            % 重置文件句柄
            obj.pcap_fid = -1;
            obj.keylog_fid = -1;
            
            % 输出关闭信息
            fprintf('信息 (PcapManager): PCAP 和 KeyLog 文件已关闭。\n');
        end
        
        function delete(obj)
            % 析构函数，确保文件被正确关闭
            
            % 检查文件是否仍然打开
            if obj.pcap_fid ~= -1 || obj.keylog_fid ~= -1
                obj.close();
            end
        end
    end
end