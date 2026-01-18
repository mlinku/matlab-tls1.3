% PcapWriterUtils.m
% PCAP (数据包捕获)文件工具类
% 用于创建符合PCAP文件格式的网络捕获文件，支持TLS记录的TCP/IP封装
% 该类提供了生成用于网络分析工具（如Wireshark）的数据包捕获文件所需的全部功能
classdef PcapWriterUtils
    methods (Static)

        function bytes = loadBytesFromFile(filePath)
            % 从文件中加载原始字节数据
            % 参数:
            %   filePath - 要读取的文件路径
            % 返回:
            %   bytes - 文件内容的字节数组(uint8类型)，加载失败则返回空数组
            
            bytes = []; 
            % 以二进制模式打开文件
            fid = fopen(filePath, 'rb');
            
            % 检查文件是否成功打开
            if fid == -1
                fprintf('错误 (PcapWriterUtils): 无法打开文件 %s\n', filePath); 
                return; 
            end
            
            % 尝试读取文件内容
            try 
                bytes = fread(fid, '*uint8')'; 
            catch ME
                fprintf('错误 (PcapWriterUtils): 读取文件 %s: %s\n', filePath, ME.message); 
            end
            
            % 关闭文件
            fclose(fid);
        end

        function fid = initPcapFile(filename)
            % 初始化PCAP文件并写入全局头部
            % PCAP格式使用小端序，包含文件魔数、版本和配置信息
            % 参数:
            %   filename - 要创建的PCAP文件路径
            % 返回:
            %   fid - 打开的文件句柄，失败则抛出错误
            
            % 创建文件
            fid = fopen(filename, 'wb');
            if fid == -1
                error('无法创建PCAP文件: %s', filename); 
            end
            
            % PCAP文件头部字段
            magic_number = uint32(hex2dec('a1b2c3d4')); % 小端序PCAP魔数标识
            version_major = uint16(2);                  % 主版本号
            version_minor = uint16(4);                  % 次版本号
            thiszone = int32(0);                        % GMT与本地时区的差异(秒)
            sigfigs = uint32(0);                        % 时间戳精度(通常为0)
            snaplen = uint32(65535);                    % 数据包最大长度
            network = uint32(1);                        % 链路层类型(1=以太网)
            
            % 使用小端序('l')写入所有头部字段
            fwrite(fid, magic_number, 'uint32', 0, 'l'); 
            fwrite(fid, version_major, 'uint16', 0, 'l');
            fwrite(fid, version_minor, 'uint16', 0, 'l'); 
            fwrite(fid, thiszone, 'int32', 0, 'l');
            fwrite(fid, sigfigs, 'uint32', 0, 'l'); 
            fwrite(fid, snaplen, 'uint32', 0, 'l');
            fwrite(fid, network, 'uint32', 0, 'l');
            
            % 移除日志以减少冗余输出
            % fprintf('信息: 小端序PCAP文件 "%s" 已初始化。\n', filename);
        end

        function closePcapFile(fid)
            % 关闭之前打开的PCAP文件
            % 参数:
            %   fid - 文件句柄(由initPcapFile返回)
            
            if fid ~= -1
                fclose(fid); 
            end 
            % 移除日志以减少冗余
        end
        
        function checksum = calculateInternetChecksum(header_bytes_no_checksum_field)
            % 计算互联网校验和(用于IP和TCP头部)
            % 实现RFC 1071中定义的标准互联网校验和算法
            % 参数:
            %   header_bytes_no_checksum_field - 不包含校验和字段的头部字节(校验和字段应为0)
            % 返回:
            %   checksum - 2字节校验和(大端序uint8数组)
            
            % 确保数据长度为偶数字节
            data_to_sum = header_bytes_no_checksum_field;
            if mod(length(data_to_sum), 2) ~= 0
                data_to_sum = [data_to_sum, uint8(0)]; 
            end
            
            % 按16位字进行累加
            sum_val = uint32(0);
            for i = 1:2:length(data_to_sum) 
                % 按网络字节序(大端序)解释数据
                sum_val = sum_val + uint32(data_to_sum(i))*256 + uint32(data_to_sum(i+1));
            end
            
            % 处理进位(将高16位加回低16位直到没有进位)
            while bitshift(sum_val, -16) > 0
                sum_val = bitand(sum_val, uint32(65535)) + bitshift(sum_val, -16);
            end
            
            % 对结果取反(一的补码)得到校验和
            checksum_val = bitcmp(uint16(sum_val));
            
            % 转换为网络字节序(大端序)字节
            checksum = typecast(swapbytes(checksum_val), 'uint8');
        end

        function tcp_checksum_bytes = calculateTCPChecksum(src_ip_bytes, dst_ip_bytes, tcp_segment_bytes)
            % 计算TCP校验和(包括TCP伪头部)
            % TCP校验和需要IP伪头部，包含源IP、目的IP、协议号和TCP段长度
            % 参数:
            %   src_ip_bytes - 4字节源IP地址(uint8行向量)
            %   dst_ip_bytes - 4字节目标IP地址(uint8行向量)
            %   tcp_segment_bytes - 完整的TCP段(TCP头部+TCP数据)，其中TCP头部的校验和字段应置为0
            % 返回:
            %   tcp_checksum_bytes - 2字节的TCP校验和(大端序uint8行向量)

            % TCP协议号为6
            protocol_tcp_byte = uint8(6); 
            
            % 计算TCP段总长度(包括头部和数据)
            tcp_length_val = uint16(length(tcp_segment_bytes)); 
            
            % 转换为网络字节序(大端序)
            tcp_length_bytes = typecast(swapbytes(tcp_length_val), 'uint8'); 

            % 构建TCP伪头部(12字节)，用于校验和计算
            % 伪头部包含: 源IP(4) + 目的IP(4) + 零字节(1) + 协议(1) + TCP长度(2)
            pseudo_header = [src_ip_bytes, dst_ip_bytes, uint8(0), protocol_tcp_byte, tcp_length_bytes];

            % 准备校验和计算的完整数据 = 伪头部 + TCP段
            data_for_checksum = [pseudo_header, tcp_segment_bytes];

            % 确保数据长度为偶数字节(如果不是，末尾补一个0字节)
            if mod(length(data_for_checksum), 2) ~= 0
                data_for_checksum = [data_for_checksum, uint8(0)];
            end
            
            % 计算16位字的补码和(与IP头校验和计算方式相同)
            sum_val = uint32(0);
            
            % 所有参与计算的字段都应视为大端序(网络字节序)
            for i = 1:2:length(data_for_checksum)
                sum_val = sum_val + uint32(data_for_checksum(i))*256 + uint32(data_for_checksum(i+1));
            end
            
            % 处理进位
            while bitshift(sum_val, -16) > 0
                sum_val = bitand(sum_val, uint32(65535)) + bitshift(sum_val, -16);
            end
            
            % 对结果取反(一的补码)得到校验和
            checksum_val = bitcmp(uint16(sum_val)); 
            
            % 转换为网络字节序(大端序)字节
            tcp_checksum_bytes = typecast(swapbytes(checksum_val), 'uint8'); 
        end
        
        function full_packet_bytes = constructTCPIPPacket(tls_record_bytes, src_ip_str, dst_ip_str, src_port_uint16, dst_port_uint16, tcp_seq_num_uint32, tcp_ack_num_uint32, tcp_flags_str_array, is_client_to_server)
            % 构造包含TLS记录的完整TCP/IP以太网帧
            % 处理所有协议层(以太网、IP、TCP)的封装，计算正确的校验和
            % 参数:
            %   tls_record_bytes - 要封装的TLS记录数据
            %   src_ip_str - 源IP地址(字符串，如'192.168.1.1')
            %   dst_ip_str - 目标IP地址(字符串，如'192.168.1.2')
            %   src_port_uint16 - 源端口号
            %   dst_port_uint16 - 目标端口号
            %   tcp_seq_num_uint32 - TCP序列号
            %   tcp_ack_num_uint32 - TCP确认号
            %   tcp_flags_str_array - TCP标志数组，包含如'ACK'、'PSH'等字符串
            %   is_client_to_server - 指示数据方向(true表示客户端到服务器)
            % 返回:
            %   full_packet_bytes - 完整的数据包字节(包括以太网、IP、TCP头部和TLS数据)

            % 1. 构建以太网头部(14字节)
            if is_client_to_server
                % 客户端到服务器方向的MAC地址
                dst_mac = uint8(hex2dec(['AA';'BB';'CC';'DD';'EE';'FF']))'; 
                src_mac = uint8(hex2dec(['11';'22';'33';'44';'55';'66']))';
            else
                % 服务器到客户端方向的MAC地址
                dst_mac = uint8(hex2dec(['11';'22';'33';'44';'55';'66']))'; 
                src_mac = uint8(hex2dec(['AA';'BB';'CC';'DD';'EE';'FF']))'; 
            end
            
            % 以太网类型字段(0x0800表示IPv4)
            ethertype_ipv4 = uint8([0x08, 0x00]); 
            
            % 组合以太网头部
            ethernet_header = [dst_mac, src_mac, ethertype_ipv4];

            % 2. 构建IPv4头部(20字节)
            version_ihl = uint8(hex2dec('45'));      % 版本(4)和头部长度(5*4=20字节)
            dscp_ecn = uint8(0);                     % 区分服务和ECN字段
            
            % 生成随机的标识字段
            identification_val = uint16(randi([0,65535])); 
            identification_bytes = typecast(swapbytes(identification_val), 'uint8'); 
            
            flags_fragment_offset = uint8([0x40, 0x00]); % 不分片标志(Don't Fragment)
            ttl = uint8(64);                             % 生存时间
            protocol_tcp = uint8(6);                     % 协议字段(6=TCP)
            
            % 解析IP地址字符串为字节数组
            src_ip_bytes_vec = uint8(sscanf(src_ip_str, '%d.%d.%d.%d'))';
            dst_ip_bytes_vec = uint8(sscanf(dst_ip_str, '%d.%d.%d.%d'))';
            
            % TLS记录作为TCP有效载荷
            tcp_payload_bytes = tls_record_bytes;
            
            % TCP头部固定长度(无选项时为20字节)
            tcp_header_fixed_len = 20;
            tcp_segment_len = tcp_header_fixed_len + length(tcp_payload_bytes);
            
            % 计算IP总长度(IP头部+TCP段)
            ip_total_len_val = 20 + tcp_segment_len; 
            ip_total_len_bytes = typecast(swapbytes(uint16(ip_total_len_val)), 'uint8');

            % 构建不包含校验和的IP头部
            ipv4_header_no_checksum = [version_ihl, dscp_ecn, ip_total_len_bytes, identification_bytes, flags_fragment_offset, ttl, protocol_tcp, uint8([0,0]), src_ip_bytes_vec, dst_ip_bytes_vec];
            
            % 计算IP头部校验和
            header_checksum_ip_bytes = PcapWriterUtils.calculateInternetChecksum(ipv4_header_no_checksum);
            
            % 构建完整的IP头部(包含校验和)
            ipv4_header = [version_ihl, dscp_ecn, ip_total_len_bytes, identification_bytes, flags_fragment_offset, ttl, protocol_tcp, header_checksum_ip_bytes, src_ip_bytes_vec, dst_ip_bytes_vec];

            % 3. 构建TCP头部(20字节，无选项)
            % 转换为网络字节序(大端序)
            src_port_bytes = typecast(swapbytes(uint16(src_port_uint16)), 'uint8'); 
            dst_port_bytes = typecast(swapbytes(uint16(dst_port_uint16)), 'uint8');
            seq_num_bytes = typecast(swapbytes(uint32(tcp_seq_num_uint32)), 'uint8');
            ack_num_bytes = typecast(swapbytes(uint32(tcp_ack_num_uint32)), 'uint8');
            
            % 数据偏移字段(头部长度，以32位字为单位)
            tcp_header_len_nibble = uint8(5); % 5*4=20字节
            data_offset_byte = bitshift(tcp_header_len_nibble, 4);
            
            % 设置TCP控制标志
            control_flags_byte = uint8(0);
            if any(strcmpi(tcp_flags_str_array, 'FIN'))
                control_flags_byte = bitor(control_flags_byte, 1); 
            end
            if any(strcmpi(tcp_flags_str_array, 'SYN'))
                control_flags_byte = bitor(control_flags_byte, 2); 
            end
            if any(strcmpi(tcp_flags_str_array, 'RST'))
                control_flags_byte = bitor(control_flags_byte, 4); 
            end
            if any(strcmpi(tcp_flags_str_array, 'PSH'))
                control_flags_byte = bitor(control_flags_byte, 8); 
            end
            if any(strcmpi(tcp_flags_str_array, 'ACK'))
                control_flags_byte = bitor(control_flags_byte, 16); 
            end
            if any(strcmpi(tcp_flags_str_array, 'URG'))
                control_flags_byte = bitor(control_flags_byte, 32); 
            end
            
            % 窗口大小字段
            window_size_val = uint16(64240); 
            window_size_bytes = typecast(swapbytes(window_size_val), 'uint8');
            
            % 校验和字段(先置为0用于校验和计算)
            checksum_tcp_placeholder = uint8([0x00, 0x00]); 
            
            % 紧急指针字段
            urgent_pointer_bytes = uint8([0x00, 0x00]);
            
            % 构建不包含校验和的TCP头部
            tcp_header_no_checksum = [src_port_bytes, dst_port_bytes, seq_num_bytes, ack_num_bytes, data_offset_byte, control_flags_byte, window_size_bytes, checksum_tcp_placeholder, urgent_pointer_bytes];
            
            % 准备用于校验和计算的TCP段(头部和数据)
            tcp_segment_for_checksum = [tcp_header_no_checksum, tcp_payload_bytes];
            
            % 计算TCP校验和(需要考虑IP伪头部)
            checksum_tcp_calculated_bytes = PcapWriterUtils.calculateTCPChecksum(src_ip_bytes_vec, dst_ip_bytes_vec, tcp_segment_for_checksum);
            
            % 构建最终的TCP头部(包含校验和)
            tcp_header_final = [src_port_bytes, dst_port_bytes, seq_num_bytes, ack_num_bytes, data_offset_byte, control_flags_byte, window_size_bytes, checksum_tcp_calculated_bytes, urgent_pointer_bytes];
            
            % 组合完整的数据包
            full_packet_bytes = [ethernet_header, ipv4_header, tcp_header_final, tcp_payload_bytes];
        end

        function addPacketToPcap(fid, full_packet_bytes, ts_sec, ts_usec)
            % 将数据包和时间戳写入PCAP文件
            % PCAP文件中每个数据包前都有一个16字节的包头，包含时间戳和长度信息
            % 参数:
            %   fid - PCAP文件句柄
            %   full_packet_bytes - 完整的数据包字节
            %   ts_sec - 时间戳秒部分
            %   ts_usec - 时间戳微秒部分
            
            if fid == -1
                error('无效的PCAP文件句柄'); 
            end
            
            % 准备数据包头部字段
            orig_len = uint32(length(full_packet_bytes)); % 原始数据包长度
            incl_len = orig_len;                          % 实际捕获的长度(与原始长度相同)
            
            % 使用小端序('l')写入数据包头部
            fwrite(fid, uint32(ts_sec), 'uint32', 0, 'l');     % 时间戳秒部分
            fwrite(fid, uint32(ts_usec), 'uint32', 0, 'l');    % 时间戳微秒部分
            fwrite(fid, incl_len, 'uint32', 0, 'l');           % 捕获长度
            fwrite(fid, orig_len, 'uint32', 0, 'l');           % 原始长度
            
            % 写入数据包内容
            fwrite(fid, full_packet_bytes, 'uint8');
        end
    end
end