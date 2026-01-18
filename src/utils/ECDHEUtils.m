% ECDHEUtils.m
% 椭圆曲线Diffie-Hellman密钥交换(ECDHE)工具类
% 实现TLS 1.3中使用的X25519密钥协商功能
classdef ECDHEUtils
    methods (Static)
        function keyMap = getKeyMapManager(action, keyHex, value)
            % 管理密钥映射池，用于缓存和重用密钥对象
            % 参数:
            %   action - 操作类型: 'get_map', 'add_entry', 'get_entry', 'clear_map'
            %   keyHex - 密钥的十六进制表示(字符串)
            %   value - 要添加到映射中的值
            % 返回:
            %   keyMap - 根据操作返回映射对象或特定条目
            
            % 使用persistent变量在多次调用之间保持映射
            persistent key_to_jce_object_map;
            
            % 首次调用时初始化映射
            if isempty(key_to_jce_object_map) || ~isa(key_to_jce_object_map, 'containers.Map')
                key_to_jce_object_map = containers.Map('KeyType', 'char', 'ValueType', 'any');
                % fprintf('信息 (ECDHEUtils): 全局密钥映射池已创建。\n');
            end
            
            % 默认返回完整映射
            keyMap = key_to_jce_object_map;
            
            % 根据操作类型处理
            if nargin > 0
                switch lower(action)
                    case 'get_map'
                        % 不做任何处理，返回整个映射
                    case 'add_entry'
                        % 添加新条目到映射
                        if nargin == 3 && ischar(keyHex)
                            key_to_jce_object_map(keyHex) = value;
                        end
                    case 'get_entry'
                        % 获取特定条目
                        if nargin >= 2 && ischar(keyHex) && isKey(key_to_jce_object_map, keyHex)
                            keyMap = key_to_jce_object_map(keyHex);
                        else
                            keyMap = [];
                        end
                    case 'clear_map'
                        % 清空映射
                        if isa(key_to_jce_object_map, 'containers.Map')
                            remove(key_to_jce_object_map, keys(key_to_jce_object_map));
                        end
                        
                        key_to_jce_object_map = containers.Map('KeyType', 'char', 'ValueType', 'any');
                        % fprintf('信息 (ECDHEUtils): 全局密钥映射池已清空并重建。\n');
                end
            end
        end

        function [rawPubKeyBytes, rawPrivKeyBytes, jcePublicKeyObj, jcePrivateKeyObj, spkiDerEncodedPublicKey, success, errorMessage] = generateFullX25519KeyPairObjects()
            % 生成X25519密钥对，包括原始字节和JCE对象格式
            % 返回:
            %   rawPubKeyBytes - 原始公钥字节(32字节uint8数组)
            %   rawPrivKeyBytes - 原始私钥字节(32字节uint8数组)
            %   jcePublicKeyObj - Java加密扩展(JCE)公钥对象
            %   jcePrivateKeyObj - Java加密扩展(JCE)私钥对象
            %   spkiDerEncodedPublicKey - DER编码的SubjectPublicKeyInfo格式公钥
            %   success - 操作是否成功
            %   errorMessage - 错误信息(如果有)
            
            % 初始化返回值
            rawPubKeyBytes = [];
            rawPrivKeyBytes = [];
            jcePublicKeyObj = [];
            jcePrivateKeyObj = [];
            spkiDerEncodedPublicKey = [];
            success = false;
            errorMessage = '未初始化或未知错误';
            
            try
                % 导入必要的Java类
                import java.security.Security;
                import org.bouncycastle.jce.provider.BouncyCastleProvider;
                import java.security.KeyPairGenerator;
                import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
                import org.bouncycastle.util.encoders.Hex;
                
                % 确保BouncyCastle提供者已添加
                if isempty(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME))
                    Security.addProvider(BouncyCastleProvider());
                end
                
                % 创建X25519密钥对生成器
                kpg = KeyPairGenerator.getInstance('X25519', BouncyCastleProvider.PROVIDER_NAME);
                
                % 生成密钥对
                keyPair = kpg.generateKeyPair();
                
                % 获取JCE公钥和私钥对象
                jcePublicKeyObj = keyPair.getPublic();
                jcePrivateKeyObj = keyPair.getPrivate();
                
                % 验证密钥对象有效性
                if isempty(jcePublicKeyObj) || isempty(jcePrivateKeyObj)
                    error('KeyPairGenerator未能返回有效的公钥或私钥对象。');
                end
                
                % 获取公钥的DER编码
                spkiDerEncodedPublicKey = jcePublicKeyObj.getEncoded();
                
                % 验证DER编码有效性
                if isempty(spkiDerEncodedPublicKey)
                    error('jcePublicKeyObj.getEncoded() 返回为空。');
                end
                
                % 提取原始公钥字节，尝试两种方法
                if ismethod(jcePublicKeyObj, 'getUEncoding')
                    % 如果公钥对象有直接获取U坐标的方法
                    rawPubKeyBytes = reshape(uint8(jcePublicKeyObj.getUEncoding()), 1, []);
                elseif ismethod(jcePublicKeyObj, 'getEncoded')
                    % 通过解析SubjectPublicKeyInfo结构提取公钥
                    tempSpki = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(spkiDerEncodedPublicKey);
                    pubKeyDataFromSpki = tempSpki.getPublicKeyData().getBytes();
                    rawPubKeyBytes = reshape(typecast(pubKeyDataFromSpki, 'uint8'), 1, []);
                    
                    % 移除前导零字节(如果存在)
                    if numel(rawPubKeyBytes) == 33 && rawPubKeyBytes(1) == 0
                        rawPubKeyBytes = rawPubKeyBytes(2:end);
                    end
                    
                    % 验证公钥长度
                    if numel(rawPubKeyBytes) ~= 32
                        error('从SPKI getEncoded()提取的原始公钥长度不是32字节。');
                    end
                else
                    error('无法从JCE公钥对象获取原始公钥字节。');
                end
                
                % 从JCE私钥对象提取原始私钥字节
                pkcs8EncodedPrivateKey = jcePrivateKeyObj.getEncoded();
                pki = PrivateKeyInfo.getInstance(pkcs8EncodedPrivateKey);
                asn1PrimitivePrivateKey = pki.parsePrivateKey();
                
                % 验证私钥格式并提取字节
                if isa(asn1PrimitivePrivateKey, 'org.bouncycastle.asn1.ASN1OctetString')
                    rawPrivKeyBytes = reshape(uint8(asn1PrimitivePrivateKey.getOctets()), 1, []);
                else
                    error(sprintf('从PKCS#8解析的私钥部分不是预期的ASN1OctetString，而是 %s。', class(asn1PrimitivePrivateKey)));
                end
                
                % 验证私钥长度
                if numel(rawPrivKeyBytes) ~= 32
                    error(sprintf('提取的原始私钥长度不是32字节 (%d)。', numel(rawPrivKeyBytes)));
                end
                
                % 将公钥加入映射池，便于后续查找
                rawPubKeyHexKey = lower(char(Hex.toHexString(rawPubKeyBytes)));
                ECDHEUtils.getKeyMapManager('add_entry', rawPubKeyHexKey, jcePublicKeyObj);
                
                % 操作成功
                success = true;
                errorMessage = '';
            catch ex
                % 异常处理
                errorMessage = sprintf('generateFullX25519KeyPairObjects 错误: %s', ex.message);
                
                % 如果是Java异常，添加详细信息
                if isa(ex, 'matlab.exception.JavaException')
                    errorMessage = [errorMessage, sprintf(' (Java: %s - %s)', ex.ExceptionObject.getClass().getName(), char(ex.ExceptionObject.getMessage()))];
                end
                
                % 重置所有输出
                rawPubKeyBytes = [];
                rawPrivKeyBytes = [];
                jcePublicKeyObj = [];
                jcePrivateKeyObj = [];
                spkiDerEncodedPublicKey = [];
                success = false;
            end
        end

        function [jceReconstructedPublicKey, success, errMsg] = reconstructJCEPublicKeyFromRawBytes(rawPublicKeyBytes)
            % 从原始公钥字节重建JCE公钥对象
            % 参数:
            %   rawPublicKeyBytes - 原始公钥字节(32字节uint8数组)
            % 返回:
            %   jceReconstructedPublicKey - 重建的JCE公钥对象
            %   success - 操作是否成功
            %   errMsg - 错误信息(如果有)
            
            % 初始化返回值
            jceReconstructedPublicKey = [];
            success = false;
            errMsg = '';
            
            % 验证输入长度
            if numel(rawPublicKeyBytes) ~= 32
                errMsg = '输入原始公钥字节长度不是32。';
                return;
            end
            
            try
                % 导入必要的Java类
                import org.bouncycastle.util.encoders.Hex;
                
                % 计算公钥的十六进制表示
                rawPubKeyHexKey = lower(char(Hex.toHexString(rawPublicKeyBytes)));
                
                % 首先尝试从映射池中获取已存在的对象
                retrievedObj = ECDHEUtils.getKeyMapManager('get_entry', rawPubKeyHexKey);
                
                if ~isempty(retrievedObj) && isa(retrievedObj, 'java.security.PublicKey')
                    % 映射池中找到了匹配的对象
                    jceReconstructedPublicKey = retrievedObj;
                    success = true;
                else
                    % 映射池中未找到，需要重新构建
                    errMsg = sprintf('公钥 %s 未在映射池中找到。将尝试标准重建。', rawPubKeyHexKey);
                    fprintf('警告 ECDHEUtils.reconstruct: %s\n', errMsg);
                    
                    % 导入更多必要的Java类
                    import java.security.Security;
                    import org.bouncycastle.jce.provider.BouncyCastleProvider;
                    import java.security.KeyFactory;
                    import java.security.spec.X509EncodedKeySpec;
                    import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
                    import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
                    import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
                    import org.bouncycastle.asn1.DERBitString;
                    
                    % 确保BouncyCastle提供者已添加
                    providerName = BouncyCastleProvider.PROVIDER_NAME;
                    
                    if isempty(Security.getProvider(providerName))
                        Security.addProvider(BouncyCastleProvider());
                    end
                    
                    % 获取X25519密钥工厂
                    kf = KeyFactory.getInstance('X25519', providerName);
                    
                    % 创建X25519算法标识符
                    algIdX25519 = AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519);
                    
                    % 创建公钥比特串
                    derBitStringPublicKey = DERBitString(rawPublicKeyBytes);
                    
                    % 构建SubjectPublicKeyInfo结构
                    spki = SubjectPublicKeyInfo(algIdX25519, derBitStringPublicKey);
                    
                    % 编码为DER格式
                    derEncodedSpki = spki.getEncoded('DER');
                    
                    % 创建密钥规范
                    keySpec = X509EncodedKeySpec(derEncodedSpki);
                    
                    % 生成公钥对象
                    jceReconstructedPublicKey = kf.generatePublic(keySpec);
                    
                    % 验证重建是否成功
                    if ~isempty(jceReconstructedPublicKey) && isa(jceReconstructedPublicKey, 'java.security.PublicKey')
                        success = true;
                        
                        % 将重建的公钥对象添加到映射池中
                        ECDHEUtils.getKeyMapManager('add_entry', rawPubKeyHexKey, jceReconstructedPublicKey);
                    else
                        errMsg = [errMsg, ' 标准KeyFactory重建也失败。'];
                        jceReconstructedPublicKey = [];
                    end
                end
            catch ex
                % 异常处理
                errMsg = sprintf('reconstructJCEPublicKeyFromRawBytes 错误: %s', ex.message);
                
                % 如果是Java异常，添加详细信息
                if isa(ex, 'matlab.exception.JavaException')
                    errMsg = [errMsg, sprintf(' (Java: %s)', char(ex.ExceptionObject.getMessage()))];
                end
            end
        end

        function [sharedSecret, success, errorMessage] = calculateSharedSecretFromJCEObjects(jceOwnPrivateKey, jcePeerPublicKey)
            % 使用己方私钥和对方公钥计算ECDHE共享密钥
            % 参数:
            %   jceOwnPrivateKey - 己方JCE私钥对象
            %   jcePeerPublicKey - 对方JCE公钥对象
            % 返回:
            %   sharedSecret - 计算得到的共享密钥(32字节uint8数组)
            %   success - 操作是否成功
            %   errorMessage - 错误信息(如果有)
            
            % 初始化返回值
            sharedSecret = [];
            success = false;
            errorMessage = '';
            
            % 验证私钥参数
            if isempty(jceOwnPrivateKey) || ~isa(jceOwnPrivateKey, 'java.security.PrivateKey')
                errorMessage = '己方JCE私钥对象无效。';
                return;
            end
            
            % 验证公钥参数
            if isempty(jcePeerPublicKey) || ~isa(jcePeerPublicKey, 'java.security.PublicKey')
                errorMessage = '对方JCE公钥对象无效。';
                return;
            end
            
            try
                % 导入必要的Java类
                import java.security.Security;
                import org.bouncycastle.jce.provider.BouncyCastleProvider;
                import javax.crypto.KeyAgreement;
                
                % 确保BouncyCastle提供者已添加
                providerName = BouncyCastleProvider.PROVIDER_NAME;
                
                if isempty(Security.getProvider(providerName))
                    Security.addProvider(BouncyCastleProvider());
                end
                
                % 创建密钥协商对象
                keyAgreement = KeyAgreement.getInstance('XDH', providerName);
                
                % 初始化密钥协商并执行密钥协商过程
                keyAgreement.init(jceOwnPrivateKey);
                keyAgreement.doPhase(jcePeerPublicKey, true);
                
                % 生成共享密钥
                sharedSecretJavaBytes = keyAgreement.generateSecret();
                
                % 将Java字节转换为MATLAB uint8数组
                sharedSecret = reshape(typecast(sharedSecretJavaBytes, 'uint8'), 1, []);
                
                % 验证共享密钥长度和有效性
                if numel(sharedSecret) == 32 
                    if all(sharedSecret == 0)
                        errorMessage = '共享密钥为全零。';
                        success = true;
                    else
                        success = true;
                    end
                else
                    errorMessage = sprintf('共享密钥长度(%d)不为32。', numel(sharedSecret));
                    sharedSecret = [];
                end
            catch ex
                % 异常处理
                errorMessage = sprintf('calculateSharedSecretFromJCEObjects 错误: %s', ex.message);
                
                % 如果是Java异常，添加详细信息
                if isa(ex, 'matlab.exception.JavaException')
                    errorMessage = [errorMessage, sprintf(' (Java 异常: %s - %s)', ex.ExceptionObject.getClass().getName(), char(ex.ExceptionObject.getMessage()))];
                end
                
                sharedSecret = [];
            end
        end
    end
end