% RSAUtils.m
% RSA加密工具类，提供RSA密钥、证书加载和签名验证功能
% 此类依赖于Java安全API和BouncyCastle加密库，为TLS 1.3实现提供加密支持
classdef RSAUtils
    methods (Static)
        function bytes = loadBytesFromFile(filePath)
            % 从文件加载原始二进制字节数据
            % 参数:
            %   filePath - 要加载的文件路径（字符串）
            % 返回:
            %   bytes - 文件内容的原始字节（uint8数组），失败时为空数组
            
            % 初始化返回值
            bytes = [];
            
            % 以二进制模式打开文件
            fid = fopen(filePath, 'rb');
            
            % 检查文件是否成功打开
            if fid == -1
                fprintf('错误 (RSAUtils): 无法打开文件 %s\n', filePath);
                return;
            end
            
            % 尝试读取文件内容
            try
                % 读取整个文件为uint8类型的行向量
                bytes = fread(fid, '*uint8')';
            catch ME
                % 捕获并报告读取错误
                fprintf('错误 (RSAUtils): 读取文件 %s: %s\n', filePath, ME.message);
            end
            
            % 关闭文件句柄
            fclose(fid);
        end

        function privateKeyObj = loadPKCS8PrivateKeyFromFile(filePath, keyAlgorithm)
            % 从DER编码的PKCS#8格式文件加载私钥
            % 参数:
            %   filePath - 私钥文件路径（字符串）
            %   keyAlgorithm - 密钥算法，例如'RSA'（字符串）
            % 返回:
            %   privateKeyObj - Java密钥对象(java.security.PrivateKey)，失败时为空
            
            % 初始化返回值
            privateKeyObj = [];
            
            % 加载私钥文件的DER编码字节
            derBytes = RSAUtils.loadBytesFromFile(filePath);
            
            % 检查字节加载是否成功
            if isempty(derBytes)
                fprintf('错误 (RSAUtils): 未从 %s 加载字节。\n', filePath);
                return;
            end
            
            % 尝试转换DER字节为Java密钥对象
            try
                % 导入所需的Java类
                import java.security.KeyFactory;
                import java.security.spec.PKCS8EncodedKeySpec;
                import java.security.Security;
                import org.bouncycastle.jce.provider.BouncyCastleProvider;
                
                % 获取BouncyCastle提供者名称
                providerName = BouncyCastleProvider.PROVIDER_NAME;
                
                % 确保BouncyCastle提供者已注册
                if isempty(Security.getProvider(providerName))
                    Security.addProvider(BouncyCastleProvider());
                end
                
                % 创建PKCS8密钥规格
                keySpec = PKCS8EncodedKeySpec(derBytes);
                
                % 获取指定算法的密钥工厂
                kf = KeyFactory.getInstance(keyAlgorithm, providerName);
                
                % 从密钥规格生成私钥
                privateKeyObj = kf.generatePrivate(keySpec);
            catch ME
                % 捕获并报告密钥加载错误
                fprintf('错误 (RSAUtils): 加载PKCS#8私钥失败 (%s, %s): %s\n', ...
                    filePath, keyAlgorithm, ME.message);
                
                % 如果是Java异常，打印更多详细信息
                if isa(ME, 'matlab.exception.JavaException')
                    fprintf('  Java异常: %s\n', char(ME.ExceptionObject.toString()));
                end
            end
        end

        function certificateObj = loadX509CertificateFromBytes(derBytes, providerName)
            % 从DER编码的字节数组加载X.509证书对象
            % 参数:
            %   derBytes - DER编码的证书字节（uint8数组）
            %   providerName - 可选，加密提供者名称，默认为BouncyCastle
            % 返回:
            %   certificateObj - Java证书对象(java.security.cert.X509Certificate)，失败时为空
            
            % 初始化返回值
            certificateObj = [];
            
            % 验证输入字节数组
            if isempty(derBytes)
                fprintf('错误 (RSAUtils): 输入的证书DER字节为空。\n');
                return;
            end
            
            % 如果未指定提供者，使用BouncyCastle
            if nargin < 2
                providerName = org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;
            end
            
            try
                % 导入所需的Java类
                import java.security.cert.CertificateFactory;
                import java.io.ByteArrayInputStream;
                import java.security.Security;
                import org.bouncycastle.jce.provider.BouncyCastleProvider;

                % 确保指定的加密提供者已注册
                if isempty(Security.getProvider(providerName))
                    Security.addProvider(BouncyCastleProvider());
                end

                % 获取X.509证书工厂
                cf = CertificateFactory.getInstance('X.509', providerName);
                
                % 将MATLAB字节数组转换为Java输入流
                is = ByteArrayInputStream(derBytes);
                
                % 从输入流生成证书对象
                certificateObj = cf.generateCertificate(is);
                
                % 关闭输入流
                is.close();
            catch ME
                % 捕获并报告证书加载错误
                fprintf('错误 (RSAUtils): 从字节加载X.509证书失败: %s\n', ME.message);
                
                % 如果是Java异常，打印更多详细信息
                if isa(ME, 'matlab.exception.JavaException')
                    fprintf('  Java异常: %s\n', char(ME.ExceptionObject.toString()));
                end
            end
        end

        function certificateObj = loadX509CertificateFromFile(filePath)
            % 从DER编码的文件加载X.509证书对象
            % 参数:
            %   filePath - 证书文件路径（字符串）
            % 返回:
            %   certificateObj - Java证书对象(java.security.cert.X509Certificate)，失败时为空
            
            % 初始化返回值
            certificateObj = [];
            
            % 加载证书文件的DER编码字节
            derBytes = RSAUtils.loadBytesFromFile(filePath);
            
            % 检查字节加载是否成功
            if isempty(derBytes)
                fprintf('错误 (RSAUtils): 未能从文件 %s 中加载证书字节以供解析。\n', filePath);
                return;
            end
            
            % 调用基于字节的证书加载器
            certificateObj = RSAUtils.loadX509CertificateFromBytes(derBytes);
            
            % 成功加载的日志（已注释掉）
            % if ~isempty(certificateObj)
            %     fprintf('信息 (RSAUtils): 从 %s 成功加载 X.509 证书。\n', filePath);
            % end
        end

        function signatureBytes = signDataPSS(jceRsaPrivateKey, dataToSignBytes, pssSpecParams)
            % 使用RSA-PSS算法对数据进行签名
            % 参数:
            %   jceRsaPrivateKey - RSA私钥对象(java.security.PrivateKey)
            %   dataToSignBytes - 待签名数据（uint8数组）
            %   pssSpecParams - PSS参数结构体，包含下列字段:
            %     - hashAlg: 哈希算法名称，如'SHA-256'
            %     - mgfAlg: 掩码生成函数算法，通常为'MGF1'
            %     - mgfHashAlg: MGF使用的哈希算法，如'SHA-256'
            %     - saltLen: 盐长度，通常为int32(32)
            %     - trailerField: 尾部字段，通常为int32(1)
            % 返回:
            %   signatureBytes - RSA-PSS签名结果（uint8数组），失败时为空数组
            
            % 初始化返回值
            signatureBytes = [];
            
            % 验证RSA私钥
            if isempty(jceRsaPrivateKey) || ~isa(jceRsaPrivateKey, 'java.security.PrivateKey') || ...
               ~strcmp(jceRsaPrivateKey.getAlgorithm(), 'RSA')
                fprintf('错误 (RSAUtils.signDataPSS): 无效RSA私钥。\n');
                return;
            end
            
            % 验证PSS参数结构体
            if ~isstruct(pssSpecParams) || ...
               ~all(isfield(pssSpecParams, {'hashAlg', 'mgfAlg', 'mgfHashAlg', 'saltLen', 'trailerField'}))
                fprintf('错误 (RSAUtils.signDataPSS): pssSpecParams不完整。\n');
                return;
            end
            
            try
                % 导入所需的Java类
                import java.security.Signature;
                import java.security.spec.PSSParameterSpec;
                import java.security.spec.MGF1ParameterSpec;
                import java.security.Security;
                import org.bouncycastle.jce.provider.BouncyCastleProvider;
                
                % 获取BouncyCastle提供者名称
                providerName = BouncyCastleProvider.PROVIDER_NAME;
                
                % 确保BouncyCastle提供者已注册
                if isempty(Security.getProvider(providerName))
                    Security.addProvider(BouncyCastleProvider());
                end
                
                % 使用RSASSA-PSS签名算法
                jceSignatureAlgorithm = 'RSASSA-PSS';
                
                % 获取签名对象
                signatureObj = Signature.getInstance(jceSignatureAlgorithm, providerName);
                
                % 创建MGF1参数规格
                mgf1Spec = MGF1ParameterSpec(pssSpecParams.mgfHashAlg);
                
                % 创建PSS参数规格
                pssSpec = PSSParameterSpec(pssSpecParams.hashAlg, pssSpecParams.mgfAlg, ...
                    mgf1Spec, pssSpecParams.saltLen, pssSpecParams.trailerField);
                
                % 初始化签名对象用于签名
                signatureObj.initSign(jceRsaPrivateKey);
                
                % 设置PSS参数
                signatureObj.setParameter(pssSpec);
                
                % 更新待签名数据
                signatureObj.update(dataToSignBytes);
                
                % 执行签名操作
                signedBytesJava = signatureObj.sign();
                
                % 转换Java字节数组为MATLAB uint8数组
                signatureBytes = reshape(typecast(signedBytesJava, 'uint8'), 1, []);
            catch ME
                % 捕获并报告签名错误
                fprintf('错误 (RSAUtils.signDataPSS): RSA-PSS签名失败: %s\n', ME.message);
                
                % 如果是Java异常，打印更多详细信息
                if isa(ME, 'matlab.exception.JavaException')
                    fprintf('  Java异常: %s\n', char(ME.ExceptionObject.toString()));
                end
            end
        end

        function isValid = verifySignaturePSS(jceRsaPublicKey, dataToVerifyBytes, signatureBytes, pssSpecParams)
            % 使用RSA-PSS算法验证签名
            % 参数:
            %   jceRsaPublicKey - RSA公钥对象(java.security.PublicKey)
            %   dataToVerifyBytes - 原始数据（uint8数组）
            %   signatureBytes - 待验证的签名（uint8数组）
            %   pssSpecParams - PSS参数结构体，与签名时使用的参数相同
            % 返回:
            %   isValid - 逻辑值，签名验证成功为true，失败为false
            
            % 初始化返回值
            isValid = false;
            
            % 验证RSA公钥
            if isempty(jceRsaPublicKey) || ~isa(jceRsaPublicKey, 'java.security.PublicKey') || ...
               ~strcmp(jceRsaPublicKey.getAlgorithm(), 'RSA')
                fprintf('错误 (RSAUtils.verifySignaturePSS): 无效RSA公钥。\n');
                return;
            end
            
            % 验证PSS参数结构体
            if ~isstruct(pssSpecParams) || ...
               ~all(isfield(pssSpecParams, {'hashAlg', 'mgfAlg', 'mgfHashAlg', 'saltLen', 'trailerField'}))
                fprintf('错误 (RSAUtils.verifySignaturePSS): pssSpecParams不完整。\n');
                return;
            end
            
            % 验证数据和签名非空
            if isempty(dataToVerifyBytes) || isempty(signatureBytes)
                fprintf('错误 (RSAUtils.verifySignaturePSS): 待验证数据或签名不能为空。\n');
                return;
            end
            
            try
                % 导入所需的Java类
                import java.security.Signature;
                import java.security.spec.PSSParameterSpec;
                import java.security.spec.MGF1ParameterSpec;
                import java.security.Security;
                import org.bouncycastle.jce.provider.BouncyCastleProvider;
                
                % 获取BouncyCastle提供者名称
                providerName = BouncyCastleProvider.PROVIDER_NAME;
                
                % 确保BouncyCastle提供者已注册
                if isempty(Security.getProvider(providerName))
                    Security.addProvider(BouncyCastleProvider());
                end
                
                % 使用RSASSA-PSS签名算法
                jceSignatureAlgorithm = 'RSASSA-PSS';
                
                % 获取签名对象
                signatureObj = Signature.getInstance(jceSignatureAlgorithm, providerName);
                
                % 创建MGF1参数规格
                mgf1Spec = MGF1ParameterSpec(pssSpecParams.mgfHashAlg);
                
                % 创建PSS参数规格
                pssSpec = PSSParameterSpec(pssSpecParams.hashAlg, pssSpecParams.mgfAlg, ...
                    mgf1Spec, pssSpecParams.saltLen, pssSpecParams.trailerField);
                
                % 初始化签名对象用于验证
                signatureObj.initVerify(jceRsaPublicKey);
                
                % 设置PSS参数
                signatureObj.setParameter(pssSpec);
                
                % 更新待验证数据
                signatureObj.update(dataToVerifyBytes);
                
                % 执行签名验证操作
                isValid = signatureObj.verify(signatureBytes);
                
                % 转换为MATLAB逻辑值类型
                isValid = logical(isValid);
            catch ME
                % 捕获并报告验证错误
                fprintf('错误 (RSAUtils.verifySignaturePSS): RSA-PSS验签时发生错误: %s\n', ME.message);
                
                % 如果是Java异常，打印更多详细信息
                if isa(ME, 'matlab.exception.JavaException')
                    fprintf('  Java异常: %s\n', char(ME.ExceptionObject.toString()));
                end
                
                % 确保验证失败时返回false
                isValid = false;
            end
        end
    end
end