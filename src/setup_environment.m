% setup_environment.m (v4 - 正确处理 clear java)
function success = setup_environment()
    % --------------------------------------------------------------------------
    % 函数名: setup_environment
    % 描述  : 为TLS 1.3模拟项目设置MATLAB运行环境。
    %         警告: 'clear java' 会清除当前MATLAB会话中的所有Java状态。
    % 输出  :
    %   success: logical - 如果环境设置成功，则为true；否则为false。
    % --------------------------------------------------------------------------
    success = false; 
    fprintf('开始环境设置 (v4 - 正确处理 clear java)...\n');

    % --- 步骤 0: 确定项目根目录和JAR路径 ---
    script_path_initial = '';
    project_root_initial = '';
    jar_filename_initial = 'bcprov-jdk15on-1.70.jar';
    jar_path_full_initial = '';

    try
        script_path_initial = fileparts(mfilename('fullpath')); 
        project_root_initial = fileparts(script_path_initial);        
        jar_path_full_initial = fullfile(project_root_initial, 'lib', jar_filename_initial);
        fprintf('  信息: 初始项目根目录被确定为: %s\n', project_root_initial);
        if ~exist(jar_path_full_initial, 'file')
            fprintf('错误: 初始检查找不到Bouncy Castle JAR文件: %s\n', jar_path_full_initial);
            return;
        end
    catch ME_path
        fprintf('错误: 初始确定项目根目录失败: %s\n', ME_path.message); return;
    end
    
    % --- 步骤 1: 尝试 'clear java' ---
    try
        fprintf('  信息: 执行 clear java 以尝试重置Java环境...\n');
        clear java; % 清除Java类定义和对象，重新初始化部分JVM接口，并清除动态Java路径
        fprintf('  信息: clear java 执行完毕。\n');
    catch err_clear_java
        fprintf('  警告: 执行 clear java 时发生错误 (可能无权限或不支持): %s\n', err_clear_java.message);
        % 即使 clear java 失败，我们仍然尝试继续，因为后续的 javaaddpath 和 Provider 注册是关键
    end

    % --- 步骤 2: 定义路径并添加 Bouncy Castle JAR ---
    % 由于 clear java 可能清除了工作区变量，需要重新获取/定义路径
    try
        script_path = fileparts(mfilename('fullpath')); 
        project_root = fileparts(script_path); % 再次获取，以防被 clear java 清除
        
        jar_filename = 'bcprov-jdk15on-1.70.jar'; % 或者从 initial 变量恢复
        jar_path_full = fullfile(project_root, 'lib', jar_filename);

        if ~exist(jar_path_full, 'file') % 再次检查 JAR 文件
            fprintf('错误: (clear java后) 找不到Bouncy Castle JAR文件: %s\n', jar_path_full);
            fprintf('       请确保 "%s" 文件位于项目根目录 ("%s") 下的 "lib" 文件夹中。\n', jar_filename, project_root);
            return;
        end

        % 添加JAR到动态路径 (clear java 后，动态路径是空的)
        javaaddpath(jar_path_full);
        fprintf('  信息: JAR文件已添加到动态Java类路径: %s\n', jar_path_full);
        
        % --- 步骤 3: 注册并验证 Bouncy Castle Provider ---
        import java.security.Security; % 在使用Security类之前导入
        
        provider_name_bc = org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;

        if isempty(Security.getProvider(provider_name_bc))
            fprintf('  信息: BC Provider ("%s") 未找到，正在尝试添加...\n', provider_name_bc);
            bcProviderInstance = org.bouncycastle.jce.provider.BouncyCastleProvider(); % 使用完全限定名
            Security.addProvider(bcProviderInstance);    
            
            if isempty(Security.getProvider(provider_name_bc))
                fprintf('错误: 添加BC Provider ("%s") 失败。\n', provider_name_bc); return; 
            else
                fprintf('  信息: BC Provider ("%s") 已成功添加并验证。\n', provider_name_bc);
            end
        else
            fprintf('  信息: BC Provider ("%s") 已存在并已验证。\n', provider_name_bc);
        end
        
    catch err_jar_provider
        fprintf('错误: BC JAR加载或Provider处理失败: %s\n', err_jar_provider.message);
        if isa(err_jar_provider, 'matlab.exception.JavaException') && ~isempty(err_jar_provider.ExceptionObject)
             fprintf('  Java异常: %s\n', char(err_jar_provider.ExceptionObject.toString()));
        end
        return;
    end

    % --- 步骤 4: 添加MATLAB源代码路径到搜索路径 ---
    paths_to_add = { 
        script_path,                           % 'src' 目录本身
        fullfile(script_path, 'utils'),        % src/utils/
        fullfile(script_path, 'protocol')      % src/protocol/
    };
    
    fprintf('  信息: 正在添加MATLAB源代码路径...\n');
    for i = 1:length(paths_to_add)
        current_path_to_add = paths_to_add{i};
        if exist(current_path_to_add, 'dir')
            addpath(current_path_to_add);
        else
            fprintf('  警告: 目录不存在，未添加: %s\n', current_path_to_add);
        end
    end
    

    success = true; 
    fprintf('环境设置完成。\n\n');
end