<?php
// 演示项目：包含多种 HNP 漏洞类型

// 1. 重定向漏洞 - 密码重置
function resetPassword() {
    $host = $_SERVER['HTTP_HOST'];  // 用户可控
    $token = $_GET['token'];
    $url = "https://" . $host . "/reset?token=" . $token;
    header("Location: " . $url);  // 危险：可被劫持到攻击者域名
}

// 2. 邮件漏洞 - 账户验证
function sendVerificationEmail() {
    $host = $_SERVER['HTTP_HOST'];
    $email = $_POST['email'];
    $verifyUrl = "https://" . $host . "/verify?code=" . generateCode();
    
    // 危险：邮件中的链接可被劫持
    $body = "请点击链接验证账户：" . $verifyUrl;
    mail($email, "账户验证", $body);
}

// 3. WordPress 风格漏洞
function wpLoginRedirect() {
    $redirectUrl = home_url('/dashboard');  // 动态生成
    wp_redirect($redirectUrl);  // 危险：未钉死域名
}

// 4. Laravel 风格漏洞
function laravelRedirect() {
    $url = url('/profile');  // 相对路径转绝对
    return redirect()->to($url);  // 危险：依赖 Host 头
}

// 5. 安全代码示例（对比）
function safeRedirect() {
    $url = "https://example.com/safe";  // 硬编码域名
    header("Location: " . $url);  // 安全
}

// 6. JSON API 响应漏洞
function apiResponse() {
    $host = $_SERVER['HTTP_HOST'];
    $data = [
        'status' => 'success',
        'redirect_url' => "https://" . $host . "/callback"  // 危险：API 返回可劫持 URL
    ];
    echo json_encode($data);
}

function generateCode() {
    return bin2hex(random_bytes(16));
}
?>
