# Практическая работа 3
## Необходимо разработать переборщик паролей для формы в задании Bruteforce на сайте dvwa.local (Можно использовать официальный ресурс или виртуальную машину Web Security Dojo)
Смотреть на разработанный переборщик в файле [bruteforce.go](./bruteforce.go)

## Проанализировать код и сделать кодревью, указав слабые места. Слабость уязвимого кода необходимо указать с использованием метрики CWE (база данных cwe.mitre.org)

### Анализ эндпоинта авторизации на основе CWE-правил
```php
<?php

if( isset( $_GET[ 'Login' ] ) ) {
	$user = $_GET[ 'username' ];

	$pass = $_GET[ 'password' ];

	/* (1) Небезопасное хэширование пароля (CWE-327) Использование функции md5() устаревшая практика, так как MD5 считается небезопасным и подвержен атакам по подбору */
	$pass = md5( $pass );

	/* (2) SQL-инъекция (CWE-89) - $user и $pass включены в SQL-запрос без предварительной фильтрации или экранирования */
	$query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";

	/* (3) Потенциальный риск раскрытия ошибок (CWE-209) */
	$result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

	if( $result && mysqli_num_rows( $result ) == 1 ) {
		// Get users details
		$row    = mysqli_fetch_assoc( $result );
		$avatar = $row["avatar"];

		/* (4) Уязвимость к межсайтовому скриптингу (XSS) (CWE-79) - Переменная $user вставляется в HTML-код без какой-либо очистки или экранирования */
		$html .= "<p>Welcome to the password protected area {$user}</p>";
		$html .= "<img src=\"{$avatar}\" />";
	}
	else {
		// Login failed
		$html .= "<pre><br />Username and/or password incorrect.</pre>";
	}

	((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}


/* (5) Код не ограничивает количество попыток входа, что позволяет злоумышленнику применять метод перебора (brute-force) для подбора пароля. Это существенно упрощает атаку на учетные записи пользователей. */

?>
```

### Исправленный эндпоинт авторизации на основе замеченных проблем
Если попробовать провести bruteforce, с данной реализацией login.php в DVWA, bruteforce будет провален из-за созданных проверок на безопасность
```php
<?php
session_start();

$attempts_limit = 5;
$attempts_time_window = 60;

if (!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = [];
}

$_SESSION['login_attempts'] = array_filter($_SESSION['login_attempts'], function($timestamp) use ($attempts_time_window) {
    return $timestamp > (time() - $attempts_time_window);
});

if (count($_SESSION['login_attempts']) >= $attempts_limit) {
    die('<pre>Too many login attempts. Please try again later.</pre>');
}

if (isset($_GET['Login'])) {
    $_SESSION['login_attempts'][] = time();

    $mysqli = $GLOBALS["___mysqli_ston"];
    
    $user = mysqli_real_escape_string($mysqli, $_GET['username']);
    
    $pass = $_GET['password'];
    $hashed_pass = password_hash($pass, PASSWORD_BCRYPT);

    $query = "SELECT * FROM `users` WHERE user = ? AND password = ?";
    $stmt = mysqli_prepare($mysqli, $query);
    mysqli_stmt_bind_param($stmt, "ss", $user, $hashed_pass);

    if (mysqli_stmt_execute($stmt)) {
        $result = mysqli_stmt_get_result($stmt);
        
        if ($result && mysqli_num_rows($result) == 1) {
            $row = mysqli_fetch_assoc($result);
            $avatar = htmlspecialchars($row["avatar"]);
            
            $html = "<p>Welcome to the password protected area " . htmlspecialchars($user) . "</p>";
            $html .= "<img src=\"{$avatar}\" />";
            
            $_SESSION['login_attempts'] = [];
        } else {
            $html = "<pre><br />Username and/or password incorrect.</pre>";
        }
    } else {
        error_log(mysqli_error($mysqli));
        $html = "<pre>Database error.</pre>";
    }
    
    mysqli_stmt_close($stmt);
    mysqli_close($mysqli);
}
?>
```