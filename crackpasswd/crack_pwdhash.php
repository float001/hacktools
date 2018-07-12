<?php
//$pwd = "===";
//$hash = password_hash($pwd, PASSWORD_DEFAULT);
//echo $hash;
function testpasswd($cryptpasswd) {
    echo $cryptpasswd . "\n";
    $handle  = fopen("dics.data", "r");
    while (!feof ($handle)) {
        $buf = fgets($handle, 4096);
        $pwd= str_replace(array("\r\n", "\r", "\n"), "", $buf); 
        echo $pwd . "\n";
        if (password_verify($pwd, $cryptpasswd)) {
            echo "Found Password!!!,密码为：". $pwd . "\n";
            return;
        }
    }
    echo "Password no found !! \n";
    fclose ($handle);
}

$passfile = fopen("password_hash", "r");
while(!feof($passfile)) {
    $buffer = fgets($passfile, 4096);
    if (strlen($buffer) > 2) {
        $str = str_replace(array("\r\n", "\r", "\n"), "", $buffer); 
        testpasswd($str);
    }
}
fclose ($passfile);
?>
