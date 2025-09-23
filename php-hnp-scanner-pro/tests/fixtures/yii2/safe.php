<?php
Yii::setAlias('@web', 'https://example.com');
$url = 'https://example.com/sso';
header('Location: ' . $url);

