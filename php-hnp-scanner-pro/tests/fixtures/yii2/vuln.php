<?php
$h = $_SERVER['HTTP_HOST'];
$url = \yii\helpers\Url::to('/sso', true);
header('Location: ' . $url);

