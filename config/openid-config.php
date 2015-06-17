<?php

// Sample BDD connexion
$c->pg_connect[] = 'dbname=davical port=5432 user=davical_app';
$c->use_persistent = true;

// External authentication source : openid
$c->authenticate_hook['call'] = 'openid';
// Associated configuration data
$c->authenticate_hook['config'] = array(
    // Autorize API from openid server
    'authorization_url' => 'http://fcp.integ01.dev-franceconnect.fr/api/v1/authorize',
    // Token API from openid server
    'token_url' => 'https://fcp.integ01.dev-franceconnect.fr/api/v1/token',
    // UserInfo API from openid server
    'userinfo_url' => 'https://fcp.integ01.dev-franceconnect.fr/api/v1/userinfo',
    // Logout API from openid server
    'logout_url' => 'https://fcp.integ01.dev-franceconnect.fr/api/v1/logout',
    // Client id & secret from openid server
    'client_id' => '239403378b6864968661ce40e13b0b53',
    'client_secret' => '9df1c84e42b4cef083a8780c68fecb34',
    // Callback url used by openid server after authorize
    'callback_url' => 'https://127.0.0.1/oidc_callback'
);
// Maked as optional
//$c->authenticate_hook['optional'] = true;
