<?php

// Sample BDD connexion
$c->pg_connect[] = 'dbname=davical port=5432 user=davical_app';

// Autorize API from openid server
$c->authorization_url='http://fcp.integ01.dev-franceconnect.fr/api/v1/authorize';

// Token API from openid server
$c->token_url='https://fcp.integ01.dev-franceconnect.fr/api/v1/token';

// UserInfo API from openid server
$c->userinfo_url='https://fcp.integ01.dev-franceconnect.fr/api/v1/userinfo';

// Logout API from openid server
$c->logout_url='https://fcp.integ01.dev-franceconnect.fr/api/v1/logout';

// Client id & secret from openid server
$c->client_id='239403378b6864968661ce40e13b0b53';
$c->client_secret='9df1c84e42b4cef083a8780c68fecb34';

// Callback url used by openid server after authorize
$c->callback_url='https://127.0.0.1/oidc_callback';
