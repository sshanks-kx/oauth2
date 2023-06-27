/configuration
\p 1234 
\c 400 4000
.oauth2.redirect_url:"http://localhost:1234/";

// schema
.oauth2.provider:([id:`symbol$()]; scope:(); client_id:(); client_secret:(); auth_endpoint:(); token_endpoint:(); userinfo_endpoint:(); revocation_endpoint:(); discovery_endpoint:(); discovery_doc:());
.oauth2.domains:([domain:`symbol$()]; provider:`symbol$());
.oauth2.state:([state:`symbol$()]; username:`symbol$(); created:`timestamp$(); provider:`symbol$(); access_token:(); refresh_token:(); expires_in:(); ok:`boolean$())

// utility
.oauth2.qs:{[dict]
  dict:$[98h=type dict;first dict;dict];
  :"&" sv ("=" sv .h.hu each) each flip (string key dict;{$[10h=type x;x;string x]} each value dict);
  };

.oauth2.getAccessToken:{[user]
  last exec access_token from .oauth2.state where username=user
  };  


k).oauth2.hmb:{x:$[10=@x;x;1_$x];p:{$[#y;y;x]}/'getenv@+`$_:\("HTTP";"NO"),\:"_PROXY";u:.Q.hap@x;t:~(~#*p)||/(*":"\:u 2)like/:{(("."=*x)#"*"),x}'","\:p 1;a:$[t;p:.Q.hap@*p;u]1; (4+*r ss d)_r:(-1!`$,/($[t;p;u]0 2))($y)," ",$[t;x;u 3]," HTTP/1.1",s,(s/:("Connection: close";"Host: ",u 2;"Authorization: Bearer ",z),((0<#a)#,$[t;"Proxy-";""],"Authorization: Basic ",((-c)_.Q.b6@,/64\:'256/:'"i"$0N 3#a,c#0),(c:.q.mod[-#a;3])#"=")),(d:s,s:"\r\n"),""};
	
// @desc generate URL to the authorization server (passes info to indentify user & details to later redirect back to us
// with a temp authentication code). Using this URL usually causes Google to prompt for login info. 
// @param username to include in request
// @return URL
.oauth2.authURL:{[username]
  domain:`$last "@"vs string username; 
  info:.oauth2.provider provider:.oauth2.domains[domain;`provider]; 
  param:enlist `response_type`client_id`redirect_uri`scope`access_type`prompt!(`code; info`client_id; .oauth2.redirect_url; info`scope; `offline; `consent );
  url:{y,"?",.oauth2.qs update state:x from z}[;info`auth_endpoint;param];
  // create unique value to keep state between calls
  state:`$"\001" sv (raze string 4?`8;string username); 
  insert[`.oauth2.state] `state xkey enlist`state`username`created`provider`access_token`refresh_token`ok!(state;username;.z.p;provider;();();0b);
  url state
  };

// @desc get access and refresh tokens from the token endpoint (that allow access to resources)
// @param state  key to .oauth2.state (unique value we generated prior to auth)
// @param code   one-time authentication code (provided by authorization server)
.oauth2.getTokens:{[state;code]
  state:$[10h=type state;`$state;state];
  code:$[10h=type code;code;string code];
  state_data:`username`provider#.oauth2.state[state];
  
  info:.oauth2.provider state_data`provider;
  postdata:.oauth2.qs enlist`grant_type`redirect_uri`code`client_id`client_secret`scope!(`authorization_code;.oauth2.redirect_url; code; info`client_id; info`client_secret; info`scope);

  // exchange the authentication code for an access & refresh token 
  result0:.j.k .Q.hp[`$":",info[`token_endpoint];"application/x-www-form-urlencoded";postdata];

  // request a resource (the user profile) using the access token
  result:.j.k .oauth2.hmb[`$":",info[`userinfo_endpoint];`GET;result0[`access_token]];
  if[`picture in key result; .debug.picture:result`picture];
  ok:(result`email_verified)&(first state_data[`username])~`$result`email;

  // update state with token info
  orig:.oauth2.state[state];
  new:cols[.oauth2.state]#@[orig;`state`access_token`refresh_token`expires_in`ok`created;:;(state;result0`access_token;result0`refresh_token;result0`expires_in;ok;.z.p)];
  upsert[`.oauth2.state; new];

  ok
  };	

// @desc request new access token (using refresh token) which replaces previous access token
// @param state  key to .oauth2.state (unique value we generated prior to auth)
.oauth2.refresh:{[state]
  u:.oauth2.state[state];
  p:.oauth2.provider u`provider;
  postdata:.oauth2.qs `refresh_token`client_id`client_secret`grant_type!(u`refresh_token; p`client_id; p`client_secret; `refresh_token);
  result0:.j.k .Q.hp[`$":",p`token_endpoint;"application/x-www-form-urlencoded";postdata];
  orig:.oauth2.state[state];
  new:cols[.oauth2.state]#@[orig;`state`access_token`expires_in`created;:;(state;result0`access_token;result0`expires_in;.z.p)];
  upsert[`.oauth2.state; new];
  }

// @desc configure .oauth2.provider with env info.
// retrieves discovery doc using http. set client credentials. set auth/resource servers.
// @param id           provider id to record info against (e.g. `google)
// @param handle       file handle to client credentials (json file)
// @param discoveryurl url used to get discovery doc
// @param scope        the set of resources and operations that you wish the access token to permit. 
//                     possible value configured in the auth server. space seperate list.
.oauth2.configure:{[id;handle;discoveryurl;scope]
  r:.j.k last "\r\n\r\n" vs raze read0 handle;
  d:distinct {("/" vs x) 2} each r[`web;`auth_uri`token_uri];
  w:.j.k @[.Q.hg;hsym `$discoveryurl;{""}];
  insert[`.oauth2.provider]`id xkey enlist`id`scope`client_id`client_secret`auth_endpoint`token_endpoint`userinfo_endpoint`revocation_endpoint`discovery_endpoint`discovery_doc!(id;scope; r[`web;`client_id];r[`web;`client_secret];w[`authorization_endpoint];w[`token_endpoint];w[`userinfo_endpoint];w[`revocation_endpoint];discoveryurl;w);
  id
  };

// @desc replace default 'http get' to either:
// * prompt for email address
// * use provided email to contact authorization server for authorization code (will redirect for authentication &
//   redirect back here with authorization code)
// * process authorization callback with provided authorization code. use to gain access/refresh tokens, which
//   can be used to get protected resource
.z.ph:{
  // browser requesting website icon, ignore & return
  if["favicon.ico"~first x;:.h.hy[`html]"";];
  
  // no data passed, prompt for email & display the Submit button
  if[""~first x;:.h.hy[`html]"<form>email <input type=\"email\" name=\"e\" autofocus><input type=submit value=Submit></form>"];
  d:.h.uh each (!) . "S=&" 0: 1_first x;
  
  // email present, request authorization code (i.e. redirect client to url for authentication from Google, passing our client details)
  if[`e in key d;:"HTTP/1.0 302 ok\r\nLocation: ",.oauth2.authURL[`$d`e],"\r\nConnection: close\r\n\r\n"];
  
  // must be callback response from Google with one-time authorization code (after authentication)
  .oauth2.getTokens[`$d`state;d`code];
  
  // return users image to the screen
  .h.hy[`html]"Users profile picture (retrieved using access token)<br><br><img src=\"", .debug.picture,"\">"
  }

/ setup .oauth2.provider info
.oauth2.configure[`google;`:google_client.json;"https://accounts.google.com/.well-known/openid-configuration";"openid email profile"];
/ setup .oauth2.domains (which email uses which auth provider)
insert[`.oauth2.domains] ([domain:1#`gmail.com]; provider:1#`google);
show .oauth2.provider`google;
/ ... wait for http requests on .z.ph ...

