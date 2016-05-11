// ==UserScript==
// @name         fake 115Browser
// @namespace    http://github.com/kkHAIKE/fake115
// @version      1.0
// @description  非115浏览器登录115.com
// @author       kkhaike
// @match        http://115.com/*
// @grant        GM_xmlhttpRequest
// @grant        unsafeWindow
// @connect      passport.115.com
// @require      https://rawgit.com/kkHAIKE/jsencrypt/balabala/bin/jsencrypt.js
// @require      http://cdn.bootcss.com/blueimp-md5/2.3.0/js/md5.min.js
// @run-at       document-end
// ==/UserScript==
(function() {
    'use strict';
var LoginEncrypt_, browserInterface, browser_115_m115_decode, browser_115_m115_encode, bytesToString, dictToQuery, g_kts, m115_asym_decode, m115_asym_encode, m115_getkey, m115_sym_decode, m115_sym_encode, prsa, srsa, stringToBytes, xor115_enc, _ref;

g_kts = [0xF0, 0xE5, 0x69, 0xAE, 0xBF, 0xDC, 0xBF, 0x5A, 0x1A, 0x45, 0xE8, 0xBE, 0x7D, 0xA6, 0x73, 0x88, 0xDE, 0x8F, 0xE7, 0xC4, 0x45, 0xDA, 0x86, 0x94, 0x9B, 0x69, 0x92, 0x0B, 0x6A, 0xB8, 0xF1, 0x7A, 0x38, 0x06, 0x3C, 0x95, 0x26, 0x6D, 0x2C, 0x56, 0x00, 0x70, 0x56, 0x9C, 0x36, 0x38, 0x62, 0x76, 0x2F, 0x9B, 0x5F, 0x0F, 0xF2, 0xFE, 0xFD, 0x2D, 0x70, 0x9C, 0x86, 0x44, 0x8F, 0x3D, 0x14, 0x27, 0x71, 0x93, 0x8A, 0xE4, 0x0E, 0xC1, 0x48, 0xAE, 0xDC, 0x34, 0x7F, 0xCF, 0xFE, 0xB2, 0x7F, 0xF6, 0x55, 0x9A, 0x46, 0xC8, 0xEB, 0x37, 0x77, 0xA4, 0xE0, 0x6B, 0x72, 0x93, 0x7E, 0x51, 0xCB, 0xF1, 0x37, 0xEF, 0xAD, 0x2A, 0xDE, 0xEE, 0xF9, 0xC9, 0x39, 0x6B, 0x32, 0xA1, 0xBA, 0x35, 0xB1, 0xB8, 0xBE, 0xDA, 0x78, 0x73, 0xF8, 0x20, 0xD5, 0x27, 0x04, 0x5A, 0x6F, 0xFD, 0x5E, 0x72, 0x39, 0xCF, 0x3B, 0x9C, 0x2B, 0x57, 0x5C, 0xF9, 0x7C, 0x4B, 0x7B, 0xD2, 0x12, 0x66, 0xCC, 0x77, 0x09, 0xA6, 0x55, 0x6F, 0xCD, 0x5E, 0x42, 0xDA, 0x13, 0xBA, 0x78, 0x76, 0x8D, 0x37, 0xE8, 0xEE, 0x04, 0x91];

m115_getkey = function(length, key) {
  var i, ret, _i;
  if (key != null) {
    ret = [];
    for (i = _i = 0; 0 <= length ? _i < length : _i > length; i = 0 <= length ? ++_i : --_i) {
      ret.push(((key[i] + g_kts[length * i]) & 0xff) ^ g_kts[length * (length - 1 - i)]);
    }
    return ret;
  }
  return g_kts.slice(-length);
};

xor115_enc = function(src, srclen, key, keylen) {
  var i, mod4, ret, _i, _j;
  mod4 = srclen % 4;
  ret = [];
  if (mod4 !== 0) {
    for (i = _i = 0; 0 <= mod4 ? _i < mod4 : _i > mod4; i = 0 <= mod4 ? ++_i : --_i) {
      ret.push(src[i] ^ key[i % keylen]);
    }
  }
  for (i = _j = mod4; mod4 <= srclen ? _j < srclen : _j > srclen; i = mod4 <= srclen ? ++_j : --_j) {
    ret.push(src[i] ^ key[(i - mod4) % keylen]);
  }
  return ret;
};

m115_sym_encode = function(src, srclen, key1, key2) {
  var k1, k2, ret;
  k1 = m115_getkey(4, key1);
  k2 = m115_getkey(12, key2);
  ret = xor115_enc(src, srclen, k1, 4);
  ret.reverse();
  ret = xor115_enc(ret, srclen, k2, 12);
  return ret;
};

m115_sym_decode = function(src, srclen, key1, key2) {
  var k1, k2, ret;
  k1 = m115_getkey(4, key1);
  k2 = m115_getkey(12, key2);
  ret = xor115_enc(src, srclen, k2, 12);
  ret.reverse();
  ret = xor115_enc(ret, srclen, k1, 4);
  return ret;
};

stringToBytes = function(s) {
  var i, ret, _i, _ref;
  ret = [];
  for (i = _i = 0, _ref = s.length; 0 <= _ref ? _i < _ref : _i > _ref; i = 0 <= _ref ? ++_i : --_i) {
    ret.push(s.charCodeAt(i));
  }
  return ret;
};

bytesToString = function(b) {
  var i, ret, _i, _len;
  ret = '';
  for (_i = 0, _len = b.length; _i < _len; _i++) {
    i = b[_i];
    ret += String.fromCharCode(i);
  }
  return ret;
};

prsa = new JSEncrypt();

prsa.setPublicKey("-----BEGIN RSA PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDR3rWmeYnRClwLBB0Rq0dlm8Mr\nPmWpL5I23SzCFAoNpJX6Dn74dfb6y02YH15eO6XmeBHdc7ekEFJUIi+swganTokR\nIVRRr/z16/3oh7ya22dcAqg191y+d6YDr4IGg/Q5587UKJMj35yQVXaeFXmLlFPo\nkFiz4uPxhrB7BGqZbQIDAQAB\n-----END RSA PUBLIC KEY-----");

srsa = new JSEncrypt();

srsa.setPrivateKey("-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQCMgUJLwWb0kYdW6feyLvqgNHmwgeYYlocst8UckQ1+waTOKHFC\nTVyRSb1eCKJZWaGa08mB5lEu/asruNo/HjFcKUvRF6n7nYzo5jO0li4IfGKdxso6\nFJIUtAke8rA2PLOubH7nAjd/BV7TzZP2w0IlanZVS76n8gNDe75l8tonQQIDAQAB\nAoGANwTasA2Awl5GT/t4WhbZX2iNClgjgRdYwWMI1aHbVfqADZZ6m0rt55qng63/\n3NsjVByAuNQ2kB8XKxzMoZCyJNvnd78YuW3Zowqs6HgDUHk6T5CmRad0fvaVYi6t\nviOkxtiPIuh4QrQ7NUhsLRtbH6d9s1KLCRDKhO23pGr9vtECQQDpjKYssF+kq9iy\nA9WvXRjbY9+ca27YfarD9WVzWS2rFg8MsCbvCo9ebXcmju44QhCghQFIVXuebQ7Q\npydvqF0lAkEAmgLnib1XonYOxjVJM2jqy5zEGe6vzg8aSwKCYec14iiJKmEYcP4z\nDSRms43hnQsp8M2ynjnsYCjyiegg+AZ87QJANuwwmAnSNDOFfjeQpPDLy6wtBeft\n5VOIORUYiovKRZWmbGFwhn6BQL+VaafrNaezqUweBRi1PYiAF2l3yLZbUQJAf/nN\n4Hz/pzYmzLlWnGugP5WCtnHKkJWoKZBqO2RfOBCq+hY4sxvn3BHVbXqGcXLnZPvo\nYuaK7tTXxZSoYLEzeQJBAL8Mt3AkF1Gci5HOug6jT4s4Z+qDDrUXo9BlTwSWP90v\nwlHF+mkTJpKd5Wacef0vV+xumqNorvLpIXWKwxNaoHM=\n-----END RSA PRIVATE KEY-----");

m115_asym_encode = function(src, srclen) {
  var i, m, ret, _i, _ref;
  m = 128 - 11;
  ret = '';
  for (i = _i = 0, _ref = Math.floor((srclen + m - 1) / m); 0 <= _ref ? _i < _ref : _i > _ref; i = 0 <= _ref ? ++_i : --_i) {
    ret += window.atob(prsa.encrypt(bytesToString(src.slice(i * m, Math.min((i + 1) * m, srclen)))));
  }
  return window.btoa(ret);
};

m115_asym_decode = function(src, srclen) {
  var i, m, ret, _i, _ref;
  m = 128;
  ret = '';
  for (i = _i = 0, _ref = Math.floor((srclen + m - 1) / m); 0 <= _ref ? _i < _ref : _i > _ref; i = 0 <= _ref ? ++_i : --_i) {
    ret += srsa.decrypt(window.btoa(bytesToString(src.slice(i * m, Math.min((i + 1) * m, srclen)))));
  }
  return stringToBytes(ret);
};

browser_115_m115_decode = function(src, key) {
  var tmp;
  tmp = stringToBytes(window.atob(src));
  tmp = m115_asym_decode(tmp, tmp.length);
  return bytesToString(m115_sym_decode(tmp.slice(16), tmp.length - 16, key, tmp.slice(0, 16)));
};

browser_115_m115_encode = function(src, tm) {
  var key, tmp;
  key = stringToBytes(md5("!@###@#" + tm + "DFDR@#@#"));
  tmp = stringToBytes(src);
  tmp = m115_sym_encode(tmp, tmp.length, key, null);
  tmp = key.slice(0, 16).concat(tmp);
  return {
    data: m115_asym_encode(tmp, tmp.length),
    key: key
  };
};

dictToQuery = function(dict) {
  var k, tmp, v;
  tmp = [];
  for (k in dict) {
    v = dict[k];
    tmp.push("" + (encodeURIComponent(k)) + "=" + (encodeURIComponent(v)));
  }
  return tmp.join('&');
};

LoginEncrypt_ = function(_arg, g) {
  var account, data, environment, goto, key, nonce, passwd, tm, tmus, token, _ref;
  account = _arg.account, passwd = _arg.passwd, environment = _arg.environment, goto = _arg.goto;
  tmus = (new Date()).getTime();
  tm = Math.floor(tmus / 1000);
  nonce = md5("" + tmus);
  token = md5("115" + nonce + account + tm + "115");
  _ref = browser_115_m115_encode(JSON.stringify({
    GUID: md5(account).slice(0, 20),
    account: account,
    device: 'jujumao',
    device_id: '',
    device_type: 'windows',
    disk_serial: '',
    dk: '',
    environment: environment,
    goto: goto,
    login_source: '115chrome',
    network: '5',
    passwd: passwd,
    sign: md5("" + account + tm),
    system_info: '',
    time: tm
  }), tmus), data = _ref.data, key = _ref.key;
  return GM_xmlhttpRequest({
    method: 'POST',
    url: "http://passport.115.com/?ct=auth&ac=login&" + (dictToQuery({
      token: token,
      nonce: nonce,
      account: account,
      time: tm
    })) + "&is_ssl=1",
    data: "data=" + data + "&goto=",
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
    },
    onload: function(response) {
      var date, datestr, json, json_data;
      json = JSON.parse(response.responseText);
      if (json.state) {
        json.is_two = true;
        json_data = JSON.parse(browser_115_m115_decode(json.data, key));
        delete json.data;
        date = new Date();
        date.setTime(date.getTime() + 7 * 24 * 3600 * 1000);
        datestr = date.toGMTString();
        document.cookie = "UID=" + json_data.cookie.UID + "; expires=" + datestr + "; path=/; domain=115.com";
        document.cookie = "CID=" + json_data.cookie.CID + "; expires=" + datestr + "; path=/; domain=115.com";
        document.cookie = "SEID=" + json_data.cookie.SEID + "; expires=" + datestr + "; path=/; domain=115.com";
        document.cookie = "OOFL=" + json_data.user_id + "; expires=" + datestr + "; path=/; domain=115.com";
      }
      return unsafeWindow.window[g](JSON.stringify(json));
    }
  });
};

browserInterface = (_ref = unsafeWindow.window.browserInterface) != null ? _ref : {};

unsafeWindow.window.browserInterface = browserInterface;

browserInterface.LoginEncrypt = function(n, g) {
  return LoginEncrypt_(JSON.parse(n), g);
};

})();
