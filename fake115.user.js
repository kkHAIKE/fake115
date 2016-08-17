// ==UserScript==
// @name         fake 115Browser
// @namespace    http://github.com/kkHAIKE/fake115
// @version      1.1
// @description  非115浏览器登录115.com
// @author       kkhaike
// @match        http://115.com/*
// @grant        GM_xmlhttpRequest
// @grant        unsafeWindow
// @connect      passport.115.com
// @require      http://cdn.bootcss.com/crc-32/0.4.1/crc32.min.js
// @require      http://cdn.bootcss.com/blueimp-md5/2.3.0/js/md5.min.js
// @require      https://rawgit.com/ricmoo/aes-js/master/index.js
// @require      http://www-cs-students.stanford.edu/~tjw/jsbn/jsbn.js
// @require      http://www-cs-students.stanford.edu/~tjw/jsbn/jsbn2.js
// @require      http://www-cs-students.stanford.edu/~tjw/jsbn/prng4.js
// @require      http://www-cs-students.stanford.edu/~tjw/jsbn/rng.js
// @require      http://www-cs-students.stanford.edu/~tjw/jsbn/ec.js
// @require      http://www-cs-students.stanford.edu/~tjw/jsbn/sec.js
// @require      https://rawgit.com/kkHAIKE/node-lz4/balabala/build/lz4.js
// @run-at       document-end
// ==/UserScript==
(function() {
    'use strict';
var Buffer, LZ4, LoginEncrypt_, browserInterface, bytesToString, dictToForm, dictToQuery, ec115_compress_decode, ec115_decode_aes, ec115_encode_data, ec115_encode_token, g_Q, g_c, g_rng, hexToBytes, intToBytes, pick_rand, stringToBytes, _ref;

g_rng = new SecureRandom();

g_c = secp224r1();

g_Q = g_c.getCurve().decodePointHex('0457A29257CD2320E5D6D143322FA4BB8A3CF9D3CC623EF5EDAC62B7678A89C91A83BA800D6129F522D034C895DD2465243ADDC250953BEEBA');

Buffer = require('buffer').Buffer;

LZ4 = require('lz4');

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

hexToBytes = function(h) {
  var i, ret, _i, _ref;
  ret = [];
  for (i = _i = 0, _ref = h.length; _i < _ref; i = _i += 2) {
    ret.push(parseInt(h.slice(i, i + 2), 16));
  }
  return ret;
};

intToBytes = function(x) {
  var i, ret, _i;
  ret = [];
  for (i = _i = 0; _i < 4; i = ++_i) {
    ret.push(x & 0xff);
    x >>= 8;
  }
  return ret;
};

pick_rand = function(n) {
  var n1, r;
  n1 = n.subtract(BigInteger.ONE);
  r = new BigInteger(n.bitLength(), g_rng);
  return r.mod(n1).add(BigInteger.ONE);
};

ec115_encode_token = function(tm) {
  var G, K, P, c, d, i, pub, r2, tmp, tmp2, y, _i, _j, _k, _l;
  d = pick_rand(g_c.getN());
  G = g_c.getG();
  P = G.multiply(d);
  c = g_c.getCurve();
  pub = c.encodePointHex(P);
  y = P.getY().toBigInteger();
  pub = hexToBytes("1d" + (y.testBit(0) ? "03" : "02") + pub.slice(2, 58));
  r2 = new Array(2);
  g_rng.nextBytes(r2);
  tmp = [];
  for (i = _i = 0; _i < 15; i = ++_i) {
    tmp.push(pub[i] ^ r2[0]);
  }
  tmp.push(r2[0]);
  tmp = tmp.concat(intToBytes(115));
  tmp = tmp.concat(intToBytes(tm));
  for (i = _j = 16; _j < 24; i = ++_j) {
    tmp[i] ^= r2[0];
  }
  for (i = _k = 15; _k < 30; i = ++_k) {
    tmp.push(pub[i] ^ r2[1]);
  }
  tmp.push(r2[1]);
  tmp = tmp.concat(intToBytes(0));
  for (i = _l = 40; _l < 44; i = ++_l) {
    tmp[i] ^= r2[1];
  }
  tmp2 = stringToBytes('^j>WD3Kr?J2gLFjD4W2y@').concat(tmp);
  tmp = tmp.concat(intToBytes(CRC32.buf(tmp2) >>> 0));
  K = g_Q.multiply(d);
  return {
    key: hexToBytes(K.getX().toBigInteger().toString(16)),
    token: window.btoa(bytesToString(tmp))
  };
};

ec115_encode_data = function(data, key) {
  var aesEcb, i, j, k, key1, key2, n, part, ret, tmp, _i;
  key1 = key.slice(0, 16);
  key2 = key.slice(-16);
  aesEcb = new aesjs.ModeOfOperation.ecb(key1);
  tmp = stringToBytes(data);
  n = tmp.length;
  j = 0;
  ret = [];
  while (n > 0) {
    part = [];
    for (i = _i = 0; _i < 16; i = ++_i) {
      k = n <= 0 ? 0 : tmp[i + j];
      part.push(key2[i] ^ k);
      --n;
    }
    key2 = aesEcb.encrypt(part);
    ret = ret.concat(key2);
    j += 16;
  }
  return bytesToString(ret);
};

ec115_decode_aes = function(data, key) {
  var aesCbc, iv, key1, ret;
  key1 = key.slice(0, 16);
  iv = key.slice(-16);
  aesCbc = new aesjs.ModeOfOperation.cbc(key1, iv);
  ret = aesCbc.decrypt(data);
  while (ret.length > 0 && ret[ret.length - 1] === 0) {
    ret.pop();
  }
  return ret;
};

ec115_compress_decode = function(data) {
  var len, p, r, ret, tmp;
  data = new Buffer(data);
  p = 0;
  ret = [];
  while (p < data.length) {
    len = data.readInt16LE(p) + 2;
    if (p + len > data.length) {
      return null;
    }
    tmp = new Buffer(0x2000);
    r = LZ4.decodeBlock(data.slice(p + 2, p + len), tmp);
    if (r < 0) {
      return null;
    }
    ret = ret.concat(Array.from(tmp.slice(0, r)));
    p += len;
  }
  return ret;
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

dictToForm = function(dict) {
  var k, tmp, v;
  tmp = [];
  for (k in dict) {
    v = dict[k];
    tmp.push("" + k + "=" + v);
  }
  return tmp.join('&');
};

LoginEncrypt_ = function(_arg, g) {
  var account, data, environment, fake, goto, key, login_type, passwd, tm, tmus, token, _ref;
  account = _arg.account, passwd = _arg.passwd, environment = _arg.environment, goto = _arg.goto, login_type = _arg.login_type;
  tmus = (new Date()).getTime();
  tm = Math.floor(tmus / 1000);
  fake = md5(account);
  _ref = ec115_encode_token(tm), key = _ref.key, token = _ref.token;
  data = ec115_encode_data(dictToForm({
    GUID: fake.slice(0, 20),
    account: account,
    device: 'jujumao',
    device_id: fake.slice(0, 12).toUpperCase(),
    device_type: 'windows',
    disk_serial: fake.slice(0, 8).toUpperCase(),
    dk: '',
    environment: environment,
    goto: goto,
    login_source: '115chrome',
    network: '5',
    passwd: passwd,
    sign: md5("" + account + tm),
    system_info: ("            " + fake[1] + fake[0] + fake[3] + fake[2] + fake[5] + fake[4] + fake[7] + fake[6]).toUpperCase(),
    time: tm,
    login_type: login_type
  }), key);
  return GM_xmlhttpRequest({
    method: 'POST',
    url: "http://passport.115.com/?ct=encrypt&ac=login&k_ec=" + token,
    data: data,
    binary: true,
    responseType: 'arraybuffer',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
    },
    anonymous: true,
    onload: function(response) {
      var date, datestr, dec, json, unzip;
      if (response.status === 200) {
        data = new Uint8Array(response.response);
        dec = data[data.length - 12 + 5];
        unzip = data[data.length - 12 + 4];
        data = data.slice(0, -12);
        if (dec === 1) {
          data = ec115_decode_aes(data, key);
        }
        if (unzip === 1) {
          data = ec115_compress_decode(data);
        }
        if (data !== null) {
          json = JSON.parse(bytesToString(data));
          if (json.state) {
            date = new Date();
            date.setTime(date.getTime() + 7 * 24 * 3600 * 1000);
            datestr = date.toGMTString();
            document.cookie = "UID=" + json.data.cookie.UID + "; expires=" + datestr + "; path=/; domain=115.com";
            document.cookie = "CID=" + json.data.cookie.CID + "; expires=" + datestr + "; path=/; domain=115.com";
            document.cookie = "SEID=" + json.data.cookie.SEID + "; expires=" + datestr + "; path=/; domain=115.com";
            document.cookie = "OOFL=" + json.data.user_id + "; expires=" + datestr + "; path=/; domain=115.com";
            json.is_two = true;
            delete json.data;
          }
          return unsafeWindow[g](JSON.stringify(json));
        }
      }
    }
  });
};

browserInterface = (_ref = unsafeWindow.browserInterface) != null ? _ref : {};

browserInterface.LoginEncrypt = function(n, g) {
  return LoginEncrypt_(JSON.parse(n), g);
};

unsafeWindow.browserInterface = cloneInto(browserInterface, unsafeWindow, {
  cloneFunctions: true
});

})();
