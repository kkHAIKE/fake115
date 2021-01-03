// ==UserScript==
// @name         fake 115Browser download
// @namespace    http://github.com/kkHAIKE/fake115
// @version      1.0.2
// @description  伪装115浏览器下载
// @author       kkhaike
// @match        *://115.com/*
// @match        *://v.anxia.com/*
// @grant        GM_xmlhttpRequest
// @grant        unsafeWindow
// @grant        GM_log
// @grant        GM_setClipboard
// @connect      proapi.115.com
// @require      https://rawgit.com/kkHAIKE/jsencrypt/balabala/bin/jsencrypt.js
// @require      https://cdn.bootcdn.net/ajax/libs/blueimp-md5/2.18.0/js/md5.min.js
// @run-at       document-start
// ==/UserScript==
(function() {
    'use strict';
var CreateDownloadTask, CreateDownloadTask_, browserInterface, bytesToString, cloneInto, g_key_l, g_key_s, g_kts, m115_asym_decode, m115_asym_encode, m115_decode, m115_encode, m115_getkey, m115_sym_decode, m115_sym_encode, prsa, ref, srsa, stringToBytes, xor115_enc;

g_kts = [0xF0, 0xE5, 0x69, 0xAE, 0xBF, 0xDC, 0xBF, 0x5A, 0x1A, 0x45, 0xE8, 0xBE, 0x7D, 0xA6, 0x73, 0x88, 0xDE, 0x8F, 0xE7, 0xC4, 0x45, 0xDA, 0x86, 0x94, 0x9B, 0x69, 0x92, 0x0B, 0x6A, 0xB8, 0xF1, 0x7A, 0x38, 0x06, 0x3C, 0x95, 0x26, 0x6D, 0x2C, 0x56, 0x00, 0x70, 0x56, 0x9C, 0x36, 0x38, 0x62, 0x76, 0x2F, 0x9B, 0x5F, 0x0F, 0xF2, 0xFE, 0xFD, 0x2D, 0x70, 0x9C, 0x86, 0x44, 0x8F, 0x3D, 0x14, 0x27, 0x71, 0x93, 0x8A, 0xE4, 0x0E, 0xC1, 0x48, 0xAE, 0xDC, 0x34, 0x7F, 0xCF, 0xFE, 0xB2, 0x7F, 0xF6, 0x55, 0x9A, 0x46, 0xC8, 0xEB, 0x37, 0x77, 0xA4, 0xE0, 0x6B, 0x72, 0x93, 0x7E, 0x51, 0xCB, 0xF1, 0x37, 0xEF, 0xAD, 0x2A, 0xDE, 0xEE, 0xF9, 0xC9, 0x39, 0x6B, 0x32, 0xA1, 0xBA, 0x35, 0xB1, 0xB8, 0xBE, 0xDA, 0x78, 0x73, 0xF8, 0x20, 0xD5, 0x27, 0x04, 0x5A, 0x6F, 0xFD, 0x5E, 0x72, 0x39, 0xCF, 0x3B, 0x9C, 0x2B, 0x57, 0x5C, 0xF9, 0x7C, 0x4B, 0x7B, 0xD2, 0x12, 0x66, 0xCC, 0x77, 0x09, 0xA6];

g_key_s = [0x29, 0x23, 0x21, 0x5E];

g_key_l = [0x42, 0xDA, 0x13, 0xBA, 0x78, 0x76, 0x8D, 0x37, 0xE8, 0xEE, 0x04, 0x91];

m115_getkey = function(length, key) {
  var i;
  if (key != null) {
    return (function() {
      var j, ref, results;
      results = [];
      for (i = j = 0, ref = length; (0 <= ref ? j < ref : j > ref); i = 0 <= ref ? ++j : --j) {
        results.push(((key[i] + g_kts[length * i]) & 0xff) ^ g_kts[length * (length - 1 - i)]);
      }
      return results;
    })();
  }
  if (length === 12) {
    return g_key_l.slice(0);
  }
  return g_key_s.slice(0);
};

xor115_enc = function(src, srclen, key, keylen) {
  var i, j, k, mod4, ref, ref1, ref2, ret;
  mod4 = srclen % 4;
  ret = [];
  if (mod4 !== 0) {
    for (i = j = 0, ref = mod4; (0 <= ref ? j < ref : j > ref); i = 0 <= ref ? ++j : --j) {
      ret.push(src[i] ^ key[i % keylen]);
    }
  }
  for (i = k = ref1 = mod4, ref2 = srclen; (ref1 <= ref2 ? k < ref2 : k > ref2); i = ref1 <= ref2 ? ++k : --k) {
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
  var i, j, ref, ret;
  ret = [];
  for (i = j = 0, ref = s.length; (0 <= ref ? j < ref : j > ref); i = 0 <= ref ? ++j : --j) {
    ret.push(s.charCodeAt(i));
  }
  return ret;
};

bytesToString = function(b) {
  var i, j, len, ret;
  ret = '';
  for (j = 0, len = b.length; j < len; j++) {
    i = b[j];
    ret += String.fromCharCode(i);
  }
  return ret;
};

prsa = new JSEncrypt();

prsa.setPublicKey(`-----BEGIN RSA PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDR3rWmeYnRClwLBB0Rq0dlm8Mr
PmWpL5I23SzCFAoNpJX6Dn74dfb6y02YH15eO6XmeBHdc7ekEFJUIi+swganTokR
IVRRr/z16/3oh7ya22dcAqg191y+d6YDr4IGg/Q5587UKJMj35yQVXaeFXmLlFPo
kFiz4uPxhrB7BGqZbQIDAQAB
-----END RSA PUBLIC KEY-----`);

srsa = new JSEncrypt();

srsa.setPrivateKey(`-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCMgUJLwWb0kYdW6feyLvqgNHmwgeYYlocst8UckQ1+waTOKHFC
TVyRSb1eCKJZWaGa08mB5lEu/asruNo/HjFcKUvRF6n7nYzo5jO0li4IfGKdxso6
FJIUtAke8rA2PLOubH7nAjd/BV7TzZP2w0IlanZVS76n8gNDe75l8tonQQIDAQAB
AoGANwTasA2Awl5GT/t4WhbZX2iNClgjgRdYwWMI1aHbVfqADZZ6m0rt55qng63/
3NsjVByAuNQ2kB8XKxzMoZCyJNvnd78YuW3Zowqs6HgDUHk6T5CmRad0fvaVYi6t
viOkxtiPIuh4QrQ7NUhsLRtbH6d9s1KLCRDKhO23pGr9vtECQQDpjKYssF+kq9iy
A9WvXRjbY9+ca27YfarD9WVzWS2rFg8MsCbvCo9ebXcmju44QhCghQFIVXuebQ7Q
pydvqF0lAkEAmgLnib1XonYOxjVJM2jqy5zEGe6vzg8aSwKCYec14iiJKmEYcP4z
DSRms43hnQsp8M2ynjnsYCjyiegg+AZ87QJANuwwmAnSNDOFfjeQpPDLy6wtBeft
5VOIORUYiovKRZWmbGFwhn6BQL+VaafrNaezqUweBRi1PYiAF2l3yLZbUQJAf/nN
4Hz/pzYmzLlWnGugP5WCtnHKkJWoKZBqO2RfOBCq+hY4sxvn3BHVbXqGcXLnZPvo
YuaK7tTXxZSoYLEzeQJBAL8Mt3AkF1Gci5HOug6jT4s4Z+qDDrUXo9BlTwSWP90v
wlHF+mkTJpKd5Wacef0vV+xumqNorvLpIXWKwxNaoHM=
-----END RSA PRIVATE KEY-----`);

m115_asym_encode = function(src, srclen) {
  var i, j, m, ref, ret;
  m = 128 - 11;
  ret = '';
  for (i = j = 0, ref = Math.floor((srclen + m - 1) / m); (0 <= ref ? j < ref : j > ref); i = 0 <= ref ? ++j : --j) {
    ret += window.atob(prsa.encrypt(bytesToString(src.slice(i * m, Math.min((i + 1) * m, srclen)))));
  }
  return window.btoa(ret);
};

m115_asym_decode = function(src, srclen) {
  var i, j, m, ref, ret;
  m = 128;
  ret = '';
  for (i = j = 0, ref = Math.floor((srclen + m - 1) / m); (0 <= ref ? j < ref : j > ref); i = 0 <= ref ? ++j : --j) {
    ret += srsa.decrypt(window.btoa(bytesToString(src.slice(i * m, Math.min((i + 1) * m, srclen)))));
  }
  return stringToBytes(ret);
};

m115_encode = function(src, tm) {
  var key, tmp;
  key = stringToBytes(md5(`!@###@#${tm}DFDR@#@#`));
  tmp = stringToBytes(src);
  tmp = m115_sym_encode(tmp, tmp.length, key, null);
  tmp = key.slice(0, 16).concat(tmp);
  return {
    data: m115_asym_encode(tmp, tmp.length),
    key
  };
};

m115_decode = function(src, key) {
  var tmp;
  tmp = stringToBytes(window.atob(src));
  tmp = m115_asym_decode(tmp, tmp.length);
  return bytesToString(m115_sym_decode(tmp.slice(16), tmp.length - 16, key, tmp.slice(0, 16)));
};

CreateDownloadTask_ = function(f, cb) {
  var data, key, tm, tmus;
  tmus = (new Date()).getTime();
  tm = Math.floor(tmus / 1000);
  ({data, key} = m115_encode(JSON.stringify({
    pickcode: f.pc
  }), tm));
  return GM_xmlhttpRequest({
    method: 'POST',
    url: `http://proapi.115.com/app/chrome/downurl?t=${tm}`,
    data: `data=${encodeURIComponent(data)}`,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    onload: function(response) {
      var json;
      json = JSON.parse(response.responseText);
      if (!json.state) {
        return alert(json.msg);
      } else {
        return cb(JSON.parse(m115_decode(json.data, key)));
      }
    }
  });
};

CreateDownloadTask = function(o) {
  var cb, f, j, len, n, ref, results, rs;
  rs = [];
  n = 0;
  cb = function(r) {
    var btn, con, f, j, len, win, x;
    for (x in r) {
      rs.push(r[x]);
      break;
    }
    if (rs.length === n) {
      GM_log(rs);
      con = $('<ul/>');
      if (n > 1) {
        btn = $('<button>复制所有链接</button>');
        con.append('<li/>');
        con.children(':first').append(btn);
        btn.click(function() {
          var all, f, j, len;
          all = '';
          for (j = 0, len = rs.length; j < len; j++) {
            f = rs[j];
            all += `${f.url.url}\n`;
          }
          return GM_setClipboard(all);
        });
      }
      for (j = 0, len = rs.length; j < len; j++) {
        f = rs[j];
        con.append(`<li><a href='${f.url.url}'>${f.file_name}</a></li>`);
      }
      win = new Core.DialogBase({
        title: '文件下载',
        content: con,
        width: 530
      });
      return win.Open(null);
    }
  };
  ref = o.list;
  results = [];
  for (j = 0, len = ref.length; j < len; j++) {
    f = ref[j];
    if (!f.is_dir) {
      n++;
      results.push(CreateDownloadTask_(f, cb));
    } else {
      results.push(void 0);
    }
  }
  return results;
};

browserInterface = (ref = unsafeWindow.browserInterface) != null ? ref : {};

browserInterface.CreateDownloadTask = function(s) {
  var error;
  try {
    return CreateDownloadTask(JSON.parse(decodeURIComponent(s)));
  } catch (error1) {
    error = error1;
    return GM_log(`${error.message}\n${error.stack}`);
  }
};

browserInterface.GetBrowserVersion = function() {
  return "100.0.0"; // 目前（20210102）需要大于23.9.3
};

if (typeof cloneInto !== 'function') {
  cloneInto = function(x) {
    return x;
  };
}

unsafeWindow.browserInterface = cloneInto(browserInterface, unsafeWindow, {
  cloneFunctions: true
});

})();
