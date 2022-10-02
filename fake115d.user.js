// ==UserScript==
// @name         fake 115Browser download
// @namespace    http://github.com/kkHAIKE/fake115
// @version      1.0.3
// @description  伪装115浏览器下载
// @author       kkhaike
// @match        *://115.com/*
// @match        *://v.anxia.com/*
// @grant        GM_xmlhttpRequest
// @grant        unsafeWindow
// @grant        GM_log
// @grant        GM_setClipboard
// @connect      proapi.115.com
// @require      https://peterolson.github.io/BigInteger.js/BigInteger.min.js
// @require      https://cdn.bootcdn.net/ajax/libs/blueimp-md5/2.18.0/js/md5.min.js
// @run-at       document-start
// ==/UserScript==
(function() {
    'use strict';
var CreateDownloadTask, CreateDownloadTask_, browserInterface, bytesToString, cloneInto, g_key_l, g_key_s, g_kts, m115_asym_decode, m115_asym_encode, m115_decode, m115_encode, m115_getkey, m115_sym_decode, m115_sym_encode, ref, srsa, stringToBytes, xor115_enc;

class MyRsa {
  constructor () {
    // this.n = BigInt('0x8686980c0f5a24c4b9d43020cd2c22703ff3f450756529058b1cf88f09b8602136477198a6e2683149659bd122c33592fdb5ad47944ad1ea4d36c6b172aad6338c3bb6ac6227502d010993ac967d1aef00f0c8e038de2e4d3bc2ec368af2e9f10a6f1eda4f7262f136420c07c331b871bf139f74f3010e3c4fe57df3afb71683')
    // this.e = BigInt('0x10001')
    this.n = bigInt('8686980c0f5a24c4b9d43020cd2c22703ff3f450756529058b1cf88f09b8602136477198a6e2683149659bd122c33592fdb5ad47944ad1ea4d36c6b172aad6338c3bb6ac6227502d010993ac967d1aef00f0c8e038de2e4d3bc2ec368af2e9f10a6f1eda4f7262f136420c07c331b871bf139f74f3010e3c4fe57df3afb71683', 16)
    this.e = bigInt('10001', 16)
  };

  a2hex (byteArray) {
    var hexString = ''
    var nextHexByte
    for (var i = 0; i < byteArray.length; i++) {
      nextHexByte = byteArray[i].toString(16)
      if (nextHexByte.length < 2) {
        nextHexByte = '0' + nextHexByte
      }
      hexString += nextHexByte
    }
    return hexString
  }

  hex2a (hex) {
    var str = ''
    for (var i = 0; i < hex.length; i += 2) {
      str += String.fromCharCode(parseInt(hex.substr(i, 2), 16))
    }
    return str
  }

  pkcs1pad2 (s, n) {
    if (n < s.length + 11) {
      return null
    }
    var ba = []
    var i = s.length - 1
    while (i >= 0 && n > 0) {
      ba[--n] = s.charCodeAt(i--)
    }
    ba[--n] = 0
    while (n > 2) { // random non-zero pad
      ba[--n] = 0xff
    }
    ba[--n] = 2
    ba[--n] = 0
    var c = this.a2hex(ba)
    return bigInt(c, 16)
  }

  pkcs1unpad2 (a) {
    var b = a.toString(16)
    if (b.length % 2 !== 0) {
      b = '0' + b
    }
    var c = this.hex2a(b)
    var i = 1
    while (c.charCodeAt(i) !== 0) {
      i++
    }
    return c.slice(i + 1)
  }

  encrypt (text) {
    var m = this.pkcs1pad2(text, 0x80)
    var c = m.modPow(this.e, this.n)
    var h = c.toString(16)
    while (h.length < 0x80 * 2) {
      h = '0' + h
    }
    return h
  };

  decrypt (text) {
    var ba = []
    var i = 0
    while (i < text.length) {
      ba[i] = text.charCodeAt(i)
      i += 1
    }
    var a = bigInt(this.a2hex(ba), 16)
    var c = a.modPow(this.e, this.n)
    var d = this.pkcs1unpad2(c)
    return d
  };
}

var new_rsa = new MyRsa()

g_kts = [240, 229, 105, 174, 191, 220, 191, 138, 26, 69, 232, 190, 125, 166, 115, 184, 222, 143, 231, 196, 69, 218, 134, 196, 155, 100, 139, 20, 106, 180, 241, 170, 56, 1, 53, 158, 38, 105, 44, 134, 0, 107, 79, 165, 54, 52, 98, 166, 42, 150, 104, 24, 242, 74, 253, 189, 107, 151, 143, 77, 143, 137, 19, 183, 108, 142, 147, 237, 14, 13, 72, 62, 215, 47, 136, 216, 254, 254, 126, 134, 80, 149, 79, 209, 235, 131, 38, 52, 219, 102, 123, 156, 126, 157, 122, 129, 50, 234, 182, 51, 222, 58, 169, 89, 52, 102, 59, 170, 186, 129, 96, 72, 185, 213, 129, 156, 248, 108, 132, 119, 255, 84, 120, 38, 95, 190, 232, 30, 54, 159, 52, 128, 92, 69, 44, 155, 118, 213, 27, 143, 204, 195, 184, 245];

g_key_s = [0x29, 0x23, 0x21, 0x5E];

g_key_l = [120, 6, 173, 76, 51, 134, 93, 24, 76, 1, 63, 70];

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


m115_asym_encode = function(src, srclen) {
  var i, j, m, ref, ret, text;
  m = 128 - 11;
  ret = '';
  for (i = j = 0, ref = Math.floor((srclen + m - 1) / m); (0 <= ref ? j < ref : j > ref); i = 0 <= ref ? ++j : --j) {
    ret += new_rsa.encrypt(bytesToString(src.slice(i * m, Math.min((i + 1) * m, srclen))));
  }
  return window.btoa(new_rsa.hex2a(ret));
};

m115_asym_decode = function(src, srclen) {
  var i, j, m, ref, ret;
  m = 128;
  ret = '';
  for (i = j = 0, ref = Math.floor((srclen + m - 1) / m); (0 <= ref ? j < ref : j > ref); i = 0 <= ref ? ++j : --j) {
    ret += new_rsa.decrypt(bytesToString(src.slice(i * m, Math.min((i + 1) * m, srclen))));
  }
  return stringToBytes(ret);
};

m115_encode = function(src, tm) {
  var key, tmp, zz;
  key = stringToBytes(md5(`!@###@#${tm}DFDR@#@#`));
  tmp = stringToBytes(src);
  tmp = m115_sym_encode(tmp, tmp.length, key, null);
  tmp = key.slice(0, 16).concat(tmp);
  zz = m115_asym_encode(tmp, tmp.length);
  return {
    data: zz,
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
