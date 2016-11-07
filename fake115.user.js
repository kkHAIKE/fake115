// ==UserScript==
// @name         fake 115Browser
// @namespace    http://github.com/kkHAIKE/fake115
// @version      1.3
// @description  伪装115浏览器
// @author       kkhaike
// @match        *://115.com/*
// @grant        GM_xmlhttpRequest
// @grant        unsafeWindow
// @grant        GM_log
// @connect      passport.115.com
// @connect      passportapi.115.com
// @connect      proapi.115.com
// @connect      uplb.115.com
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
// @require      https://rawgit.com/emn178/js-md4/master/build/md4.min.js
// @require      https://rawgit.com/kkHAIKE/fake115/master/fec115.min.js
// @require      http://cdn.bootcss.com/jsSHA/2.2.0/sha1.js
// @run-at       document-start
// ==/UserScript==
(function() {
    'use strict';
var Buffer, LZ4, LoginEncrypt_, browserInterface, bytesToHex, bytesToInt, bytesToString, dictToForm, dictToQuery, ec115_compress_decode, ec115_decode, ec115_decode_aes, ec115_encode_data, ec115_encode_token, ec115_init, g_Q, g_c, g_rng, g_ver, get_key, hexToBytes, intToBytes, md4_init, pick_rand, preLoginEncrypt, sig_calc, sig_init, stringToBytes, _ref;

g_ver = '7.2.4.37';

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

bytesToHex = function(b) {
  var ret, t, _i, _len;
  ret = '';
  for (_i = 0, _len = b.length; _i < _len; _i++) {
    t = b[_i];
    ret += (t >> 4).toString(16);
    ret += (t & 0xf).toString(16);
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

bytesToInt = function(b) {
  return b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24);
};

pick_rand = function(n) {
  var n1, r;
  n1 = n.subtract(BigInteger.ONE);
  r = new BigInteger(n.bitLength(), g_rng);
  return r.mod(n1).add(BigInteger.ONE);
};

ec115_init = function() {
  var G, K, P, c, d, pub, y;
  d = pick_rand(g_c.getN());
  G = g_c.getG();
  P = G.multiply(d);
  c = g_c.getCurve();
  pub = c.encodePointHex(P);
  y = P.getY().toBigInteger();
  pub = hexToBytes("1d" + (y.testBit(0) ? "03" : "02") + pub.slice(2, 58));
  K = g_Q.multiply(d);
  return {
    pub: pub,
    key: hexToBytes(K.getX().toBigInteger().toString(16))
  };
};

ec115_encode_token = function(pub, tm, cnt) {
  var i, r2, tmp, tmp2, _i, _j, _k, _l;
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
  tmp = tmp.concat(intToBytes(cnt));
  for (i = _l = 40; _l < 44; i = ++_l) {
    tmp[i] ^= r2[1];
  }
  tmp2 = stringToBytes('^j>WD3Kr?J2gLFjD4W2y@').concat(tmp);
  tmp = tmp.concat(intToBytes(CRC32.buf(tmp2) >>> 0));
  return window.btoa(bytesToString(tmp));
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

get_key = function(data_buf) {
  var i, p, ret, t, _i;
  p = 0;
  ret = new Uint8Array(40);
  for (i = _i = 0; _i < 40; i = ++_i) {
    t = bytesToInt(data_buf.slice(p, p + 4));
    p = t + 1;
    ret[i] = data_buf[t];
  }
  return ret;
};

md4_init = function(pSig) {
  var pSig_32, ret;
  ret = md4.create();
  pSig_32 = new Int32Array(pSig.buffer);
  ret.h0 = pSig_32[1];
  ret.h1 = pSig_32[2];
  ret.h2 = pSig_32[3];
  ret.h3 = pSig_32[4];
  ret.first = false;
  return ret;
};

sig_init = function(body) {
  var data_buf, data_buf_p, dhash, md4h, ori_data_p, pSig, sz;
  ori_data_p = Module._malloc(body.length);
  Module.HEAPU8.set(body, ori_data_p);
  data_buf_p = Module._malloc(body.length);
  sz = Module.ccall('calc_out', 'number', ['number', 'number', 'number'], [ori_data_p, body.length, data_buf_p]);
  Module._free(ori_data_p);
  data_buf = new Uint8Array(Module.buffer, data_buf_p, sz);
  pSig = get_key(data_buf);
  md4h = md4_init(pSig);
  md4h.update(data_buf);
  dhash = md4h.digest();
  return {
    data_buf: data_buf,
    data_buf_p: data_buf_p,
    pSig: pSig,
    dhash: dhash
  };
};

sig_calc = function(_arg, src) {
  var data_buf, data_buf_p, dhash, h1, h1_p, i, md4h, out_data, out_data_p, pSig, ret, sz, _i;
  data_buf = _arg.data_buf, data_buf_p = _arg.data_buf_p, pSig = _arg.pSig, dhash = _arg.dhash;
  md4h = md4_init(pSig);
  md4h.update(dhash);
  md4h.update(src);
  md4h.update(pSig);
  h1 = new Uint8Array(md4h.buffer());
  h1_p = Module._malloc(16);
  Module.HEAPU8.set(h1, h1_p);
  out_data_p = Module._malloc(0x10000);
  sz = Module.ccall('encode', 'number', ['number', 'number', 'number', 'number', 'number', 'number', 'number'], [data_buf_p, data_buf.length / 2, h1_p, 16, out_data_p, 8, 10]);
  Module._free(data_buf_p);
  Module._free(h1_p);
  out_data = new Uint8Array(Module.buffer, out_data_p, sz);
  md4h = md4_init(pSig);
  md4h.update(out_data);
  ret = md4h.digest();
  Module._free(out_data_p);
  ret.push(pSig[0]);
  for (i = _i = 36; _i < 40; i = ++_i) {
    ret.push(pSig[i]);
  }
  return bytesToHex(ret);
};

ec115_decode = function(data, key) {
  var dec, unzip;
  dec = data[data.length - 12 + 5];
  unzip = data[data.length - 12 + 4];
  data = data.slice(0, -12);
  if (dec === 1) {
    data = ec115_decode_aes(data, key);
  }
  if ((data != null) && unzip === 1) {
    data = ec115_compress_decode(data);
  }
  return data;
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

LoginEncrypt_ = function(_arg, g, _arg1, sig) {
  var account, data, environment, fake, goto, key, login_type, passwd, pub, tm, tmus, token;
  account = _arg.account, passwd = _arg.passwd, environment = _arg.environment, goto = _arg.goto, login_type = _arg.login_type;
  pub = _arg1.pub, key = _arg1.key;
  tmus = (new Date()).getTime();
  tm = Math.floor(tmus / 1000);
  fake = md5(account);
  token = ec115_encode_token(pub, tm, 1);
  data = ec115_encode_data(dictToForm({
    GUID: fake.slice(0, 20),
    account: account,
    device: 'jujumao',
    device_id: fake.slice(0, 12).toUpperCase(),
    device_type: 'windows',
    disk_serial: fake.slice(0, 8).toUpperCase(),
    dk: '',
    environment: environment,
    login_source: '115chrome',
    network: '5',
    passwd: passwd,
    sign: md5("" + account + tm),
    system_info: ("            " + fake[1] + fake[0] + fake[3] + fake[2] + fake[5] + fake[4] + fake[7] + fake[6]).toUpperCase(),
    time: tm,
    login_type: login_type,
    sign115: sig_calc(sig, md5("" + account + tm))
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
      var date, datestr, json;
      if (response.status === 200) {
        data = new Uint8Array(response.response);
        data = ec115_decode(data, key);
        if (data != null) {
          json = JSON.parse(bytesToString(data));
          if (json.state) {
            date = new Date();
            date.setTime(date.getTime() + 7 * 24 * 3600 * 1000);
            datestr = date.toGMTString();
            unsafeWindow.document.cookie = "UID=" + json.data.cookie.UID + "; expires=" + datestr + "; path=/; domain=115.com";
            unsafeWindow.document.cookie = "CID=" + json.data.cookie.CID + "; expires=" + datestr + "; path=/; domain=115.com";
            unsafeWindow.document.cookie = "SEID=" + json.data.cookie.SEID + "; expires=" + datestr + "; path=/; domain=115.com";
            unsafeWindow.document.cookie = "OOFL=" + json.data.user_id + "; expires=" + datestr + "; path=/; domain=115.com";
            json.goto = "" + json.goto + (encodeURIComponent(goto));
            delete json.data;
          }
          return unsafeWindow[g](JSON.stringify(json));
        } else {
          return GM_log('data is null');
        }
      } else {
        return GM_log("response.status = " + response.status);
      }
    }
  });
};

preLoginEncrypt = function(n, g) {
  var key, pub, tm, tmus, token, _ref;
  tmus = (new Date()).getTime();
  tm = Math.floor(tmus / 1000);
  _ref = ec115_init(), pub = _ref.pub, key = _ref.key;
  token = ec115_encode_token(pub, tm, 0);
  return GM_xmlhttpRequest({
    method: 'GET',
    url: "https://passportapi.115.com/app/2.0/web/" + g_ver + "/login/sign?k_ec=" + token,
    responseType: 'arraybuffer',
    anonymous: true,
    onload: function(response) {
      var body, data, error, i, json, sig, tmp, _i, _ref1;
      if (response.status === 200) {
        data = new Uint8Array(response.response);
        data = ec115_decode(data, key);
        if (data != null) {
          json = JSON.parse(bytesToString(data));
          if (json.state) {
            tmp = window.atob(json.sign);
            body = new Uint8Array(tmp.length);
            for (i = _i = 0, _ref1 = tmp.length; 0 <= _ref1 ? _i < _ref1 : _i > _ref1; i = 0 <= _ref1 ? ++_i : --_i) {
              body[i] = tmp.charCodeAt(i);
            }
            try {
              sig = sig_init(body);
              return LoginEncrypt_(JSON.parse(n), g, {
                pub: pub,
                key: key
              }, sig);
            } catch (_error) {
              error = _error;
              return GM_log("" + error);
            }
          } else {
            return GM_log(JSON.stringify(json));
          }
        } else {
          return GM_log('data is null');
        }
      } else {
        return GM_log("response.status = " + response.status);
      }
    }
  });
};

browserInterface = (_ref = unsafeWindow.browserInterface) != null ? _ref : {};

browserInterface.LoginEncrypt = function(n, g) {
  var error;
  try {
    return preLoginEncrypt(n, g);
  } catch (_error) {
    error = _error;
    return GM_log("" + error);
  }
};

unsafeWindow.browserInterface = cloneInto(browserInterface, unsafeWindow, {
  cloneFunctions: true
});

unsafeWindow.document.addEventListener('DOMContentLoaded', function() {
  var cont, error, fakeSizeLimitGetter, fastSig, fastUpload, finput, getUserKey, js_top_panel_box, procLabel, uploadinfo;
  try {
    js_top_panel_box = unsafeWindow.document.getElementById('js_top_panel_box');
    if (js_top_panel_box != null) {
      cont = document.createElement('div');
      finput = document.createElement('input');
      finput.setAttribute('type', 'file');
      procLabel = document.createElement('span');
      cont.appendChild(finput);
      cont.appendChild(procLabel);
      js_top_panel_box.appendChild(cont);
      cont.style.position = 'absolute';
      cont.style.top = '20px';
      cont.style.left = '80px';
      fastSig = function(userid, fileid, target, userkey) {
        var sha1, tmp;
        sha1 = new jsSHA('SHA-1', 'TEXT');
        sha1.update("" + userid + fileid + target + "0");
        tmp = sha1.getHash('HEX');
        sha1 = new jsSHA('SHA-1', 'TEXT');
        sha1.update("" + userkey + tmp + "000000");
        return sha1.getHash('HEX', {
          outputUpper: true
        });
      };
      uploadinfo = null;
      fastUpload = function(_arg) {
        var fileid, filename, filesize, preid, tm, tmus;
        fileid = _arg.fileid, preid = _arg.preid, filename = _arg.filename, filesize = _arg.filesize;
        tmus = (new Date()).getTime();
        tm = Math.floor(tmus / 1000);
        return GM_xmlhttpRequest({
          method: 'POST',
          url: uploadinfo.url_upload + '?' + dictToQuery({
            appid: 0,
            appfrom: 10,
            appversion: '2.0.0.0',
            format: 'json',
            isp: 0,
            sig: fastSig(uploadinfo.user_id, fileid, 'U_1_0', uploadinfo.userkey),
            t: tm
          }),
          data: dictToForm({
            api_version: '2.0.0.0',
            fileid: fileid,
            filename: filename,
            filesize: filesize,
            preid: preid,
            target: 'U_1_0',
            userid: uploadinfo.user_id
          }),
          responseType: 'json',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
          },
          onload: function(response) {
            if (response.status === 200) {
              if (response.response.status === 2) {
                return alert('fastupload OK, refresh window and goto root folder to find it');
              } else {
                return alert('fastupload FAIL, LOL');
              }
            } else {
              return GM_log("response.status = " + response.status);
            }
          }
        });
      };
      getUserKey = function(param) {
        return GM_xmlhttpRequest({
          method: 'GET',
          url: 'http://proapi.115.com/app/uploadinfo',
          responseType: 'json',
          onload: function(response) {
            if (response.status === 200) {
              uploadinfo = response.response;
              return fastUpload(param);
            } else {
              return GM_log("response.status = " + response.status);
            }
          }
        });
      };
      finput.onchange = function(e) {
        var PSIZE, allSha1, f, finalPart, nextPart, npart, preid;
        if (e.target.files.length === 0) {
          return;
        }
        f = e.target.files[0];
        if (f.size < 128 * 1024) {
          alert('file size less than 128K');
          return;
        }
        PSIZE = 1 * 1024 * 1024;
        npart = Math.floor((f.size + PSIZE - 1) / PSIZE);
        allSha1 = new jsSHA('SHA-1', 'ARRAYBUFFER');
        preid = '';
        finalPart = function() {
          var fileid, param;
          fileid = allSha1.getHash('HEX', {
            outputUpper: true
          });
          param = {
            fileid: fileid,
            preid: preid,
            filename: f.name,
            filesize: f.size
          };
          if (uploadinfo != null) {
            return fastUpload(param);
          } else {
            return getUserKey(param);
          }
        };
        nextPart = function(n) {
          var b, reader;
          reader = new FileReader();
          b = f.slice(n * PSIZE, (n + 1) * PSIZE > f.size ? f.size : (n + 1) * PSIZE);
          reader.onerror = function(e) {
            return GM_log("" + e.target.error);
          };
          reader.onload = function(e) {
            var data, sha1;
            data = new Uint8Array(e.target.result);
            if (n === 0) {
              sha1 = new jsSHA('SHA-1', 'ARRAYBUFFER');
              sha1.update(data.slice(0, 128 * 1024));
              preid = sha1.getHash('HEX', {
                outputUpper: true
              });
            }
            allSha1.update(data);
            procLabel.textContent = "(" + (Math.floor((n + 1) * 100 / npart)) + "%)";
            if (n === npart - 1) {
              return finalPart();
            } else {
              return nextPart(n + 1);
            }
          };
          return reader.readAsArrayBuffer(b);
        };
        return nextPart(0);
      };
    }
    if (unsafeWindow.UPLOAD_CONFIG_H5 != null) {
      fakeSizeLimitGetter = function() {
        return 115 * 1024 * 1024 * 1024;
      };
      if (Object.defineProperty != null) {
        return Object.defineProperty(unsafeWindow.UPLOAD_CONFIG_H5, 'size_limit', {
          get: fakeSizeLimitGetter
        });
      } else if (Object.prototype.__defineGetter__ != null) {
        return unsafeWindow.UPLOAD_CONFIG_H5.__defineGetter__('size_limit', fakeSizeLimitGetter);
      }
    }
  } catch (_error) {
    error = _error;
    return GM_log("" + error);
  }
});

})();
