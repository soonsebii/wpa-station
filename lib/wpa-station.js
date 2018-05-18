var fs     = require('fs');
var events = require('events');
var util   = require('util');

var WpaClientSocket = require('wpa-client-socket');
var QuickLRU = require('quick-lru');

var NetworkConfig = require('./networkConfig');

const CTRL_PATH = '/var/run/wpa_supplicant';

/*
 * STATE
 */
const WPA_INITIALIZED  = 'INITIALIZED';
const WPA_INACTIVE     = 'INACTIVE';
const WPA_SCANNING     = 'SCANNING';
const WPA_COMPLETED    = 'COMPLETED';
const WPA_DISCONNECTED = 'DISCONNECTED';

/*
 * EVENT
 */
const CTRL_EVENT_PREFIX_STR           = 'CTRL-EVENT-';
const CTRL_EVENT_SCAN_RESULTS_STR     = 'SCAN-RESULTS';
const CTRL_EVENT_NET_CONNECTED_STR    = 'CONNECTED';
const CTRL_EVENT_NET_DISCONNECTED_STR = 'DISCONNECTED';

const WPA_EVENT_PREFIX_STR    = 'WPA: ';
const WPA_EVENT_PSK_INCORRECT = 'pre-shared key may be incorrect';

/*
 * RESPONSE
 */
const RESPONSE_OK = new Buffer('OK\n');

/*
 * SCAN
 */
const SCAN_DATA_SSID_STR   = 'ssid=';
const SCAN_DATA_BSSID_STR  = 'bssid=';
const SCAN_DATA_LEVEL_STR  = 'level=';
const SCAN_DATA_TSF_STR    = 'tsf=';
const SCAN_DATA_FLAGS_STR  = 'flags=';
const SCAN_DATA_FREQ_STR   = 'freq=';

const STATUS_DATA_ID_STR       = 'id=';
const STATUS_DATA_PAIRWISE_STR = 'pairwise_cipher=';
const STATUS_DATA_GROUP_STR    = 'group_cipher=';
const STATUS_DATA_KEY_STR      = 'key_mgmt=';
const STATUS_DATA_STATE_STR    = 'wpa_state=';
const STATUS_DATA_ADDRESS_STR  = 'address=';

var WpaSupplicant = function() {
  this.target_path;
  this.target_interface;
  this.socket = new WpaClientSocket();
  this.cache = new QuickLRU({maxSize: 20});

  this.wpa_state = WPA_INITIALIZED;
  this.address = null;
  this.current_cfg = new NetworkConfig();
};

util.inherits(WpaSupplicant, events.EventEmitter);

WpaSupplicant.prototype.init = function() {
  const self = this;
  this.socket.on('data', this.onMonitor.bind(this));
  this.socket.on('error', this.onError.bind(this));

  fs.readdir(CTRL_PATH, function(err, files) {
    if (err) throw err;

    if (files.length < 1) {
      throw new Error('Unable to open connection to supplicant on ' + CTRL_PATH);
    }

    self.target_interface = files[0];
    self.target_path = CTRL_PATH + '/' + files[0];

    self.socket.bind(self.target_path);
    self.socket.start();
    self._stateEventInvoker();

    self._updateStatus();
    self._stateEventInvoker();
  });
};

WpaSupplicant.prototype.onMonitor = function(msg) {
  var event = msg.toString('utf8', 3).trim();

  if (event.startsWith(CTRL_EVENT_PREFIX_STR)) {
    var ctrl_evt = event.slice(CTRL_EVENT_PREFIX_STR.length);

    if (ctrl_evt === CTRL_EVENT_SCAN_RESULTS_STR) {
      this._setScanResults();
    } else if (ctrl_evt.startsWith(CTRL_EVENT_NET_DISCONNECTED_STR)) {
      // TODO
    } else if (ctrl_evt.startsWith(CTRL_EVENT_NET_CONNECTED_STR)) {
      this._stateEventInvoker(WPA_COMPLETED);
    } else {
      //console.log(ctrl_evt);
    }
  } else if (event.startsWith(WPA_EVENT_PREFIX_STR)) {
    var wpa_evt = event.slice(WPA_EVENT_PREFIX_STR.length);

    if (wpa_evt.indexOf(WPA_EVENT_PSK_INCORRECT) > -1) {
      // TODO
      this.emit('error', new Error('WPA pre-shared key may be incorrect'));
    }
  }
};

WpaSupplicant.prototype.onError = function(msg) {

};

WpaSupplicant.prototype._stateEventInvoker = function(state) {
  if (state)
    this.wpa_state = state;

  this.emit('wpaState', this.wpa_state);
};

WpaSupplicant.prototype._updateStatus = function() {
  var stat = this.socket.write('STATUS');

  if (Buffer.isBuffer(stat)) {
    var str = stat.toString().trim();
    var attributes = str.split('\n');

    for (var attribute of attributes) {
      if (attribute.startsWith(STATUS_DATA_STATE_STR)) {
        this.wpa_state = attribute.substring(STATUS_DATA_STATE_STR.length);
      } else if (attribute.startsWith(STATUS_DATA_ADDRESS_STR)) {
        this.address = attribute.substring(STATUS_DATA_ADDRESS_STR.length);
      }
    }

    if (this.wpa_state === WPA_COMPLETED) {
      var bssid, freq, ssid;
      var networkId, pairwise, group, key_mgmt;

      for (var attribute of attributes) {
        if (attribute.startsWith(SCAN_DATA_BSSID_STR)) {
          bssid = attribute.substring(SCAN_DATA_BSSID_STR.length);
        } else if (attribute.startsWith(SCAN_DATA_FREQ_STR)) {
          freq = attribute.substring(SCAN_DATA_FREQ_STR.length);
        } else if (attribute.startsWith(SCAN_DATA_SSID_STR)) {
          ssid = attribute.substring(SCAN_DATA_SSID_STR.length);
        } else if (attribute.startsWith(STATUS_DATA_ID_STR)) {
          networkId = attribute.substring(STATUS_DATA_ID_STR.length);
        }
      }

      pairwise = this._getNetworkVariable(networkId, 'pairwise');
      group    = this._getNetworkVariable(networkId, 'group');
      key_mgmt = this._getNetworkVariable(networkId, 'key_mgmt');

      this.current_cfg.updateFromStatus({networkId, bssid, ssid, freq, pairwise, group, key_mgmt});
    }
  }
};

/*
 * Change AP Scan
 *
 * 0. no scanning
 * 1. wpa_supplicant requests scans and uses scan results to select the AP
 * 2. wpa_supplicant does not use scanning and just requests driver to associate
 * and take care of AP selection
 *
 */
WpaSupplicant.prototype._setApScanMode = function(mode) {
  var isOk = this.socket.write('AP_SCAN ' + mode);
};

WpaSupplicant.prototype._status = function() {
  var stat = this.socket.write('STATUS');

  if (Buffer.isBuffer(stat)) {
    var str = stat.toString().trim();
    var attributes = str.split('\n');

    var bssid, freq, ssid, pairwise, group, key_mgmt;

    for (var attribute of attributes) {
      if (attribute.startsWith(SCAN_DATA_BSSID_STR)) {
        bssid = attribute.substring(SCAN_DATA_BSSID_STR.length);
      } else if (attribute.startsWith(SCAN_DATA_FREQ_STR)) {
        freq = attribute.substring(SCAN_DATA_FREQ_STR.length);
      } else if (attribute.startsWith(SCAN_DATA_SSID_STR)) {
        ssid = attribute.substring(SCAN_DATA_SSID_STR.length);
      } else if (attribute.startsWith(STATUS_DATA_PAIRWISE_STR)) {
        pairwise = attribute.substring(STATUS_DATA_PAIRWISE_STR.length);
      } else if (attribute.startsWith(STATUS_DATA_GROUP_STR)) {
        group = attribute.substring(STATUS_DATA_GROUP_STR.length);
      } else if (attribute.startsWith(STATUS_DATA_KEY_STR)) {
        key_mgmt = attribute.substring(STATUS_DATA_KEY_STR.length);
      } else if (attribute.startsWith(STATUS_DATA_STATE_STR)) {
        this.wpa_state = attribute.substring(STATUS_DATA_STATE_STR.length);
      } else if (attribute.startsWith(STATUS_DATA_ADDRESS_STR)) {
        this.address = attribute.substring(STATUS_DATA_ADDRESS_STR.length);
        // post update
        this.current_cfg.updateFromStatus(bssid, ssid, freq, pairwise, group, key_mgmt);
      }
    }
  }
};

WpaSupplicant.prototype._addNetwork = function() {
  var networkId = this.socket.write('ADD_NETWORK');
  return networkId.toString().trim();
};

WpaSupplicant.prototype._selectNetwork = function(networkId) {
  var isOk = this.socket.write('SELECT_NETWORK ' + networkId); 
};

WpaSupplicant.prototype._enableNetwork = function(networkId) {
  var isOk = this.socket.write('ENABLE_NETWORK ' + networkId); 
};

WpaSupplicant.prototype._disableNetwork = function(networkId) {
  var isOk = this.socket.write('DISABLE_NETWORK ' + networkId); 
};

WpaSupplicant.prototype._removeNetwork = function(networkId) {
  var isOk = this.socket.write('REMOVE_NETWORK ' + networkId);
};

/*
 * List of network variable
 *
 * ssid
 * psk
 * key_mgmt (NONE, WPA-PSK, WPA-EAP)
 * proto (WPA WPA2)
 * pairwise (CCMP TKIP)
 * group (CCMP TKIP WEP40 WEP104)
 * wep_key0
 * wep_tx_keyidx
 *
 */
WpaSupplicant.prototype._setNetworkVariable = function(networkId, variable, value, noQuote) {
  var command;

  if (!noQuote)
    command = 'SET_NETWORK ' + networkId + ' ' + variable + ' "' + value + '"';
  else
    command = 'SET_NETWORK ' + networkId + ' ' + variable + ' ' + value;

  var isOk = this.socket.write(command);
};

WpaSupplicant.prototype._listNetwork = function() {
  var list = this.socket.write('LIST_NETWORKS');
};

WpaSupplicant.prototype._getNetworkVariable = function(networkId, name) {
  var value = this.socket.write('GET_NETWORK ' + networkId + " " + name);
  return value.toString().trim();
};

WpaSupplicant.prototype._setScanResults = function() {
  var scanResults = this.socket.write('BSS RANGE=ALL MASK=0x21986');

  if (Buffer.isBuffer(scanResults)) {
    var lines = scanResults.toString().split("\n");
    var bssid, freq, level, tsf, flags, ssid;

    for (var line of lines) {
      if (line === '' || line === '####') continue; 

      if (line.startsWith(SCAN_DATA_BSSID_STR)) {
        bssid = line.substring(SCAN_DATA_BSSID_STR.length);
      } else if (line.startsWith(SCAN_DATA_FREQ_STR)) {
        freq = line.substring(SCAN_DATA_FREQ_STR.length);
      } else if (line.startsWith(SCAN_DATA_LEVEL_STR)) {
        level = line.substring(SCAN_DATA_LEVEL_STR.length);
      } else if (line.startsWith(SCAN_DATA_TSF_STR)) {
        tsf = line.substring(SCAN_DATA_TSF_STR.length);
      } else if (line.startsWith(SCAN_DATA_FLAGS_STR)) {
        flags = line.substring(SCAN_DATA_FLAGS_STR.length);
      } else if (line.startsWith(SCAN_DATA_SSID_STR)) {
        ssid = line.substring(SCAN_DATA_SSID_STR.length);
      } else if (line.startsWith('====')) {
        var key = bssid + ssid;
        if (this.cache.has(key)) {
          // update cache
          var t = this.cache.get(key);
          t.bssid = bssid;
          t.freq = freq;
          t.level = level;
          t.tsf = tsf;
          t.flags = flags;
          t.ssid = ssid;
        } else {
          this.cache.set(key, new NetworkConfig(bssid, freq, level, tsf, flags, ssid));
        }
      }
    }

    this.emit('discovery');
  } else {
    this.emit('error', new Error('SCAN failed because the operation was canceled due to an internal error'));
  }
};

WpaSupplicant.prototype.connect = function(networkCfg) {
  if (networkCfg instanceof NetworkConfig) {
    // WPA,WPA2,OPEN
    var netId = this._addNetwork();
    this._setApScanMode(1);
    this._setNetworkVariable(netId, "ssid", networkCfg.ssid);
    this._setNetworkVariable(netId, "psk", networkCfg.getPreSharedKey());
    this._setNetworkVariable(netId, "key_mgmt", networkCfg.getKeyMgt(), true);
    this._selectNetwork(netId);
  }
};

WpaSupplicant.prototype.disconnect = function() {
  this.socket.write('DISCONNECT');
  this._stateEventInvoker(WPA_DISCONNECTED);
};

WpaSupplicant.prototype.save = function() {
  this.socket.write('SAVE_CONFIG');
};

WpaSupplicant.prototype.scan = function() {
  var isOk = this.socket.write('SCAN');

  if (isOk.indexOf(RESPONSE_OK) == -1) {
    this.emit('error', new Error('SCAN failed becasue the WpaSupplicant is busy'));
  }
};

WpaSupplicant.prototype.scanResults = function(callback) {
  var list = [];

  if (this.cache.size < 1)
    list = null;

  for (var apCfg of this.cache)
    list.push(apCfg[1]);

  if (callback)
    callback(list);
};

WpaSupplicant.prototype.status = function(callback) {
  this._status();
};

module.exports = WpaSupplicant;
