
const INVALID_NETWORK_ID = -1;

function _parseFlags(config, fline) {
  var flags = fline.slice(1, -1).split('][');

  config.proto = 'WPA RSN';

  for (var flag of flags) {
    if (flag.startsWith('WPA')) {
      config.key_mgmt = 'WPA-PSK';
      config.auth_alg = 'OPEN';
    } else if (flag.startsWith('WPA2')) {
      config.key_mgmt = 'WPA-PSK';
      config.auth_alg = 'OPEN';
    } else if (flag.startsWith('WPS')) {
      continue;
    } else if (flag.startsWith('ESS')) {
      continue;
    }
    
    if (flag.indexOf('CCMP+TKIP') > -1) {
      config.pairwise = 'CCMP TKIP';
      config.group = 'CCMP TKIP';
    } else if (flag.indexOf('CCMP') > -1) {
      config.pairwise = 'CCMP';
      config.group = 'CCMP';
    } else if (flag.indexOf('TKIP') > -1) {
      config.pairwise = 'TKIP';
      config.group = 'TKIP';
    }
  }
};

function NetworkConfig(bssid, freq, level, tsf, flags, ssid) {
  this.networkId = INVALID_NETWORK_ID;
  this.bssid = bssid || '';
  this.level = level || '';
  this.freq = freq || '';
  this.flags = flags || ''
  this.ssid = ssid || '';

  this.proto;
  this.key_mgmt;
  this.auth_alg;
  this.pairwise;
  this.group;
  this.psk;

  if (flags)
    _parseFlags(this, flags);
};

NetworkConfig.prototype.updateFromStatus = function(status) {
  for (var property in status) {
    if (this[property])
      this[property] = status[property];
  }
};

NetworkConfig.prototype.setPreSharedKey = function(psk) {
  this.psk = psk;
};

NetworkConfig.prototype.getPreSharedKey = function(psk) {
  return this.psk || "00000000";
};

NetworkConfig.prototype.getKeyMgt = function() {
  return this.key_mgmt;
};

module.exports = NetworkConfig;
