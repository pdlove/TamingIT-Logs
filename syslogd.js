var dgram = require('dgram')

function noop() {}

function Syslogd(fn, opt) {
    if (!(this instanceof Syslogd)) {
        return new Syslogd(fn, opt)
    }
    this.opt = opt || {}
    this.handler = fn
    this.server = dgram.createSocket('udp4')
}

var proto = Syslogd.prototype

proto.listen = function(port, cb) {
    var server = this.server
    if (this.port) {
        console.log('server has binded to %s', port)
        return
    }
    console.log('try bind to %s', port)
    cb = cb || noop
    this.port = port || 514 // default is 514
    var me = this
    server
        .on('error', function(err) {
            console.log('binding error: %o', err)
            cb(err)
        })
        .on('listening', function() {
            console.log('binding ok')
            cb(null)
        })
        .on('message', function(msg, rinfo) {
            var info = parser(msg, rinfo)
            me.handler(info)
        })
        .bind(port, this.opt.address )

    return this
}

var Severity = {
    "0":"Emergency",
    "1":"Alert",
    "2":"Critical",
    "3":"Error",
    "4":"Warning",
    "5":"Notice",
    "6":"Informational",
    "7":"Debug"
}
var Facility = {
    "0":"kernel messages",
    "1":"userlevel messages",
    "2":"mail system",
    "3":"system daemons",
    "4":"securityauthorization messages",
    "5":"messages generated internally by syslogd",
    "6":"line printer subsystem",
    "7":"network news subsystem",
    "8":"UUCP subsystem",
    "9":"clock daemon",
   "10":"securityauthorization messages",
   "11":"FTP daemon",
   "12":"NTP subsystem",
   "13":"log audit",
   "14":"log alert",
   "15":"clock daemon",
   "16":"local0",
   "17":"local1",
   "18":"local2",
   "19":"local3",
   "20":"local4",
   "21":"local5",
   "22":"local6",
   "23":"local7"
} 

function parser(msg, rinfo) {
    // https://tools.ietf.org/html/rfc5424
    // e.g. <PRI>msg
    msg = msg + '';
    var endPRIVAL = msg.indexOf(">");
    var PRIVAL = parseInt(msg.substring(1,endPRIVAL));

    var syslogPacket = {};
    syslogPacket.severity = PRIVAL % 8;
    syslogPacket.facility = (PRIVAL-syslogPacket.severity) / 8;
    syslogPacket.msg=msg.substr(endPRIVAL+1); //Verify this gets the message.
    syslogPacket.receivedTime=new Date();
    syslogPacket.sourceIP=rinfo.address;

    return syslogPacket;
}
module.exports = {Syslogd,Severity,Facility};