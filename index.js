const sql = require('mssql')

var syslogd = require('./syslogd');
var fs = require('fs');

var configFile='config.json';
var config={
        "logFolder":'./',        
        "hosts": {}
}

if (fs.existsSync(configFile)){
    config = JSON.parse(fs.readFileSync(configFile));
}
sql.connect(config.logSQL, { encrypt: false, trustServerCertificate: true });

syslogd.Syslogd(receiveSyslogMessage).listen(514, function (err) {
    console.log('Started Syslog Monitor');
});

setInterval(function() {fs.writeFile(configFile, JSON.stringify(config,null,4), function(err){ if(err) throw err; });}, 600000);
setInterval(function() {fs.writeFile('E:/logs/test.json', JSON.stringify(NameUsage,null,4), function(err){ if(err) throw err; });}, 600000);



function receiveSyslogMessage(syslogMessage) {
    //Need to add a detection of what kind of syslog message it is.

    if (!config.hosts[syslogMessage.sourceIP]) {
        config.hosts[syslogMessage.sourceIP]={format: 'unknown', consolidation: 'D'}
    }
    config.hosts[syslogMessage.sourceIP].lastMessage=syslogMessage.receivedTime;

    switch (config.hosts[syslogMessage.sourceIP].format) {
        case "FortigateCSV":
            parseCSVlog(syslogMessage,null);
            break
        default:
            saveSyslogData(syslogMessage);
            break
    }


    //console.log(syslogMessage);
}

function saveSyslogData(syslogMessage) {
    var yearString = syslogMessage.receivedTime.getFullYear().toString();
    var monthString = syslogMessage.receivedTime.getMonth().toString().padStart(2,'0');
    var dayString = syslogMessage.receivedTime.getDay().toString().padStart(2,'0');
    var hourString = syslogMessage.receivedTime.getHours().toString().padStart(2,'0');
    var filename = config.logFolder+syslogMessage.sourceIP+'/';
    
    if (!fs.existsSync(filename)){
        fs.mkdirSync(filename);
    }

    switch (config.hosts[syslogMessage.sourceIP].consolidation) {
        case 'H':
            filename += yearString+'.'+monthString+'.'+dayString+'.'+hourString+'.';
            break;
        case 'D':
            filename += yearString+'.'+monthString+'.'+dayString+'.';
            break;
    }
    filename += syslogd.Severity[syslogMessage.severity]+'.'+syslogd.Facility[syslogMessage.facility]+'.syslog';
    fs.appendFileSync(filename, syslogMessage.msg+'\n');
}
var NameUsage={};
function parseCSVlog(syslogMessage, options) {
    let log={};
    let breakdown = syslogMessage.msg.split(',');
    for (let i=0;i<breakdown.length;i++) {
        let KeyValuePair = breakdown[i].split("=");
        let quotespot = KeyValuePair[1].indexOf('"');
        if (quotespot>=0){
            while (KeyValuePair[1].indexOf('"',quotespot+1)<0) {
                KeyValuePair[1]+=','+breakdown[++i];
            }
            KeyValuePair[1]=KeyValuePair[1].replaceAll("'",'').replaceAll('"',"'");
        }
        log[KeyValuePair[0]]=KeyValuePair[1];        
        if (!NameUsage[KeyValuePair[0]]) {
            NameUsage[KeyValuePair[0]]={count:1,firstvalue:KeyValuePair[1]};
        } else {
            NameUsage[KeyValuePair[0]].count++;
        }
    }
    var SQLfields = "[logfromip]";
    var SQLvalues = "'" + syslogMessage.sourceIP + "'"

    for (let fname in log) {
        SQLfields+=",["+fname+"]";
        switch (fname) {
            case "eventtime":
                case "logid":
                case "srcport":
                case "dstport":
                case "sessionid":
                case "proto":
                case "policyid":
                case "duration":
                case "sentbyte":
                case "rcvdbyte":
                case "sentpkt":
                case "rcvdpkt":
                case "shapingpolicyid":
                case "shaperdropsentbyte":
                case "shaperdroprcvdbyte":
                case "vwlid":
                case "crscore":
                case "craction":
                case "transport":
                case "appid":
                case "countapp":
                case "dstreputation":
                case "sentdelta":
                case "rcvddelta":
                case "cpu":
                case "mem":
                case "totalsession":
                case "disk":
                case "setuprate":
                case "disklograte":
                case "fazlograte":
                case "freediskstorage":
                case "sysuptime":
                case "slatargetid":
                case "latency":
                case "jitter":
                case "packetloss":
                case "identifier":
                case "remport":
                case "locport":
                case "psrcport":
                case "pdstport":
                case "serviceid":
                case "tunnelid":
                case "nextstat":                
                SQLvalues+=","+log[fname];
                break;
            default:
                if (log[fname].indexOf("'")<0) {
                    SQLvalues+=",'"+log[fname]+"'";                    
                } else {
                    SQLvalues+=","+log[fname];
                }
                
                break;
        }
        
    }
    let query = "INSERT INTO Fortigate_Log ("+SQLfields+") VALUES ("+SQLvalues+")"
    //console.log(query);
    try {
        sql.query(query).catch(err => { 
            console.log(err);
            console.log(query);
         });
    } catch(exceptionVar) {
        console.log(exceptionVar);
        console.log(query);
    }

    //fs.appendFileSync("E:/logs/converted.json", JSON.stringify(log)+'\n');
    saveSyslogData(syslogMessage);
}