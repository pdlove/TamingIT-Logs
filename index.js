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

syslogd.Syslogd(receiveSyslogMessage).listen(514, function (err) {
    console.log('Started Syslog Monitor');
});

setInterval(function() {fs.writeFile(configFile, JSON.stringify(config,null,4), function(err){ if(err) throw err; });}, 6000000);

function receiveSyslogMessage(syslogMessage) {
    //Need to add a detection of what kind of syslog message it is.
    var yearString = syslogMessage.receivedTime.getFullYear().toString();
    var monthString = syslogMessage.receivedTime.getMonth().toString().padStart(2,'0');
    var dayString = syslogMessage.receivedTime.getDay().toString().padStart(2,'0');
    var hourString = syslogMessage.receivedTime.getHours().toString().padStart(2,'0');
    if (!config.hosts[syslogMessage.sourceIP]) {
        config.hosts[syslogMessage.sourceIP]={format: 'unknown', consolidation: 'D'}
    }
    config.hosts[syslogMessage.sourceIP].lastMessage=syslogMessage.receivedTime;
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
    fs.appendFileSync(filename, syslogMessage.msg);
    //console.log(syslogMessage);
}