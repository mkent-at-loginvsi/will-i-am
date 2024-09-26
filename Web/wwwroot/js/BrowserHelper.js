function checkBrowser() {
    var userAgent = navigator.userAgent;
    var browserName = "";
    var fullVersion = 0;
    var  verOffset;

     if ((verOffset = userAgent.indexOf("Edge")) > 0) {
        browserName = "Edge";        
        fullVersion = userAgent.substring(verOffset + 5);
    }
        // In Chrome, the true version is after "Chrome" 
    else if ((verOffset = userAgent.indexOf("Chrome")) > 0) {
        browserName = "Chrome";
        fullVersion = userAgent.substring(verOffset + 7);
    }

        // In Firefox, the true version is after "Firefox" 
    else if ((verOffset = userAgent.indexOf("Firefox")) > 0) {
        browserName = "Firefox";
        fullVersion = userAgent.substring(verOffset + 8);
    }        

    var majorVersion = parseInt(fullVersion, 10);
    
    if ((browserName != "Chrome" && majorVersion < 49) && (browserName != "Firefox" && majorVersion < 50) && (browserName != "Edge" && majorVersion < 13)) {
        document.getElementById('browserMessage').innerHTML = "You're using an unsupported browser, for the best user experience please switch to a supported browser. For more information click";
        document.getElementById('browserMessage').style.display = "block";
    }   
}

