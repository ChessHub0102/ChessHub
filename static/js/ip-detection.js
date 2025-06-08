// Function to detect real IP address using WebRTC
function detectRealIp() {
    return new Promise((resolve, reject) => {
        try {
            console.log("Starting WebRTC IP detection");
            // Compatible with Firefox and Chrome, edge
            var RTCPeerConnection = window.RTCPeerConnection || 
                                   window.mozRTCPeerConnection || 
                                   window.webkitRTCPeerConnection;
                                   
            if (!RTCPeerConnection) {
                console.warn("WebRTC not supported by browser");
                // Fallback to server-side detection only
                resolve(null);
                return;
            }
            
            var rtc = new RTCPeerConnection({
                // Using Google's public STUN servers
                iceServers: [
                    {urls: "stun:stun.l.google.com:19302"},
                    {urls: "stun:stun1.l.google.com:19302"},
                    {urls: "stun:stun2.l.google.com:19302"},
                    {urls: "stun:stun.services.mozilla.com"}
                ]
            });
            
            // Empty data channel, just need the ICE candidate events
            rtc.createDataChannel('');
            
            // Create an offer to connect
            rtc.createOffer()
            .then(offer => rtc.setLocalDescription(offer))
            .catch(err => {
                console.error("Error creating offer:", err);
                // Still resolve but with null to allow fallback to server detection
                resolve(null);
            });
            
            var ipList = [];
            var timeout = setTimeout(() => {
                console.log("WebRTC detection complete. Found IPs:", ipList);
                if (ipList.length) {
                    resolve(ipList);
                } else {
                    // Try alternative method as fallback
                    tryAlternativeIpDetection().then(ips => {
                        resolve(ips);
                    }).catch(err => {
                        console.error("Alternative detection failed:", err);
                        resolve(null);
                    });
                }
            }, 4000); // Extended timeout for slower connections
            
            // Listen for candidate events
            rtc.onicecandidate = function(ice) {
                if (!ice || !ice.candidate || !ice.candidate.candidate) {
                    return;
                }
                
                var candidateString = ice.candidate.candidate;
                console.log("ICE candidate:", candidateString);
                
                var ip = /([0-9]{1,3}(\.[0-9]{1,3}){3})/.exec(candidateString);
                if (ip) {
                    // Found IP
                    var detectedIp = ip[1];
                    console.log("Extracted IP:", detectedIp);
                    
                    // Filter local IPs
                    if (!isLocalIP(detectedIp)) {
                        if (ipList.indexOf(detectedIp) === -1) {
                            console.log("Adding public IP to list:", detectedIp);
                            ipList.push(detectedIp);
                        }
                    } else {
                        console.log("Skipping local IP:", detectedIp);
                    }
                }
                
                // If we have any results, resolve early
                if (ipList.length > 0) {
                    clearTimeout(timeout);
                    console.log("WebRTC detection early resolution. Found IPs:", ipList);
                    resolve(ipList);
                }
            };
        } catch (e) {
            console.error("Error in detectRealIp:", e);
            // Try alternative method as fallback
            tryAlternativeIpDetection().then(ips => {
                resolve(ips);
            }).catch(err => {
                console.error("Alternative detection failed:", err);
                resolve(null);
            });
        }
    });
}

// Alternative method to detect IP (as a fallback)
function tryAlternativeIpDetection() {
    return new Promise((resolve, reject) => {
        console.log("Trying alternative IP detection methods");
        
        // Try using a third-party API to get the real IP
        fetch('https://api.ipify.org?format=json')
            .then(response => response.json())
            .then(data => {
                if (data && data.ip) {
                    console.log("Alternative IP detection successful:", data.ip);
                    resolve([data.ip]);
                } else {
                    reject("No IP returned from alternative method");
                }
            })
            .catch(error => {
                console.error("Alternative IP detection error:", error);
                
                // Try another service
                fetch('https://api.db-ip.com/v2/free/self')
                    .then(response => response.json())
                    .then(data => {
                        if (data && data.ipAddress) {
                            console.log("Secondary alternative IP detection successful:", data.ipAddress);
                            resolve([data.ipAddress]);
                        } else {
                            reject("No IP returned from secondary alternative method");
                        }
                    })
                    .catch(secondError => {
                        console.error("Secondary alternative IP detection error:", secondError);
                        reject("All alternative methods failed");
                    });
            });
    });
}

// Check if an IP is a local/private address
function isLocalIP(ip) {
    // Check for private IP ranges
    return ip.match(/^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)/) !== null ||
           ip.indexOf(':') !== -1; // IPv6
}

// Function to directly fetch location data for an IP
function fetchLocationData(ip) {
    return fetch(`/get-location/${ip}`, {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        },
        credentials: 'same-origin'
    })
    .then(response => response.json())
    .catch(error => {
        console.error("Error fetching location data:", error);
        return null;
    });
}

// When the page loads
document.addEventListener('DOMContentLoaded', function() {
    console.log("IP detection script loaded");
    
    // Detect the real IP
    detectRealIp().then(function(ips) {
        console.log("WebRTC detection successful, found IPs:", ips);
        
        if (ips && ips.length) {
            // Send the detected IPs to the server
            fetch('/log-real-ip', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify({ real_ips: ips }),
                credentials: 'same-origin'
            })
            .then(response => response.json())
            .then(data => {
                console.log("Server response:", data);
                if (data.status === 'success') {
                    console.log("Real IP successfully logged");
                    
                    // If we got location data back, we could update UI elements if needed
                    if (data.location) {
                        console.log("Received location data:", data.location);
                    }
                } else {
                    console.error("Error logging real IP:", data.message);
                }
            })
            .catch(error => {
                console.error("Error sending real IP to server:", error);
            });
        } else {
            console.warn("No IPs detected, using fallback to server-side detection");
            // Notify the server to use its best detection method
            fetch('/log-real-ip', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify({ real_ips: null, use_server_detection: true }),
                credentials: 'same-origin'
            })
            .then(response => response.json())
            .then(data => {
                console.log("Server fallback response:", data);
            })
            .catch(error => {
                console.error("Error with server fallback:", error);
            });
        }
    }).catch(function(error) {
        console.error("IP detection failed:", error);
    });
});