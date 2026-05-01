exports.handler = async (event) => {
  if (event.httpMethod !== 'GET') {
    return { statusCode: 405, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  const ip = event.queryStringParameters && event.queryStringParameters.ip;

  if (!ip) {
    return { statusCode: 400, body: JSON.stringify({ error: 'No IP address provided' }) };
  }

  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  if (!ipv4Regex.test(ip) && !ipv6Regex.test(ip)) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Invalid IP address format' }) };
  }

  const privateRanges = ['127.', '192.168.', '10.', '172.16.', '0.0.0.0'];
  if (privateRanges.some(range => ip.startsWith(range))) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Private/local IP addresses cannot be checked' }) };
  }

  const API_KEY = '94ea9b6d2dcadbe89238107e87f381bda8db756af2d1cf3dae6ea7bc403639717e451702fd2fc42c';

  try {
    const url = 'https://api.abuseipdb.com/api/v2/check?ipAddress=' + encodeURIComponent(ip) + '&maxAgeInDays=90&verbose';
    const response = await fetch(url, {
      headers: {
        'Key': API_KEY,
        'Accept': 'application/json'
      }
    });

    if (!response.ok) {
      const errText = await response.text();
      return {
        statusCode: response.status,
        body: JSON.stringify({ error: 'AbuseIPDB error: ' + response.status, detail: errText })
      };
    }

    const json = await response.json();
    const info = json.data;

    const abuseScore = info.abuseConfidenceScore;

    const result = {
      ip:           info.ipAddress,
      isPublic:     info.isPublic,
      abuseScore:   abuseScore,
      country:      info.countryCode  || 'Unknown',
      countryName:  info.countryName  || 'Unknown',
      isp:          info.isp          || 'Unknown',
      domain:       info.domain       || 'Unknown',
      usageType:    info.usageType    || 'Unknown',
      totalReports: info.totalReports,
      lastReported: info.lastReportedAt || null,
      isWhitelisted: info.isWhitelisted,
      threatLevel:  abuseScore >= 75 ? 'Critical'
                  : abuseScore >= 50 ? 'High'
                  : abuseScore >= 25 ? 'Medium'
                  : abuseScore >  0  ? 'Low'
                  : 'Clean',
      isThreat: abuseScore > 0 || info.totalReports > 0,
    };

    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      },
      body: JSON.stringify(result)
    };

  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Server error: ' + err.message })
    };
  }
};
