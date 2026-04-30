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
    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`;
    const response = await fetch(url, {
      headers: {
        'Key': API_KEY,
        'Accept': 'application/json'
      }
    });
    if (!response.ok) {
      const errText = await response.text();
      return { statusCode: response.status, body: JSON.stringify({ error: `AbuseIPDB error: ${response.status}`, detail: errText }) };
    }
    const data = await response.json();
    const d = data.data;
    const result = {
      ip:           d.ipAddress,
      isPublic:     d.isPublic,
      abuseScore:   d.abuseConfidenceScore,
      country:      d.countryCode  || 'Unknown',
      countryName:  d.countryName  || 'Unknown',
      isp:          d.isp          || 'Unknown',
      domain:       d.domain       || 'Unknown',
      usageType:    d.usageType    || 'Unknown',
      totalReports: d.totalReports,
      lastReported: d.lastReportedAt || null,
      isWhitelisted: d.isWhitelisted,
      threatLevel:  d.abuseConfidenceScore >= 75 ? 'Critical'
                  : d.abuseConfidenceScore >= 50 ? 'High'
                  : d.abuseConfidenceScore >= 25 ? 'Medium'
                  : d.abuseConfidenceScore >  0  ? 'Low'
                  : 'Clean',
      isThreat: d.abuseConfidenceScore > 0 || d.totalReports > 0,
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
    return { statusCode: 500, body: JSON.stringify({ error: 'Server error: ' + err.message }) };
  }
};
