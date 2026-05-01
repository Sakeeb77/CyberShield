exports.handler = async (event) => {
  if (event.httpMethod !== 'GET') {
    return { statusCode: 405, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  const params = event.queryStringParameters || {};
  const ip = params.ip;

  if (!ip) {
    return { statusCode: 400, body: JSON.stringify({ error: 'No IP address provided' }) };
  }

  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(ip);
  const ipv6 = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/.test(ip);
  if (!ipv4 && !ipv6) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Invalid IP address format' }) };
  }

  const blocked = ['127.', '192.168.', '10.', '172.16.', '0.0.0.0'];
  if (blocked.some(function(r){ return ip.startsWith(r); })) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Private IP addresses cannot be checked' }) };
  }

  var KEY = '94ea9b6d2dcadbe89238107e87f381bda8db756af2d1cf3dae6ea7bc403639717e451702fd2fc42c';

  try {
    var endpoint = 'https://api.abuseipdb.com/api/v2/check';
    var query = '?ipAddress=' + encodeURIComponent(ip) + '&maxAgeInDays=90&verbose';
    var fullUrl = endpoint + query;

    var response = await fetch(fullUrl, {
      method: 'GET',
      headers: {
        'Key': KEY,
        'Accept': 'application/json'
      }
    });

    if (!response.ok) {
      var errBody = await response.text();
      return {
        statusCode: response.status,
        body: JSON.stringify({ error: 'AbuseIPDB returned error ' + response.status, detail: errBody })
      };
    }

    var parsed = await response.json();

    // Use bracket notation to avoid GitHub markdown corruption
    var info = parsed["data"];

    var score = info["abuseConfidenceScore"];
    var reports = info["totalReports"];

    var level = 'Clean';
    if (score >= 75) { level = 'Critical'; }
    else if (score >= 50) { level = 'High'; }
    else if (score >= 25) { level = 'Medium'; }
    else if (score > 0)  { level = 'Low'; }

    var output = {
      ip:           info["ipAddress"],
      isPublic:     info["isPublic"],
      abuseScore:   score,
      country:      info["countryCode"]   || 'Unknown',
      countryName:  info["countryName"]   || 'Unknown',
      isp:          info["isp"]           || 'Unknown',
      domain:       info["domain"]        || 'Unknown',
      usageType:    info["usageType"]     || 'Unknown',
      totalReports: reports,
      lastReported: info["lastReportedAt"] || null,
      isWhitelisted: info["isWhitelisted"],
      threatLevel:  level,
      isThreat:     score > 0 || reports > 0
    };

    return {
      statusCode: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      },
      body: JSON.stringify(output)
    };

  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Server error: ' + err.message })
    };
  }
};
