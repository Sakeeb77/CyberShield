export default async function handler(req, res) {
  // Only allow GET
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  var ip = req.query.ip;

  if (!ip) {
    return res.status(400).json({ error: 'No IP address provided' });
  }

  var ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(ip);
  var ipv6 = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/.test(ip);
  if (!ipv4 && !ipv6) {
    return res.status(400).json({ error: 'Invalid IP address format' });
  }

  var blocked = ['127.', '192.168.', '10.', '172.16.', '0.0.0.0'];
  for (var i = 0; i < blocked.length; i++) {
    if (ip.startsWith(blocked[i])) {
      return res.status(400).json({ error: 'Private IP addresses cannot be checked' });
    }
  }

  var KEY = '94ea9b6d2dcadbe89238107e87f381bda8db756af2d1cf3dae6ea7bc403639717e451702fd2fc42c';

  try {
    var url = 'https://api.abuseipdb.com/api/v2/check?ipAddress=' + encodeURIComponent(ip) + '&maxAgeInDays=90&verbose';

    var response = await fetch(url, {
      method: 'GET',
      headers: {
        'Key': KEY,
        'Accept': 'application/json'
      }
    });

    if (!response.ok) {
      var errBody = await response.text();
      return res.status(response.status).json({ error: 'AbuseIPDB error ' + response.status, detail: errBody });
    }

    var parsed = await response.json();
    var info = parsed["data"];
    var score = info["abuseConfidenceScore"];
    var reports = info["totalReports"];

    var level = 'Clean';
    if (score >= 75) { level = 'Critical'; }
    else if (score >= 50) { level = 'High'; }
    else if (score >= 25) { level = 'Medium'; }
    else if (score > 0)   { level = 'Low'; }

    return res.status(200).json({
      ip:           info["ipAddress"],
      isPublic:     info["isPublic"],
      abuseScore:   score,
      country:      info["countryCode"]    || 'Unknown',
      countryName:  info["countryName"]    || 'Unknown',
      isp:          info["isp"]            || 'Unknown',
      domain:       info["domain"]         || 'Unknown',
      usageType:    info["usageType"]      || 'Unknown',
      totalReports: reports,
      lastReported: info["lastReportedAt"] || null,
      isWhitelisted: info["isWhitelisted"],
      threatLevel:  level,
      isThreat:     score > 0 || reports > 0
    });

  } catch (err) {
    return res.status(500).json({ error: 'Server error: ' + err.message });
  }
}
