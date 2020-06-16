const expect = require('chai').expect;
const fs = require('fs');
const path = require('path');
const samlp = require('../lib/samlp');

describe('sendError', () => {
  let headers;
  let body;

  const res = {
    set: (header, value) => headers[header] = value,
    send: (body_) => body = body_,
  };

  const options = {
    RelayState: 'some state',
    issuer: 'some issuer',
    signatureAlgorithm: 'rsa-sha1',
    digestAlgorithm: 'sha1',
    cert: fs.readFileSync(path.join(__dirname, 'fixture/samlp.test-cert.pem')),
    key: fs.readFileSync(path.join(__dirname, 'fixture/samlp.test-cert.key')),
    instant: new Date(2020, 0, 1, 0, 0, 0),
    id: 'some id',
  };

  const postUrl = 'some url';
  const handler = samlp.sendError(res, postUrl, options);
  const error = new Error('some error');

  beforeEach(() => {
    headers = {};
    body = undefined;
  });

  it('sets the content type', () => {
    handler(error);
    expect(headers).to.eql({ 'Content-Type': 'text/html' });
  });

  it('sends a form to post the response', () => {
    handler(error);
    expect(body).to.eql("<html>\n<head>\n    <title>Working...</title>\n</head>\n<body>\n    <form method=\"post\" name=\"hiddenform\" action=\"some url\">\n        <input type=\"hidden\" \n               name=\"SAMLResponse\" \n               value=\"PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIElEPSJzb21lIGlkIiAgVmVyc2lvbj0iMi4wIiBJc3N1ZUluc3RhbnQ9IldlZCBKYW4gMDEgMjAyMCAwMDowMDowMCBHTVQrMDkwMCAoSmFwYW4gU3RhbmRhcmQgVGltZSkiID48c2FtbDpJc3N1ZXIgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+c29tZSBpc3N1ZXI8L3NhbWw6SXNzdWVyPjxzYW1scDpTdGF0dXM+PHNhbWxwOlN0YXR1c0NvZGUgVmFsdWU9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpzdGF0dXM6UmVzcG9uZGVyIi8+PHNhbWxwOlN0YXR1c01lc3NhZ2UgVmFsdWU9InNvbWUgZXJyb3IiLz48L3NhbWxwOlN0YXR1cz48L3NhbWxwOlJlc3BvbnNlPg==\">\n        <input type=\"hidden\" name=\"RelayState\" value=\"some state\">\n        <noscript>\n            <p>\n                Script is disabled. Click Submit to continue.\n            </p><input type=\"submit\" value=\"Submit\">\n        </noscript>\n    </form>\n    <script language=\"javascript\" type=\"text/javascript\">\n        window.setTimeout(function(){document.forms[0].submit();}, 0);\n    </script>\n</body>\n</html>");
  });
});
