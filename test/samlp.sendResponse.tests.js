const expect = require('chai').expect;
const samlp = require('../lib/samlp');

describe('sendResponse', () => {
  let headers;
  let body;

  const samlResponse = 'some response';
  const postUrl = 'some url';
  const relayState = 'some state';
  const res = {
    set: (header, value) => headers[header] = value,
    send: (body_) => body = body_,
  };

  beforeEach(() => {
    headers = {};
    body = undefined;
    samlp.sendResponse(samlResponse, postUrl, relayState, res);
  });

  it('sets the content type', () => {
    expect(headers).to.eql({ 'Content-Type': 'text/html' });
  });

  it('sends a form to post the response', () => {
    expect(body).to.eql("<html>\n<head>\n    <title>Working...</title>\n</head>\n<body>\n    <form method=\"post\" name=\"hiddenform\" action=\"some url\">\n        <input type=\"hidden\" \n               name=\"SAMLResponse\" \n               value=\"c29tZSByZXNwb25zZQ==\">\n        <input type=\"hidden\" name=\"RelayState\" value=\"some state\">\n        <noscript>\n            <p>\n                Script is disabled. Click Submit to continue.\n            </p><input type=\"submit\" value=\"Submit\">\n        </noscript>\n    </form>\n    <script language=\"javascript\" type=\"text/javascript\">\n        window.setTimeout(function(){document.forms[0].submit();}, 0);\n    </script>\n</body>\n</html>");
  });
});
