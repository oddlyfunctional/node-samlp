const expect = require('chai').expect;
const xmldom = require('xmldom');
const zlib = require('zlib');
const xmlhelper = require('./xmlhelper');
const fs = require('fs');
const path = require('path');
const samlp = require('../lib/samlp');
const encoder = require('../lib/encoders');

const cert = fs.readFileSync(path.join(__dirname, 'fixture/samlp.test-cert.pem'));
const key = fs.readFileSync(path.join(__dirname, 'fixture/samlp.test-cert.key'));
const user = {
  id: 12345678,
  displayName: 'John Foo',
  name: {
    familyName: 'Foo',
    givenName: 'John'
  },
  emails: [
    {
      type: 'work',
      value: 'jfoo@gmail.com'
    }
  ]
};

const defaultOptions = {
  cert,
  key,
  issuer: 'urn:fixture-test',
};

const createResponse = ({ samlRequest, options }, next) => {
  samlp.createResponse(
    user,
    // TODO: parse request
    new xmldom.DOMParser().parseFromString(samlRequest),
    Object.assign({}, defaultOptions, options),
    next,
  );
};

describe('SAMLRequest on querystring', () => {
  const samlRequest = '<?xml version="1.0" encoding="UTF-8"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" AssertionConsumerServiceURL="https://login.salesforce.com" Destination="https://contoso.auth0.com/saml" ID="_2N5GGp2nmITCFbcyGSKjaQ3ai6Kx9cAwDhBGX1gAJyvCrlJvoEQdjEgTsfajgM9m7j.w.I9Fz1ddVjZ9lKZChcsptp9kxkCuqcwbeNe.lJyVQpB8iSa4awFYsj9A5r7REb5JpHH72B6feguHFFPE8Mak3u4hSEKl9_8moiXLdA57WVhzwa8XYxn4mDshSp3Xb0PEZKODHMtxlVXaycGYuMgC20GpfCA" IssueInstant="2013-04-28T22:43:42.386Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://auth0-dev-ed.my.salesforce.com</saml:Issuer></samlp:AuthnRequest>';

  let signedAssertion, attributes;

  before(done => {
    createResponse(
      {
        samlRequest,
      },
      (error, SAMLResponse) => {
        if (error) { return done(error); }

        signedAssertion = /(<saml:Assertion.*<\/saml:Assertion>)/.exec(SAMLResponse)[1];
        attributes = xmlhelper.getAttributes(signedAssertion);
        done();
      },
    );
  });

  it('should contain a valid signal assertion', () => {
    var isValid = xmlhelper.verifySignature(
      signedAssertion, 
      cert);
    expect(isValid).to.be.ok;
  });

  it('should have signature after issuer', () => {
    var doc = new xmldom.DOMParser().parseFromString(signedAssertion);

    var signature = doc.documentElement.getElementsByTagName('Signature');
    expect(signature[0].previousSibling.nodeName).to.equal('saml:Issuer');
  });

  it('should use sha256 as default signature algorithm', () => {
    var algorithm = xmlhelper.getSignatureMethodAlgorithm(signedAssertion);
    expect(algorithm).to.equal('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
  });

  it('should use sha256 as default digest algorithm', () => {
    var algorithm = xmlhelper.getDigestMethodAlgorithm(signedAssertion);
    expect(algorithm).to.equal('http://www.w3.org/2001/04/xmlenc#sha256');
  });

  it('should map every attributes from profile', () => {
    function validateAttribute(position, name, value, type, nameFormat) {

      expect(attributes[position].getAttribute('Name'))
        .to.equal(name);
      expect(attributes[position].getAttribute('NameFormat'))
        .to.equal(nameFormat);
      expect(attributes[position].firstChild.getAttribute('xsi:type'))
        .to.equal(type);
      expect(attributes[position].firstChild.textContent)
        .to.equal(value);
    }

    validateAttribute(0, 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier', String(user.id), 'xs:double', 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri');
    validateAttribute(1, 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',   user.emails[0].value, 'xs:string', 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri');
    validateAttribute(2, 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',           user.displayName, 'xs:string', 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri');
    validateAttribute(3, 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',      user.name.givenName, 'xs:string', 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri');
    validateAttribute(4, 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',        user.name.familyName, 'xs:string', 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri');
  });

  it('should contains the name identifier', () => {
    expect(xmlhelper.getNameIdentifier(signedAssertion).textContent)
      .to.equal(String(user.id));
  });

  it('should set nameidentifier format to urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified by default', () => {
    expect(xmlhelper.getNameIdentifier(signedAssertion).getAttribute('Format'))
      .to.equal('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified');
  });

  it('should contains the issuer', () => {
    expect(xmlhelper.getIssuer(signedAssertion))
      .to.equal('urn:fixture-test');
  });

  it('should contains the audiences', () => {
    expect(xmlhelper.getAudiences(signedAssertion)[0].textContent)
      .to.equal('https://auth0-dev-ed.my.salesforce.com');
  });

  it('should use the default authnContextClassRef', () => {
    expect(xmlhelper.getAuthnContextClassRef(signedAssertion).textContent)
      .to.equal('urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified');
  });
});

describe('SAMLRequest on querystring with a specific authnContextClassRef', () => {
  const samlRequest = '<?xml version="1.0" encoding="UTF-8"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" AssertionConsumerServiceURL="https://login.salesforce.com" Destination="https://contoso.auth0.com/saml" ID="_2N5GGp2nmITCFbcyGSKjaQ3ai6Kx9cAwDhBGX1gAJyvCrlJvoEQdjEgTsfajgM9m7j.w.I9Fz1ddVjZ9lKZChcsptp9kxkCuqcwbeNe.lJyVQpB8iSa4awFYsj9A5r7REb5JpHH72B6feguHFFPE8Mak3u4hSEKl9_8moiXLdA57WVhzwa8XYxn4mDshSp3Xb0PEZKODHMtxlVXaycGYuMgC20GpfCA" IssueInstant="2013-04-28T22:43:42.386Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://auth0-dev-ed.my.salesforce.com</saml:Issuer></samlp:AuthnRequest>';

  const options = {
    authnContextClassRef: "something",
  };

  let signedAssertion, attributes;

  before(done => {
    createResponse(
      {
        samlRequest,
        options,
      },
      (error, SAMLResponse) => {
        if (error) { return done(error); }

        signedAssertion = /(<saml:Assertion.*<\/saml:Assertion>)/.exec(SAMLResponse)[1];
        attributes = xmlhelper.getAttributes(signedAssertion);
        done();
      },
    );
  });

  it('should use the expected authnContextClassRef', () => {
    expect(xmlhelper.getAuthnContextClassRef(signedAssertion).textContent)
      .to.equal('something');
  });
});

describe('when using a different name identifier format', () => {
  const samlRequest = '<?xml version="1.0" encoding="UTF-8"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" AssertionConsumerServiceURL="https://login.salesforce.com" Destination="https://contoso.auth0.com/saml" ID="_2N5GGp2nmITCFbcyGSKjaQ3ai6Kx9cAwDhBGX1gAJyvCrlJvoEQdjEgTsfajgM9m7j.w.I9Fz1ddVjZ9lKZChcsptp9kxkCuqcwbeNe.lJyVQpB8iSa4awFYsj9A5r7REb5JpHH72B6feguHFFPE8Mak3u4hSEKl9_8moiXLdA57WVhzwa8XYxn4mDshSp3Xb0PEZKODHMtxlVXaycGYuMgC20GpfCA" IssueInstant="2013-04-28T22:43:42.386Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://auth0-dev-ed.my.salesforce.com</saml:Issuer></samlp:AuthnRequest>';

  const options = {
    nameIdentifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  };

  let signedAssertion, attributes;

  before(done => {
    createResponse(
      {
        samlRequest,
        options,
      },
      (error, SAMLResponse) => {
        if (error) { return done(error); }

        signedAssertion = /(<saml:Assertion.*<\/saml:Assertion>)/.exec(SAMLResponse)[1];
        attributes = xmlhelper.getAttributes(signedAssertion);
        done();
      },
    );
  });

  it('should override nameidentifier format', () => {
    expect(xmlhelper.getNameIdentifier(signedAssertion).getAttribute('Format'))
      .to.equal('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress');
  });
});

describe('when sending SAMLRequest ID ', () => {
  const samlRequest = '<?xml version="1.0" encoding="UTF-8"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" AssertionConsumerServiceURL="https://acs" Destination="https://destination" ID="12345" IssueInstant="2013-04-28T22:43:42.386Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://sp</saml:Issuer></samlp:AuthnRequest>';

  let signedAssertion, attributes, samlResponse;

  before(done => {
    createResponse(
      {
        samlRequest,
      },
      (error, SAMLResponse) => {
        if (error) { return done(error); }

        samlResponse = SAMLResponse;
        signedAssertion = /(<saml:Assertion.*<\/saml:Assertion>)/.exec(SAMLResponse)[1];
        attributes = xmlhelper.getAttributes(signedAssertion);
        done();
      },
    );
  });

  it('should send back the ID as InResponseTo', () => {
    expect(xmlhelper.getSubjectConfirmationData(signedAssertion).getAttribute('InResponseTo'))
      .to.equal('12345');
  });

  it('should send back the ID as InResponseTo', () => {
    var doc = new xmldom.DOMParser().parseFromString(samlResponse);
    expect(doc.documentElement.getAttribute('InResponseTo')).to.equal('12345');
  });
});

describe('when sending SAMLRequest without RelayState ', () => {
  const samlRequest = '<?xml version="1.0" encoding="UTF-8"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" AssertionConsumerServiceURL="https://acs" Destination="https://destination" ID="12345" IssueInstant="2013-04-28T22:43:42.386Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://sp</saml:Issuer></samlp:AuthnRequest>';

  let signedAssertion, attributes, samlResponse;

  before(done => {
    createResponse(
      {
        samlRequest,
      },
      (error, SAMLResponse) => {
        if (error) { return done(error); }

        samlResponse = SAMLResponse;
        signedAssertion = /(<saml:Assertion.*<\/saml:Assertion>)/.exec(SAMLResponse)[1];
        attributes = xmlhelper.getAttributes(signedAssertion);
        done();
      },
    );
  });

  it('should not throw an error', () => {
    expect(xmlhelper.getSubjectConfirmationData(signedAssertion).getAttribute('InResponseTo'))
      .to.equal('12345');
  });
});

describe('configured signature signatureNamespacePrefix', () => {
  describe('signResponse = true', () => {
    const samlRequest = '<?xml version="1.0" encoding="UTF-8"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" AssertionConsumerServiceURL="https://acs" Destination="https://destination" ID="12345" IssueInstant="2013-04-28T22:43:42.386Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://sp</saml:Issuer></samlp:AuthnRequest>';

    const options = {  signatureNamespacePrefix: 'ds' , signResponse : true };

    let samlResponse;
    before(function (done) {
      createResponse(
        {
          samlRequest,
          options,
        },
        (error, SAMLResponse) => {
          if (error) { return done(error); }

          samlResponse = SAMLResponse;
          done();
        },
      );
    });

    it('should return signature with the specified signatureNamespacePrefix inside the response', () => {
      var doc = new xmldom.DOMParser().parseFromString(samlResponse);
      var signature = doc.documentElement.getElementsByTagName('ds:Signature');
      expect(signature[0].parentNode.nodeName).to.equal('samlp:Response');
    });
  });

  describe('signResponse = false', () => {
    const samlRequest = '<?xml version="1.0" encoding="UTF-8"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" AssertionConsumerServiceURL="https://acs" Destination="https://destination" ID="12345" IssueInstant="2013-04-28T22:43:42.386Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://sp</saml:Issuer></samlp:AuthnRequest>';

    const options = {  signatureNamespacePrefix: 'ds' , signResponse : false };

    let signedAssertion;
    before(function (done) {
      createResponse(
        {
          samlRequest,
          options,
        },
        (error, SAMLResponse) => {
          if (error) { return done(error); }

          signedAssertion = /(<saml:Assertion.*<\/saml:Assertion>)/.exec(SAMLResponse)[1];
          done();
        },
      );
    });

    it('should return signature with the specified signatureNamespacePrefix inside the assertion', () => {
      var doc = new xmldom.DOMParser().parseFromString(signedAssertion);
      var signature = doc.documentElement.getElementsByTagName('ds:Signature');
      expect(signature[0].parentNode.nodeName).to.equal('saml:Assertion');
    });
  });

  describe('invalid signatureNamespacePrefix', () => {
    const samlRequest = '<?xml version="1.0" encoding="UTF-8"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" AssertionConsumerServiceURL="https://acs" Destination="https://destination" ID="12345" IssueInstant="2013-04-28T22:43:42.386Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">http://sp</saml:Issuer></samlp:AuthnRequest>';

    const options = {  signatureNamespacePrefix: 123 , signResponse : false };

    let signedAssertion;
    before(function (done) {
      createResponse(
        {
          samlRequest,
          options,
        },
        (error, SAMLResponse) => {
          if (error) { return done(error); }

          signedAssertion = /(<saml:Assertion.*<\/saml:Assertion>)/.exec(SAMLResponse)[1];
          done();
        },
      );
    });

    it('should return signature without signatureNamespacePrefix inside the assertion', () => {
      var doc = new xmldom.DOMParser().parseFromString(signedAssertion);
      var signature = doc.documentElement.getElementsByTagName('Signature');
      expect(signature[0].parentNode.nodeName).to.equal('saml:Assertion');
    });
  });
});
