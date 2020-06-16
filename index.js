var fs = require('fs');
const saml = require('samlify');
const validator = require('@authenio/samlify-xsd-schema-validator');

async function main() {
saml.setSchemaValidator(validator);

const sampleRequestInfo = { extract: { request: { id: 'request_id' } } };
const createTemplateCallback = (_idp, _sp, user) => template => {
  const _id =  '_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6';
  const now = new Date();
  const spEntityID = _sp.entityMeta.getEntityID();
  const idpSetting = _idp.entitySetting;
  const fiveMinutesLater = new Date(now.getTime());
  fiveMinutesLater.setMinutes(fiveMinutesLater.getMinutes() + 5);
  const tvalue = {
    ID: _id,
    AssertionID: idpSetting.generateID ? idpSetting.generateID() : `${uuid.v4()}`,
    Destination: _sp.entityMeta.getAssertionConsumerService(binding.post),
    Audience: spEntityID,
    SubjectRecipient: spEntityID,
    NameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    NameID: user.email,
    Issuer: idp.entityMeta.getEntityID(),
    IssueInstant: now.toISOString(),
    ConditionsNotBefore: now.toISOString(),
    ConditionsNotOnOrAfter: fiveMinutesLater.toISOString(),
    SubjectConfirmationDataNotOnOrAfter: fiveMinutesLater.toISOString(),
    AssertionConsumerServiceURL: _sp.entityMeta.getAssertionConsumerService(binding.post),
    EntityID: spEntityID,
    InResponseTo: '_4606cc1f427fa981e6ffd653ee8d6972fc5ce398c4',
    StatusCode: 'urn:oasis:names:tc:SAML:2.0:status:Success',
    attrUserEmail: 'myemailassociatedwithsp@sp.com',
    attrUserName: 'mynameinsp',
  };
  return {
    id: _id,
    context: libsaml.replaceTagsByValue(template, tvalue),
  };
};

let isAssertionEncrypted = false;
let wantAssertionsSigned = true;

//create SP
const sp = saml.ServiceProvider({
  //metadata : spMetaData,
  entityID: "testEntityID",
  wantAssertionsSigned , 
  signingCert : fs.readFileSync('./certs/idp-pub.crt'),
  // optional
  encPrivateKey: fs.readFileSync('./certs/sp-pvt.pem'),
  isAssertionEncrypted,
});

//create idp
const idp = saml.IdentityProvider({
  metadata : fs.readFileSync('./certs/idpmetadata.xml'),
  privateKey: fs.readFileSync('./certs/idp-pvt.pem'),
  encPrivateKey : fs.readFileSync('./certs/sp-pvt.pem'),
  isAssertionEncrypted
});

// ------ Sample requests  ------
// create SAML assertion packet with IDP initiated workflow
const user = { email: 'user@esaml2.com' };
const { id, context} = await idp.createLoginResponse(sp, sampleRequestInfo, 'post', user, createTemplateCallback(idp, sp, user));
console.log('IDP generated SAML Assertion packet : ' + context);

//SP validation of assertion packet 
let SAMLResponse = context;
const { samlContent, extract } = await sp.parseLoginResponse(idp, 'post', { body: { SAMLResponse } });
console.log('SP signature validated SAML Assertion packet : ' + samlContent);

}

main();

process.on('uncaughtException', function (exception) {
  console.log(exception); // to see your exception details in the console
});
