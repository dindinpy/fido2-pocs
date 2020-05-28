function stringToArrayBuffer(str){
    return Uint8Array.from(str, c => c.charCodeAt(0)).buffer;
}

function getCredentialOptions() {
  let createCredentialOptions = {
      rp: {
          name: "WebAuthn Sample App",
          icon: "https://example.com/rpIcon.png"
      },
      user: {
          id: stringToArrayBuffer("some.user.id"),
          name: "bob.smith@contoso.com",
          displayName: "Bob Smith",
          icon: "https://example.com/userIcon.png"
      },
      pubKeyCredParams: [
          {
              //External authenticators support the ES256 algorithm
              type: "public-key",
              alg: -7                 
          }, 
          {
              //Windows Hello supports the RS256 algorithm
              type: "public-key",
              alg: -257
          }
      ],
      authenticatorSelection: {
          //Select authenticators that support username-less flows
          requireResidentKey: true,
          //Select authenticators that have a second factor (e.g. PIN, Bio)
          // userVerification: "discouraged",
          //Selects between bound or detachable authenticators
          authenticatorAttachment: "cross-platform"
      },
      //Since Edge shows UI, it is better to select larger timeout values
      timeout: 50000,
      //an opaque challenge that the authenticator signs over
      // challenge: options.publicKey.challenge,
      //prevent re-registration by specifying existing credentials here
      excludeCredentials: [],
      //specifies whether you need an attestation statement
      attestation: "none"
  };
  return createCredentialOptions;
}

$(window).on('load', function() {
    console.log("INFO: in $(window).on ")
    
    init();

    

    fetch('/api/register/begin', {
        method: 'POST',
      }).then(function(response) {
        console.log("INFO: /begin response received")
        if(response.ok) return response.arrayBuffer();
        console.log("INFO: throwing error")
        throw new Error('Error getting registration data!');

      }).then(CBOR.decode).then(function(options) {
        console.log(typeof(options))
        delete options.publicKey.rp['id']
        options.publicKey.rp['name'] = 'Python WebAuthn'
        console.log("INFO: calling navigator.credentials.create")

        let optionsx = getCredentialOptions()
        optionsx['challenge'] = options.publicKey.challenge;


        return navigator.credentials.create({'publicKey': optionsx});

      }, function(err) {
        console.log("ERROR during navigator.credentials.create ", err);

      }).then(function(attestation) {
        console.log("INFO: calling register/complete")
        return fetch('/api/register/complete', {
          method: 'POST',
          headers: {'Content-Type': 'application/cbor'},
          body: CBOR.encode({
            "attestationObject": new Uint8Array(attestation.response.attestationObject),
            "clientDataJSON": new Uint8Array(attestation.response.clientDataJSON),
          })
        });
      }).then(function(response) {
        var stat = response.ok ? 'successful' : 'unsuccessful';
        alert('Registration ' + stat + ' More details in server log...');
      }, function(reason) {
        alert(reason);
      }).then(function() {
        window.location = '/';
      }).catch(function(err){
        console.log("ERROR", err)
      });
})  

function init() {
    if (PublicKeyCredential) {
        console.log("INFO: publickeycredential exists")
        
        console.log("init(): " + PublicKeyCredential.type)
        console.log("init(): " + PublicKeyCredential.id)
        console.log("init(): " + PublicKeyCredential.rawId)
        console.log("init(): " + PublicKeyCredential.response)

    } else {
        console.log("IFNO: if (publickeycredential) is false")
    }
}


    
