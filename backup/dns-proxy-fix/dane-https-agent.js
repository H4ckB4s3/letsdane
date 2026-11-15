import https from 'node:https';

import tls from 'node:tls';



export class DaneHttpsAgent extends https.Agent {

  constructor(securityVerifier, options = {}) {

    super({

      keepAlive: false,

      ...options

    });



    if (

      !securityVerifier ||

      typeof securityVerifier.verifyPeerCertificate !== 'function'

    ) {

      throw new Error('DANE security verifier is required');

    }



    this.securityVerifier = securityVerifier;

  }



  createConnection(options, callback) {

    const hostname = options.servername || options.host;

    const port = Number(options.port || 443);



    let settled = false;



    const finish = (error, socket) => {

      if (settled) return;

      settled = true;



      if (error) {

        socket?.destroy();

      }



      callback?.(error, socket);

    };



    const socket = tls.connect({

      ...options,

      servername: hostname,

      rejectUnauthorized: false

    });



    socket.once('error', error => {

      finish(error);

    });



    socket.once('secureConnect', async () => {

      try {

        const peerCertificate = socket.getPeerCertificate(true);



        if (!peerCertificate?.raw) {

          throw new Error('Upstream supplied no certificate');

        }



        const verification =

          await this.securityVerifier.verifyPeerCertificate(

            hostname,

            port,

            peerCertificate.raw

          );



        if (

          verification?.spki !== 'MATCH' ||

          verification?.interception !== 'VERIFICATION_PASSED'

        ) {

          throw new Error(

            `DANE BLOCKED ${hostname}: ${verification?.reason || 'Verification failed'}`

          );

        }



        console.log(

          `[DANE] VERIFIED ${hostname}:${port} ` +

          `(${verification.trustMode})`

        );



        finish(null, socket);



      } catch (error) {

        console.error(

          `[DANE] BLOCKED ${hostname}:${port}:`,

          error.message

        );



        finish(error, socket);

      }

    });



    return socket;

  }

} 
