const express = require('express');
const OAuth = require('oauth-1.0a');
const fetch = require('node-fetch');
const crypto = require('crypto');
const bodyParser = require('body-parser');

const app = express();
const port = 3000;

// Middleware para parsear JSON
app.use(bodyParser.json());

app.post('/call-netsuite', (req, res) => {

    //BODY DE LA SOLICITUD
    const data = req[`body`];
    const arrayId = data[`arrayId`]

    if (arrayId.length > 0)
    {
        for (let i = 0; i < arrayId.length; i++)
        {
            //CONFIGURACION OAUTH 1.0
            const oauth = OAuth({
                consumer: {
                    key: data[`consumer_key`],
                    secret: data[`consumer_secret`]
                },
                signature_method: 'HMAC-SHA256',
                hash_function(base_string, key) {
                    return crypto.createHmac('sha256', key).update(base_string).digest('base64');
                }
            });

            //TOKEN DE ACCESO
            const token = {
                key: data[`token_key`],
                secret: data[`token_secret`]
            };
            console.log(`arrayId: ${arrayId[i]}`)
            //URL RESTLET
            let url = `${data[`url`]}&id=${arrayId[i]}`;
console.log(`url: ${url}`)
            //HEADERS AUTORIZACION
            const authorization = oauth.toHeader(oauth.authorize({url, method: `GET`}, token));
            authorization['Authorization'] += `, realm="${data[`realm`]}"`;
            
            //let notification = { resourceType: data[`resourceType`], resourceId: arrayId, companyId: data[`companyId`] };
            
            //OPCIONES DE LA PETICION A NETSUITE
            const options = {
                method: `GET`,
                headers: {
                    ...authorization,
                    'Content-Type': 'application/json'
                }/*,
                body: JSON.stringify(notification)*/
            };


            //EJECUCION DE REQUEST
            fetch(url, options)
                .then(response => response.json())
                .then(data => res.status(200).json(data))
                .catch(error => {
                    console.error(`Error al llamar a NetSuite:`, error);
                    res.status(500).json({ error: `Error interno del servidor` });
                });

        }
    }
    else
    {
        res.status(500).json({ status: 500, error: true, details: `No se recibio elementos en el atributo "arrayId".`, ns_error: `` });
    }
});

app.listen(port, () => {
    console.log(`Servidor corriendo en http://localhost:${port}`);
});
