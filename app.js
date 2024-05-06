const express = require('express');
const OAuth = require('oauth-1.0a');
const fetch = require('node-fetch');
const crypto = require('crypto');
const bodyParser = require('body-parser');

const app = express();
const port = 3000;

// Middleware para parsear JSON
app.use(bodyParser.json());

// Configuración de OAuth 1.0
const oauth = OAuth({
    consumer: {
        key: 'f1250b94561332f973c967ac353d69b3a59032a535fcad7ace371b0938120b78',
        secret: '2ab9d5ad5e24dfba8b0e38c8b6e400455ef307472b4d53185ff0fa7c18e34598'
    },
    signature_method: 'HMAC-SHA256',
    hash_function(base_string, key) {
        return crypto.createHmac('sha256', key).update(base_string).digest('base64');
    }
});

// Token de acceso
const token = {
    key: '10c915943c84affea592c7807883f556898de53e91d7d62914b8da99c9d17e5b',
    secret: '85df6afaef8562b674069720ee96572b47a8b52a5dc5dfe48fa2bef8641cbfe9'
};

app.post('/call-netsuite', (req, res) => {
    // La URL del Restlet en NetSuite
    const url = 'https://5032996-sb1.restlets.api.netsuite.com/app/site/hosting/restlet.nl?script=6329&deploy=1';

    // Datos recibidos en el body de la solicitud
    const data = req.body;

    // Generar cabecera de autorización OAuth
    const authorization = oauth.toHeader(oauth.authorize({url, method: 'POST'}, token));
    console.log(`authorization: ${JSON.stringify(authorization[`Authorization`])}`);
    authorization['Authorization'] += `, realm="5032996_SB1"`;
    console.log(`authorization2: ${JSON.stringify(authorization[`Authorization`])}`);
    // Opciones de la petición a NetSuite
    const options = {
        method: 'POST',
        headers: {
            ...authorization,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    };
    //console.log(url);
    //console.log(JSON.stringify(options))
    // Realizar la petición a NetSuite
    fetch(url, options)
        .then(response => response.json())
        .then(data => res.status(200).json(data))
        .catch(error => {
            console.error('Error al llamar a NetSuite:', error);
            res.status(500).json({ error: 'Error interno del servidor' });
        });
});

app.listen(port, () => {
    console.log(`Servidor corriendo en http://localhost:${port}`);
});
