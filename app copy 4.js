const express = require('express');
const OAuth = require('oauth-1.0a');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const axios = require('axios');
const rateLimit = require('axios-rate-limit');
const axiosRetry = require('axios-retry').default;

const app = express();
const port = 3000;

app.use(bodyParser.json());

// Crea un cliente de Axios y configura el límite de tasa
const http = rateLimit(axios.create(), { maxRequests: 10, perMilliseconds: 1000 });

// Configura reintentos para el cliente de Axios
axiosRetry(http, {
    retries: 3
});

app.post('/call-netsuite', async (req, res) => {
    const data = req.body;
    const arrayId = data['arrayId'];

    if (!arrayId || arrayId.length === 0) {
        return res.status(400).json({ error: "No se recibieron elementos en el atributo 'arrayId'." });
    }

    // Configuración OAuth 1.0
    const oauth = OAuth({
        consumer: {
            key: data['consumer_key'],
            secret: data['consumer_secret']
        },
        signature_method: 'HMAC-SHA256',
        hash_function(base_string, key) {
            return crypto.createHmac('sha256', key).update(base_string).digest('base64');
        }
    });

    // Token de acceso
    const token = {
        key: data['token_key'],
        secret: data['token_secret']
    };

    const requests = arrayId.map(id => {
        const url = `${data['url']}&id=${id}`;
        const authorization = oauth.toHeader(oauth.authorize({url, method: 'GET'}, token));
        authorization['Authorization'] += `, realm="${data['realm']}"`;

        return http.get(url, {
            headers: {
                ...authorization,
                'Content-Type': 'application/json'
            }
        }).then(response => response.data).catch(error => {
            return { error: true, details: error.message, id };
        });
    });

    Promise.all(requests)
        .then(results => res.status(200).json(results))
        .catch(error => res.status(500).json({ error: 'Error interno del servidor' }));
});

app.listen(port, () => {
    console.log(`Servidor corriendo en http://localhost:${port}`);
});
