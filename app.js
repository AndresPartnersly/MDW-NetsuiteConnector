const express = require('express');
const OAuth = require('oauth-1.0a');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const axios = require('axios');
const rateLimit = require('axios-rate-limit');
const axiosRetry = require('axios-retry').default;
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const { get } = require('https');
const { is } = require('express/lib/request');
const fs = require('fs');
const path = require('path');
dotenv.config();

// Creación de una instancia de Express para gestionar las solicitudes HTTP.
const app = express();
const port = 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const USERS_DATA = process.env.USERS_DATA;
const PRODUCT_CONFIGURATION = process.env.PRODUCT_CONFIGURATION;
const BASE_URL = process.env.BASE_URL;
const FIELDSET = process.env.FIELDSET;
const WEBSITE_ID = process.env.WEBSITE_ID;
const filePath = path.resolve(process.env.DATABASE_PATH);

// Middleware de Express para analizar cuerpos de solicitud JSON automáticamente.
app.use(bodyParser.json());

/*const http = rateLimit(axios.create(), { maxRequests: 10, perMilliseconds: 60000 });
// Configuración de reintentos automáticos para el cliente Axios para manejar fallos temporales en las peticiones.
axiosRetry(http, {
    retries: 10
});*/

//Configuración por defecto.
let http = rateLimit(axios.create(), { maxRequests: 10, perMilliseconds: 60000 });

// Inicia el servidor en el puerto especificado y muestra un mensaje en la consola.
app.listen(port, () => {
    console.log(`41. Servidor corriendo en http://localhost:${port}`);
});

app.post('/netsuite-puente', async (req, res) => {

    const data = req.body; // Datos recibidos en el cuerpo de la solicitud.

    http = rateLimit(axios.create(), { maxRequests: 1, perMilliseconds: 100 });

    //console.log(`127. retries: ${data['retries']} - maxRequests: ${data['maxRequests']} - perMilliseconds: ${data['perMilliseconds']}`)
    // Configuración de reintentos automáticos para el cliente Axios para manejar fallos temporales en las peticiones.
    axiosRetry(http, {
        retries: data['retries']
    });

    const oauth = OAuth({
        consumer: {
            key: data['consumer_key'], // Clave del consumidor para OAuth.
            secret: data['consumer_secret'] // Secreto del consumidor para OAuth.
        },
        signature_method: 'HMAC-SHA256', // Método de firma HMAC-SHA256.
        hash_function(base_string, key) { // Función para generar el hash de la firma.
            return crypto.createHmac('sha256', key).update(base_string).digest('base64');
        }
    });

    // Token de acceso para las peticiones.
    const token = {
        key: data['token_key'], // Clave del token de acceso.
        secret: data['token_secret'] // Secreto del token de acceso.
    };
   
    const postData = JSON.stringify(data[`postdata`]);
    const url = `${data['url']}`; // Construye la URL para cada ID.
    const authorization = oauth.toHeader(oauth.authorize({ url, method: 'POST' }, token)); // Genera el encabezado de autorización.
    authorization['Authorization'] += `, realm="${data['realm']}"`; // Añade 'realm' al encabezado de autorización.
    console.log(`176`);
    // Realiza la petición GET y maneja la respuesta o errores.
    /*return http.get(url, {
        headers: {
            ...authorization,
            'Content-Type': 'application/json' // Establece el tipo de contenido esperado de la respuesta.
        }
    }).then(response => response.data).catch(error => {
        // Maneja errores en la petición y devuelve un objeto de error.
        return { status: 400, error: true, details: `name =>: ${error.name} - code =>: ${error.code} - message =>: ${error.message}` };
    });*/


    try {
        // Realiza la solicitud POST y maneja la respuesta.
        const response = await http.post(url, postData, {
            headers: {
                ...authorization,
                'Content-Type': 'application/json' // Establece el tipo de contenido esperado de la respuesta.
            }
        });
        res.json(response.data); // Envía la respuesta del servidor al cliente.
    } catch (error) {
        // Maneja errores en la petición y devuelve un objeto de error.
        {
            // Maneja errores en la petición y devuelve un objeto de error.
            res.status(400).json({
                status: 400,
                error: true,
                details: {
                    name: error.name,
                    code: error.code,
                    message: error.message,
                    response: error.response ? {
                        status: error.response.status,
                        data: error.response.data,
                        headers: error.response.headers
                    } : null // Si hay una respuesta del servidor, inclúyela en el error
                }
            });
        }
    }

});