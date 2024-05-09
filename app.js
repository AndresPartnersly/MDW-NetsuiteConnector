const express = require('express');
const OAuth = require('oauth-1.0a');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const axios = require('axios');
const rateLimit = require('axios-rate-limit');
const axiosRetry = require('axios-retry').default;

// Creación de una instancia de Express para gestionar las solicitudes HTTP.
const app = express();
const port = 3000;

// Middleware de Express para analizar cuerpos de solicitud JSON automáticamente.
app.use(bodyParser.json());

const http = rateLimit(axios.create(), { maxRequests: 15, perMilliseconds: 30000 });
// Configuración de reintentos automáticos para el cliente Axios para manejar fallos temporales en las peticiones.
axiosRetry(http, {
    retries: 10
});

app.post('/netsuite-trigger', async (req, res) => {
    
    const data = req.body; // Datos recibidos en el cuerpo de la solicitud.
    const arrayId = data['arrayId']; // Array de IDs que se obtienen del cuerpo de la solicitud.

    // Verifica si el arrayId es válido y contiene elementos.
    if (!arrayId || arrayId.length === 0) {
        return res.status(400).json({ error: "No se recibieron elementos en el atributo 'arrayId'." });
    }

    // Responder inmediatamente al cliente que la solicitud ha sido recibida
    res.status(202).json({ status: 202, error: false, details: `Solicitud recibida, procesando información.` });
    // Continuar con el procesamiento en segundo plano
    processRequest(data, arrayId);
});

function processRequest(data, arrayId) {
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

    // Mapa de IDs a peticiones HTTP individuales utilizando Axios con autenticación OAuth.
    const requests = arrayId.map(id => {
        const url = `${data['url']}&id=${id}`; // Construye la URL para cada ID.
        const authorization = oauth.toHeader(oauth.authorize({url, method: 'GET'}, token)); // Genera el encabezado de autorización.
        authorization['Authorization'] += `, realm="${data['realm']}"`; // Añade 'realm' al encabezado de autorización.

        // Realiza la petición GET y maneja la respuesta o errores.
        return http.get(url, {
            headers: {
                ...authorization,
                'Content-Type': 'application/json' // Establece el tipo de contenido esperado de la respuesta.
            }
        }).then(response => response.data).catch(error => {
            // Maneja errores en la petición y devuelve un objeto de error.
            return { status: 400, error: true, details: `name =>: ${error.name} - code =>: ${error.code} - message =>: ${error.message}`, id: id };
        });
    });

    // Espera que todas las peticiones se completen y luego envía la respuesta global.
    Promise.all(requests)
        .then(results => {
            console.log("Procesamiento completado:", results);
            // Aquí podrías, por ejemplo, enviar estos resultados a otro sistema o almacenarlos en una base de datos
        })
        .catch(error => {
            console.error("Error procesando las solicitudes:", error);
        });
}

// Inicia el servidor en el puerto especificado y muestra un mensaje en la consola.
app.listen(port, () => {
    console.log(`Servidor corriendo en http://localhost:${port}`);
});
