const express = require('express');
const OAuth = require('oauth-1.0a');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const axios = require('axios');
const rateLimit = require('axios-rate-limit');
const axiosRetry = require('axios-retry').default;
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
dotenv.config();

// Creación de una instancia de Express para gestionar las solicitudes HTTP.
const app = express();
const port = 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const USERS_DATA = process.env.USERS_DATA;
console.log(USERS_DATA);
// Middleware de Express para analizar cuerpos de solicitud JSON automáticamente.
app.use(bodyParser.json());

/*const http = rateLimit(axios.create(), { maxRequests: 10, perMilliseconds: 60000 });
// Configuración de reintentos automáticos para el cliente Axios para manejar fallos temporales en las peticiones.
axiosRetry(http, {
    retries: 10
});*/

//Configuración por defecto.
let http = rateLimit(axios.create(), { maxRequests: 10, perMilliseconds: 60000 });

app.post('/netsuite-trigger', async (req, res) => {
    
    const data = req.body; // Datos recibidos en el cuerpo de la solicitud.
    const arrayId = data['arrayId']; // Array de IDs que se obtienen del cuerpo de la solicitud.

    http = rateLimit(axios.create(), { maxRequests: data['maxRequests'], perMilliseconds: data['perMilliseconds'] });

    console.log(`retries: ${data['retries']} - maxRequests: ${data['maxRequests']} - perMilliseconds: ${data['perMilliseconds']}`)
    // Configuración de reintentos automáticos para el cliente Axios para manejar fallos temporales en las peticiones.
    axiosRetry(http, {
        retries: data['retries']
    });

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

// Ruta de inicio de sesión para obtener un token JWT
app.post('/login', async (req, res) => {

    const { username, password } = req.body;
    const respuesta = await axios.get(USERS_DATA);
    console.log(`User data query status => ${respuesta[`status`]}`);
    if (respuesta[`status`] == 200)
    {
        console.log(`Users data => ${JSON.stringify(respuesta[`data`])}`)
        if (respuesta[`data`].length > 0)
        {
            let filter = respuesta[`data`].filter(element => (element[`user`] === username && element[`password`] === password));

            if (filter.length > 0)
            {
                const user = { name: username };
                const accessToken = jwt.sign(user, JWT_SECRET, { expiresIn: `5m` });
                //console.log(`accessToken: ${accessToken}`)
                res.json({ error: false, message: `Usuario autenticado`, token: accessToken });
            }
            else
            {
                res.status(401).json({ error: true, message: `Usuario & contraseña incorrecta`, token: null });
            }
        }
    }
    else
    {
        res.status(401).json({ error: true, message: `Error al consultar usuario y contraseña`, token: null });
    }
    /*// En un entorno real, deberías verificar el usuario y la contraseña con la base de datos

    
    if (username === `user` && password === `password`)
    {
        const user = { name: username };
        const accessToken = jwt.sign(user, JWT_SECRET, { expiresIn: `5m` });
        //console.log(`accessToken: ${accessToken}`)
        res.json({ error: false, message: `Usuario autenticado`, token: accessToken });
    } else {
        res.status(401).json({ error: true, message: `Usuario & contraseña incorrecta`, token: null });
    }*/
});

function validateToken(req, res, next) {

    const accessToken = req.headers['authorization'];

    if (!accessToken) res.status(401).send(`Access denegado, no se recibio token de autorización`);

    jwt.verify(accessToken, JWT_SECRET, (err, user) => {
        if (err) { 
            res.status(401).send(`Access denied, token expirado or incorrecto`)
        }
        else{
            req.user = user;
            next();
        }
            //return res.sendStatus(403);
        //req.user = user;
        //next();
    });
}

// Ruta protegida que requiere autenticación
app.get('/protected', validateToken, (req, res) => {
    res.json({
        message: `This is a protected route`,
        username: req[`user`]
    });
});

// Inicia el servidor en el puerto especificado y muestra un mensaje en la consola.
app.listen(port, () => {
    console.log(`Servidor corriendo en http://localhost:${port}`);
});
