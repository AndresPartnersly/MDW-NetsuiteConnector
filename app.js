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
dotenv.config();

// Creación de una instancia de Express para gestionar las solicitudes HTTP.
const app = express();
const port = 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const USERS_DATA = process.env.USERS_DATA;
const PRODUCT_CONFIGURATION = process.env.PRODUCT_CONFIGURATION;
const BASE_URL = process.env.BASE_URL;
const FIELDSET = process.env.FIELDSET;

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
        const authorization = oauth.toHeader(oauth.authorize({ url, method: 'GET' }, token)); // Genera el encabezado de autorización.
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
    if (respuesta[`status`] == 200) {
        console.log(`Users data => ${JSON.stringify(respuesta[`data`])}`)
        if (respuesta[`data`].length > 0) {
            let filter = respuesta[`data`].filter(element => (element[`user`] === username && element[`password`] === password));

            if (filter.length > 0) {
                const user = { name: username };
                const accessToken = jwt.sign(user, JWT_SECRET, { expiresIn: `5m` });
                //console.log(`accessToken: ${accessToken}`)
                res.json({ error: false, message: `Usuario autenticado`, token: accessToken });
            }
            else {
                res.status(401).json({ error: true, message: `Usuario & contraseña incorrecta`, token: null });
            }
        }
    }
    else {
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
        else {
            req.user = user;
            next();
        }
    });
}

//
app.get('/protected', validateToken, (req, res) => {
    res.json({
        message: `This is a protected route`,
        username: req[`user`]
    });
});

//
app.get('/products', async (req, res) => {

    let serviceResponse = { error: true, message: ``, customerId: null };

    try {

        const respuesta = await axios.get(PRODUCT_CONFIGURATION);
        let parsedResponse = respuesta.data;
        let responseCode = respuesta.status;
        //console.log(`173. Response: ${JSON.stringify(parsedResponse)}`);
        console.log(`Product configuration query status => ${respuesta[`status`]}`);

        if (responseCode == 200) {

            let responseConfig = parsedResponse.configuration;
            //console.log(`179. Response Config: ${JSON.stringify(responseConfig)}`);

            if (!isEmpty(responseConfig)) {

                let userId = 'xxxxxxxxx';
                serviceResponse.customerId = userId;
                let customerData = responseConfig.filter(element => (element[`customerId`] === userId));
                //console.log(`199. customerData Result: ${JSON.stringify(customerData)}`);
                if (customerData.length > 0) {

                    let customerId = customerData[0].customerId;
                    console.log(`193. Autenticación satisfactoria | Usuario: ${customerId}.`);

                    let locationsConfig = customerData[0].configLocationData; // Array
                    console.log(`196. Locations Config: ${JSON.stringify(locationsConfig)}`);

                    if (!isEmpty(locationsConfig)) {

                        let priceLevelConfig = customerData[0].configPriceLevelData; // Array
                        console.log(`201. Price Level Config: ${JSON.stringify(priceLevelConfig)}`);

                        if (!isEmpty(priceLevelConfig)) {

                            let priceLevelId = priceLevelConfig[0].priceLevelId;
                            let baseUrl = `${BASE_URL}?fieldset=${FIELDSET}&limit=100&offset=0`;
                            console.log(`202. BaseUrl: ${baseUrl}`);
                            let itemsParameter = customerData[0].itemsId;
                            let customerItemsArray = itemsParameter.split(',');
                            let customerItemsQty = customerItemsArray.length;
                            console.log(`206. Items disponibles para el cliente ${customerItemsQty}`)//: ${JSON.stringify(customerItemsArray)})

                            if (!isEmpty(itemsParameter) && !isEmpty(customerItemsArray)) {

                                let cantidadIteraciones = 1;
                                let itemsProcesar = null;
                                let itemsResultArray = [];

                                if (customerItemsQty > 100) {
                                    itemsProcesar = arraySplit(customerItemsArray, 100);
                                    //console.log(`216. Items a procesar: ${JSON.stringify(itemsProcesar)}`);
                                    cantidadIteraciones = itemsProcesar.length;
                                }

                                console.log(`217. Cantidad de iteraciones: ${cantidadIteraciones}`);

                                for (let i = 0; i < cantidadIteraciones; i++) {

                                    //console.log(`222. Line: ${i} | Ids a procesar (${itemsProcesar[i].length}): ${JSON.stringify(itemsProcesar[i])}`);
                                    let itemsIds = itemsProcesar[i].toString().replace(`"`, ``).replace(`[`, ``).replace(`]`, ``);
                                    //console.log(`227. ItemIds: ${itemsIds}`);
                                    let nsRequestUrl = `${baseUrl}&id=${itemsIds}`;
                                    const nsResponse = await axios.get(nsRequestUrl);
                                    let nsResponseData = nsResponse.data;
                                    let nsResposeCode = nsResponse.status;
                                    console.log(`232. Line ${i} | NetSuite Response: ${nsResposeCode}`);
                                    //console.log(`233. NetSuite Response Data: ${JSON.stringify(nsResponseData)}`);

                                    if (nsResposeCode == 200) {

                                        let nsResponseItems = nsResponseData.items;
                                        console.log(`238. Line ${i} | NetSuite Response Items Quantity: ${nsResponseItems.length}`);

                                        if (nsResponseItems.length > 0) {
                                            itemsResultArray = itemsResultArray.concat(nsResponseItems);
                                        }
                                    }
                                    else {
                                        serviceResponse.message = `Error: el servicio de SuiteCommerce no se ejecuto correctamente. Code: ${nsResposeCode}.`
                                        res.status(401).json(serviceResponse);
                                    }
                                }

                                console.log(`245. Final Items Array Quantity: ${itemsResultArray.length}`); //${JSON.stringify(itemsResultArray)}

                                if (itemsResultArray.length > 0) {

                                    let itemsFilter = itemsResultArray.filter(element => (element.isinstock == true));
                                    console.log(`250. Items in Stock: ${itemsFilter.length} | ${JSON.stringify(itemsFilter)}`);

                                    let outputArray = [];

                                    if (itemsFilter.length > 0) {
                                        for (let i = 0; i < itemsFilter.length; i++) {

                                            let obj = {
                                                id: itemsFilter[i].internalid,
                                                name: itemsFilter[i].itemid,
                                                full_name: itemsFilter[i].displayname,
                                                upc_code: itemsFilter[i].upccode,
                                                marca: itemsFilter[i].custitem_marca,
                                                price: null,
                                                in_stock: false
                                            };

                                            if (itemsFilter[i].hasOwnProperty(priceLevelId)) {
                                                obj.price = itemsFilter[i][`${priceLevelId}`];
                                            }

                                            for (let b = 0; b < locationsConfig.length; b++) {

                                                let locationId = locationsConfig[b].nsLocationId;
                                                console.log(`269. Line: ${i}_${b} | Location: ${locationId}`);
                                                let locationStockPercent = parseFloat(locationsConfig[b].stockPercent);
                                                let locationStockMax = parseFloat(locationsConfig[b].stockMax);
                                                console.log(`272. Line: ${i}_${b} | Location Stock Percent: ${locationStockPercent} | Location Stock Max: ${locationStockMax}`);

                                                let itemLocations = itemsFilter[i].quantityavailable_detail.locations; // Array
                                                console.log(`275. Line: ${i}_${b} | Item Locations: ${JSON.stringify(itemLocations)}`);
                                                let itemLocFilter = itemLocations.filter(element => (element.internalid == locationId));
                                                console.log(`277. Line: ${i}_${b} | ItemLocFilter: ${JSON.stringify(itemLocFilter)}`);

                                                if (itemLocFilter.length > 0) {

                                                    let quantityAvailable = itemLocFilter[0].quantityavailable;
                                                    console.log(`282. Line: ${i}_${b} | Location Available Quantity: ${quantityAvailable}`);

                                                    if (quantityAvailable > 0 && obj.price != null) {
                                                        obj.in_stock = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            outputArray.push(obj);
                                        }

                                        console.log(`310. Servicio correctamente ejecutado`);
                                        serviceResponse.error = false;
                                        serviceResponse.message = `Solicitud realizada con exito`;
                                        serviceResponse.quantity = outputArray.length;
                                        serviceResponse.items = outputArray;
                                        res.status(200).json(serviceResponse);
                                    }
                                    else {
                                        serviceResponse.message = `No se encontraron articulos en stock.`
                                        res.status(200).json(serviceResponse);
                                    }
                                }
                                else {
                                    serviceResponse.message = `No se pudo encontro ninguno de los articulos asociados a cuenta del cliente.`
                                    res.status(401).json(serviceResponse);
                                }
                            }
                            else {
                                serviceResponse.message = `No se pudo obtener configuracion de articulos disponibles.`
                                res.status(401).json(serviceResponse);
                            }
                        }
                        else {
                            serviceResponse.message = `No se pudo obtener configuracion de listas de precios.`
                            res.status(401).json(serviceResponse);
                        }
                    }
                    else {
                        serviceResponse.message = `No se pudo obtener configuracion de localizaciones.`
                        res.status(401).json(serviceResponse);
                    }
                }
                else {
                    serviceResponse.message = `Credenciales no autorizadas.`
                    res.status(500).json(serviceResponse);
                }
            }
            else {
                serviceResponse.message = `No se pudo obtener atributo de configuracion de usuarios.`
                res.status(401).json(serviceResponse);
            }
        }
        else {
            serviceResponse.message = `No se pudo consultar servicio de configuracion de credenciales.`
            res.status(401).json(serviceResponse);
        }
    }
    catch (e) {

        let errorMsg = null;

        console.log(`Error: ${JSON.stringify(e)}`);
        console.log(`Error: ${e.message}`);

        if (!isEmpty(e.message)) {
            errorMsg = e.message;
        }
        else {
            errorMsg = JSON.stringify(e)
        }

        serviceResponse.message = errorMsg;
        res.status(401).json(serviceResponse);
    }
});

// Inicia el servidor en el puerto especificado y muestra un mensaje en la consola.
app.listen(port, () => {
    console.log(`Servidor corriendo en http://localhost:${port}`);
});

let isEmpty = (value) => {

    if (value === ``)
        return true;

    if (value === null)
        return true;

    if (value === undefined)
        return true;

    if (value === `undefined`)
        return true;

    if (value === `null`)
        return true;

    return false;
}

let arraySplit = (array, chunkSize) => {
    let chunks = [];
    for (let i = 0; i < array.length; i += chunkSize) {
        chunks.push(array.slice(i, i + chunkSize));
    }
    return chunks;
}