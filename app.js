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
    console.log(`Servidor corriendo en http://localhost:${port}`);
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

function validateToken(req, res, next) {

    let serviceResponse = { error: true, message: ``, token: null }

    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    console.log(`150. Access Token: ${JSON.stringify(token)}`);


    if (!token) {
        serviceResponse.message = `Access denegado, no se recibio token de autorización`;
        res.status(401).json(serviceResponse);
    }
    else {
        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) {
                console.log(`156. Error: ${JSON.stringify(err)}`);
                serviceResponse.message = `Acceso denegado, token expirado o incorrecto`;
                res.status(401).json(serviceResponse);
            }
            else {
                req.user = user;
                next();
            }
        });
    }
}

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

// Ruta de inicio de sesión para obtener un token JWT
app.post('/login', async (req, res) => {

    const { username, password } = req.body;
    console.log(`110. Request Body: ${JSON.stringify(req.body)}`);
    const respuesta = await axios.get(USERS_DATA);
    console.log(`User data query status => ${respuesta[`status`]}`);
    if (respuesta[`status`] == 200) {
        console.log(`Users data => ${JSON.stringify(respuesta[`data`])}`)
        if (respuesta[`data`].length > 0) {
            let filter = respuesta[`data`].filter(element => (element[`user`] === username && element[`password`] === password));

            if (filter.length > 0) {
                const user = { name: username, password: password };
                const accessToken = jwt.sign(user, JWT_SECRET, { expiresIn: `5m` });
                //console.log(`accessToken: ${accessToken}`)
                res.json({ error: false, message: `Usuario autenticado`, token: accessToken });
            }
            else {
                res.status(401).json({ error: true, message: `Usuario o contraseña incorrecta`, token: null });
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

app.post('/update_config_file', async (req, res) => {

    let serviceResponse = { error: true, message: `` }

    try {

        const reqBody = req.body;
        console.log(`180. Request Body Length: ${reqBody.length}`);

        if (reqBody.hasOwnProperty('data')) {

            let newContent = reqBody.data;
            console.log(`187. Configuration Array Length: ${newContent.length}`);

            if (Array.isArray(newContent) && newContent.length > 0) {

                let continueValidator = true;

                for (let i = 0; i < newContent.length; i++) {

                    let object = newContent[i];
                    console.log(`196. ${typeof newContent[i].user}`);
                    if (object.hasOwnProperty('user')) {
                        if (typeof newContent[i].user != 'string' || newContent[i].user == '') {
                            continueValidator = false;
                            serviceResponse.message = `El atributo 'user' en posicion ${i} debe ser de tipo string y no estar vacio`;
                            break;
                        }
                    }
                    else {
                        continueValidator = false;
                        serviceResponse.message = `El objeto en posicion ${i} no tiene atributo 'user'.`;
                        break;
                    }
                    if (object.hasOwnProperty('configuration')) {
                        if (!Array.isArray(newContent[i].configuration) || newContent[i].configuration.length <= 0) {
                            continueValidator = false;
                            serviceResponse.message = `El atributo 'configuration' en posicion ${i} debe ser un array y contener por lo menos un objeto.`;
                            break;
                        }
                    }
                    else {
                        continueValidator = false;
                        serviceResponse.message = `El objeto en posicion ${i} no tiene atributo 'configuration'.`;
                        break;
                    }
                }

                if (continueValidator == true) {

                    console.log(`New Content: ${JSON.stringify(newContent)}`);
                    let textContent = JSON.stringify(newContent);

                    if (isEmpty(textContent)) {
                        serviceResponse.message = 'No se pudo procesar el contenido recibido.'
                        console.error(`Response code: 500 | ${serviceResponse.message}`);
                        return res.status(500).json(serviceResponse);
                    }
                    else {
                        fs.writeFile(filePath, textContent, (err) => {

                            if (err) {
                                serviceResponse.message = 'Error al sobreescribir el archivo.'
                                console.error(`Response code: 500 | ${serviceResponse.message}`);
                                return res.status(500).json(serviceResponse);
                            }
                            else {
                                serviceResponse.error = false;
                                serviceResponse.message = 'Archivo actualizado exitosamente.';
                                console.log(`198. Response code: 200 | ${serviceResponse.message}`);
                                res.status(200).json(serviceResponse);
                            }
                        });
                    }
                }
                else {
                    console.error(`Response code: 400 | ${serviceResponse.message}`);
                    return res.status(400).json(serviceResponse);
                }
            }
            else {
                serviceResponse.message = `El atributo 'data' debe ser un array de objetos y no puede estar vacio`;
                console.error(`Response code: 500 | ${serviceResponse.message}`);
                return res.status(500).json(serviceResponse);
            }
        }
        else {
            serviceResponse.message = `Se debe incluir el atributo 'data' en el body de la solicitud`;
            console.error(`Response code: 400 | ${serviceResponse.message}`);
            return res.status(400).json(serviceResponse);
        }
    }
    catch (e) {
        serviceResponse.message = `${e.message}`;
        console.error(`Error: ${e.message}`);
        res.status(500).json(serviceResponse);
    }
});

//
app.get('/protected', validateToken, (req, res) => {

    console.log(`Headers: ${JSON.stringify(req.headers)}`);

    res.json({
        message: `This is a protected route`,
        username: req[`user`],
        password: req[`password`]
    });
});

//
app.get('/products', validateToken, async (req, res) => {

    let expectedHeaders = {
        user: null,
        password: null
    } // Variable unicamente utilizada como referencia

    let serviceResponse = { error: true, message: `` };
    let requestHeaders = req.headers;
    //console.log(`180. Request Data: ${req}`); No se puede logear objeto por dependencia circular
    console.log(`304. Request Headers: ${JSON.stringify(requestHeaders)}`);

    try {

        let requestUser = req.user.name;
        let requestPassword = req.user.password;
        console.log(`310. Request Credentials Index | User: ${JSON.stringify(requestUser)} | Password: ${JSON.stringify(requestPassword)}`);

        if (!isEmpty(requestUser) && !isEmpty(requestPassword)) {

            let userId = requestUser;
            let usersDataQuery = await axios.get(USERS_DATA); // Se obtiene informacion de base de datos de clientes
            let usersDataparsedResponse = usersDataQuery.data;
            let usersDataResponseCode = usersDataQuery.status;
            console.log(`318. Users Data Query Response => ${usersDataResponseCode} | Data: ${JSON.stringify(usersDataparsedResponse)}`);

            if (usersDataResponseCode == 200) {

                let usersDataFilter = usersDataparsedResponse.filter(element => element.user == requestUser && element.password == requestPassword);
                // Se compara usuario que realiza el request con base de datos de clientes
                console.log(`324. User Filter: ${JSON.stringify(usersDataFilter)}`);

                if (usersDataFilter.length > 0) {

                    console.log(`328. Usuario autenticado correctamente.`);
                    let parsedResponse = await leerArchivoYParsearJSON(filePath);
                    console.log(`330. Database File (${parsedResponse.length}): ${JSON.stringify(parsedResponse)}`);

                    if (!isEmpty(parsedResponse)) {

                        let customerData = parsedResponse.filter(element => (element[`user`] === userId));
                        console.log(`335. customerData Result: ${JSON.stringify(customerData)}`);
                        if (customerData.length > 0) {

                            let customerId = customerData[0].user;
                            console.log(`339. Autenticación satisfactoria | Usuario: ${customerId}.`);
                            let customerConfiguration = customerData[0].configuration;

                            let locationsConfig = customerConfiguration[0].configLocationData; // Array
                            console.log(`343. Locations Config: ${JSON.stringify(locationsConfig)}`);

                            if (!isEmpty(locationsConfig)) {

                                let priceLevelConfig = customerConfiguration[0].configPriceLevelData; // Array
                                console.log(`348. Price Level Config: ${JSON.stringify(priceLevelConfig)}`);

                                if (!isEmpty(priceLevelConfig)) {

                                    let standardPrice = null;
                                    let specialPrice = null;

                                    for (let i = 0; i < priceLevelConfig.length; i++) {

                                        let priceLevelType = priceLevelConfig[i].intPriceLevelId;
                                        let priceLevel = priceLevelConfig[i].priceLevelId;

                                        console.log(`360. Line: ${i} | Price Level Type: ${priceLevelType} | Price Id: ${priceLevel}`);

                                        if (priceLevelType == 'price') {
                                            standardPrice = priceLevel;
                                        }
                                        else if (priceLevelType == 'special_price') {
                                            specialPrice = priceLevel;
                                        }
                                        else {
                                            serviceResponse.message = `Error al obtener informacion de listas de precios en configuracion.`
                                            res.status(500).json(serviceResponse);
                                        }
                                    }

                                    if (!isEmpty(standardPrice)) {

                                        let baseUrl = `${BASE_URL}?fieldset=${FIELDSET}&limit=100&offset={offset_value}&currency=USD`;
                                        let firstBaseUrl = baseUrl.replace('{offset_value}', `0`);
                                        console.log(`377. BaseUrl: ${baseUrl} | First Base Url: ${firstBaseUrl}`);

                                        let cantidadIteraciones = 1;
                                        const nsItemsData = await axios.get(firstBaseUrl);
                                        //console.log(`Ns Response: ${JSON.stringify(nsResponse.data)}`);

                                        if (!isEmpty(nsItemsData)) {

                                            let itemsResultArray = nsItemsData.data.items;
                                            let itemsProcesarQty = nsItemsData.data.total;
                                            console.log(`387. Cantidad de articulos obtenidos de NetSuite: ${itemsProcesarQty}`);

                                            if (itemsProcesarQty > 100) {
                                                //itemsProcesar = arraySplit(itemsResultArray, 100);
                                                //console.log(`369. Items a procesar: ${JSON.stringify(itemsProcesar)}`);
                                                let itemsProcesar = Math.floor(itemsProcesarQty / 100);
                                                cantidadIteraciones = itemsProcesar;
                                            }

                                            console.log(`396. Cantidad de iteraciones: ${cantidadIteraciones}`);

                                            for (let i = 1; i <= cantidadIteraciones; i++) {

                                                let calculo = i * 100;
                                                let nsRequestUrl = baseUrl.replace('{offset_value}', `${calculo}`);
                                                console.log(`401. Line: ${i} | New Request Url: ${nsRequestUrl}`);
                                                const nsResponse = await axios.get(nsRequestUrl);

                                                let nsResponseData = nsResponse.data;
                                                let nsResposeCode = nsResponse.status;
                                                console.log(`406. Line ${i} | NetSuite Response: ${nsResposeCode}`);
                                                //console.log(`272. NetSuite Response Data: ${JSON.stringify(nsResponseData)}`);

                                                if (nsResposeCode == 200) {

                                                    let nsResponseItems = nsResponseData.items;
                                                    console.log(`412. Line ${i} | NetSuite Response Items Quantity: ${nsResponseItems.length}`);

                                                    if (nsResponseItems.length > 0) {
                                                        itemsResultArray = itemsResultArray.concat(nsResponseItems);
                                                    }
                                                }
                                                else {
                                                    serviceResponse.message = `Error: el servicio de SuiteCommerce no se ejecuto correctamente. Code: ${nsResposeCode}.`
                                                    res.status(500).json(serviceResponse);
                                                }
                                            }

                                            console.log(`425. Final Items Array Quantity: ${itemsResultArray.length}`);
                                            //console.log(`426. Final Items Array: ${JSON.stringify(itemsResultArray)}`);

                                            if (itemsResultArray.length > 0) {

                                                let itemsFilter = itemsResultArray.filter(element => (element.isinstock == true));
                                                console.log(`429. Items in Stock: ${itemsFilter.length}`);

                                                let outputArray = [];

                                                if (itemsFilter.length > 0) {
                                                    for (let i = 0; i < itemsFilter.length; i++) {

                                                        if (itemsFilter[i].hasOwnProperty('custitem_ptly_mgt_web_sites')) {

                                                            let itemWebsites = itemsFilter[i].custitem_ptly_mgt_web_sites.split(',');
                                                            //console.log(`381. ItemWebsites: ${JSON.stringify(itemWebsites)}`)
                                                            let webSiteFilter = itemWebsites.filter(element => limpiarString(element) == WEBSITE_ID);
                                                            console.log(`445. Items Disponibles en Web: ${webSiteFilter.length}`);

                                                            if (webSiteFilter.length > 0) {

                                                                let obj = {
                                                                    id: itemsFilter[i].internalid,
                                                                    sku: itemsFilter[i].itemid,
                                                                    display_name: itemsFilter[i].storedisplayname2,
                                                                    marca: itemsFilter[i].custitem_marca,
                                                                    upc_code: itemsFilter[i].upccode
                                                                };

                                                                if (itemsFilter[i].hasOwnProperty('mpn')) {
                                                                    obj.modelo = itemsFilter[i].mpn;
                                                                }

                                                                if (itemsFilter[i].hasOwnProperty('vendorname')) {
                                                                    obj.vendor_name = itemsFilter[i].vendorname;
                                                                }

                                                                let standardPriceValue = 0;
                                                                let specialPriceValue = null;

                                                                if (itemsFilter[i].hasOwnProperty(standardPrice)) {

                                                                    standardPriceValue = itemsFilter[i][standardPrice];

                                                                    if (!isEmpty(specialPrice)) {
                                                                        if (itemsFilter[i].hasOwnProperty(specialPrice)) {
                                                                            specialPriceValue = itemsFilter[i][specialPrice];
                                                                        }
                                                                    }

                                                                    if (specialPriceValue != null && specialPriceValue != 0 && specialPriceValue < standardPriceValue) {
                                                                        obj.price = specialPriceValue;
                                                                    }
                                                                    else {
                                                                        obj.price = standardPriceValue;
                                                                    }
                                                                }
                                                                else {
                                                                    obj.price = null;
                                                                }

                                                                obj.in_stock = false;

                                                                if (itemsFilter[i].hasOwnProperty('quantityavailable_detail')) {

                                                                    let quantityAvailable = itemsFilter[i].quantityavailable_detail;

                                                                    if (quantityAvailable.hasOwnProperty('quantityavailable') && quantityAvailable.hasOwnProperty('locations')) {
                                                                        if (quantityAvailable.quantityavailable > 0 && quantityAvailable.locations.length > 0) {

                                                                            for (let b = 0; b < locationsConfig.length; b++) {

                                                                                let locationId = locationsConfig[b].nsLocationId;
                                                                                let locationStockPercent = parseFloat(locationsConfig[b].stockPercent);
                                                                                let locationStockMax = locationsConfig[b].stockMax;
                                                                                //console.log(`495. Line: ${i}_${b} | Location: ${locationId}`);

                                                                                if (!isEmpty(locationId) && !isEmpty(locationStockPercent)) {

                                                                                    for (let c = 0; c < quantityAvailable.locations.length; c++) {

                                                                                        let itemLocFilter = quantityAvailable.locations.filter(element => element.internalid == locationId);

                                                                                        if (itemLocFilter.length > 0) {

                                                                                            let itemLocQty = quantityAvailable.locations[c].quantityavailable;
                                                                                            let calculo = itemLocQty * locationStockPercent;

                                                                                            if (calculo > 0) {
                                                                                                if (!isEmpty(locationStockMax)) {
                                                                                                    if (calculo < locationStockMax) {
                                                                                                        obj.in_stock = true;
                                                                                                    }
                                                                                                }
                                                                                                else {
                                                                                                    obj.in_stock = true;
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }

                                                                if (itemsFilter[i].hasOwnProperty('taxschedule')) {

                                                                    let taxResult = null;
                                                                    // Valores fijos actualmente
                                                                    if (itemsFilter[i].taxschedule == "IVA REDUCIDO") {
                                                                        taxResult = '10.5%';
                                                                        obj.tax = taxResult;
                                                                    }
                                                                    else if (itemsFilter[i].taxschedule == "IVA GENERAL") {
                                                                        taxResult = '21%';
                                                                        obj.tax = taxResult;
                                                                    }
                                                                    else if (itemsFilter[i].taxschedule == "IVA ESPECIAL") {
                                                                        taxResult = '27%';
                                                                        obj.tax = taxResult;
                                                                    }
                                                                    else if (itemsFilter[i].taxschedule == "EXENTO") {
                                                                        taxResult = '0%';
                                                                        obj.tax = taxResult;
                                                                    }
                                                                }

                                                                if (itemsFilter[i].hasOwnProperty('custitem_3k_porc_imp_int')) {
                                                                    obj.imp_interno = itemsFilter[i].custitem_3k_porc_imp_int;
                                                                }
                                                                else {
                                                                    obj.imp_interno = `0%`
                                                                }

                                                                if (itemsFilter[i].hasOwnProperty('custitem_ptly_ancho_cm')) {
                                                                    obj.ancho_cm = itemsFilter[i].custitem_ptly_ancho_cm;
                                                                }

                                                                if (itemsFilter[i].hasOwnProperty('custitem_ptly_largo_cm')) {
                                                                    obj.largo_cm = itemsFilter[i].custitem_ptly_largo_cm;
                                                                }

                                                                if (itemsFilter[i].hasOwnProperty('custitem_ptly_alto_cm')) {
                                                                    obj.alto_cm = itemsFilter[i].custitem_ptly_alto_cm;
                                                                }

                                                                if (itemsFilter[i].hasOwnProperty('custitem_ptly_peso_kg')) {
                                                                    obj.peso_kg = itemsFilter[i].custitem_ptly_peso_kg;
                                                                }

                                                                if (itemsFilter[i].hasOwnProperty('itemimages_detail')) {

                                                                    let imagenes = itemsFilter[i].itemimages_detail;

                                                                    if (imagenes.hasOwnProperty('urls')) {
                                                                        if (imagenes.urls.length > 0) {
                                                                            obj.imagenes = imagenes.urls;
                                                                        }
                                                                    }
                                                                }

                                                                outputArray.push(obj);
                                                            }
                                                            else {

                                                            }
                                                        }
                                                    }

                                                    console.log(`410. Servicio correctamente ejecutado | Resultado: ${outputArray.length} articulos`);
                                                    serviceResponse.error = false;
                                                    serviceResponse.message = `Solicitud realizada con exito`;
                                                    serviceResponse.result = outputArray.length;
                                                    serviceResponse.items = outputArray;
                                                    res.status(200).json(serviceResponse);
                                                }
                                                else {
                                                    serviceResponse.result = 0;
                                                    serviceResponse.items = [];
                                                    serviceResponse.message = `No se encontraron articulos en stock.`
                                                    res.status(204).json(serviceResponse);
                                                }
                                            }
                                            else {
                                                serviceResponse.message = `Ocurrio un error inesperado al segmentar informacion de articulos del sistema.`
                                                res.status(500).json(serviceResponse);
                                            }
                                        }
                                        else {
                                            serviceResponse.message = `Error al obtener informacion de articulos del sistema.`
                                            res.status(500).json(serviceResponse);
                                        }
                                    }
                                    else {
                                        serviceResponse.message = `Error al obtener informacion de listas de precios en configuracion.`
                                        res.status(500).json(serviceResponse);
                                    }
                                }
                                else {
                                    serviceResponse.message = `No se pudo obtener configuracion de listas de precios.`
                                    res.status(500).json(serviceResponse);
                                }
                            }
                            else {
                                serviceResponse.message = `No se pudo obtener configuracion de localizaciones.`
                                res.status(500).json(serviceResponse);
                            }
                        }
                        else {
                            serviceResponse.message = `No se encontro configuracion para el usuario autenticado.`
                            res.status(500).json(serviceResponse);
                        }
                    }
                    else {
                        serviceResponse.message = `No se pudo consultar base de datos de usuarios.`
                        res.status(500).json(serviceResponse);
                    }
                }
                else {
                    serviceResponse.message = `Credenciales incorrectas o no autorizadas`
                    res.status(401).json(serviceResponse);
                }
            }
            else {
                serviceResponse.message = `No se pudo realizar consulta a base de datos de clientes.`
                res.status(500).json(serviceResponse);
            }
        }
        else {
            serviceResponse.message = `Ocurrio un error al intentar procesar las credenciales de la solicitud.`
            res.status(500).json(serviceResponse);
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

app.get('/product_config', async (req, res) => {

    let serviceResponse = { error: true, message: '' };

    try {

        let fileData = await leerArchivoYParsearJSON(filePath);

        if (!isEmpty(fileData)) {

            let fileString = JSON.stringify(fileData);
            console.log(`601. File String: ${fileString}`);

            serviceResponse.error = false;
            serviceResponse.message = `Solicitud realizada con exito.`;
            serviceResponse.quantity = fileData.length;
            serviceResponse.body = fileData;
            console.log(`607. ${serviceResponse.message}`);
            res.status(200).json(serviceResponse);

        }
        else {
            serviceResponse.message = `No se encontro informacion en archivo de datos de configuracion`;
            console.error(`Error: ${serviceResponse.message}`);
            res.status(500).json(serviceResponse)
        }
    }
    catch (e) {
        console.error(`Error: ${e.message}`);
        serviceResponse.message = e.message;
        res.status(500).json(serviceResponse)
    }
})

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

/*let arraySplit = (array, chunkSize) => {
    let chunks = [];
    for (let i = 0; i < array.length; i += chunkSize) {
        chunks.push(array.slice(i, i + chunkSize));
    }
    return chunks;
}*/

let limpiarString = (value) => {
    const regularExp = /[^a-z0-9| ,]/gi;
    return value.toString().replace(regularExp, ``).trim();
}

let leerArchivoYParsearJSON = (filePath) => {

    let message = ``;
    console.log(`657. File Path: ${filePath}`);

    return new Promise((resolve, reject) => {
        fs.readFile(filePath, 'utf8', (err, data) => {
            console.log(`661. Data: ${JSON.stringify(data)}`);
            if (err) {
                message = `Error al procesar archivo Database.txt | Details: ${JSON.stringify(err)}`
                console.error(message);
                reject(message);
            }

            try {
                if (!isEmpty(data)) {
                    const contenidoJSON = JSON.parse(data);
                    resolve(contenidoJSON);
                }
                else {
                    message = `No se pudo parsear contenido de archivo.`;
                    console.error(message);
                    reject(message)
                }
            } catch (err) {
                message = `Error al parsear archivo Database.txt | Details: ${err.message}`
                console.error(message);
                reject(message);
            }
        });
    });
};